"""Browser Ed25519 receipts must match the Python backend byte-for-byte."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_approvals import GitApprovalVerifier
from tests.security.test_git_approval_receipts import request

NODE = shutil.which('node')
MODULE = Path(__file__).resolve().parents[2] / 'src/agentporter/owner_approval/protocol.mjs'
pytestmark = pytest.mark.skipif(NODE is None, reason='Node Web Crypto unavailable')
PROGRAM = r'''
import {pathToFileURL} from 'node:url';
const protocol = await import(pathToFileURL(process.argv[1]));
let source = '';
for await (const chunk of process.stdin) source += chunk;
try {
  const reviewed = await protocol.reviewProposal(source);
  const pair = await protocol.createDeviceKey();
  let privateExportDenied = false;
  try { await crypto.subtle.exportKey('pkcs8', pair.privateKey); }
  catch { privateExportDenied = true; }
  const publicKey = await protocol.publicKeyHex(pair);
  const receipt = await protocol.signReviewed(pair, reviewed, 1001);
  console.log(JSON.stringify({ok:true, payload:reviewed.payload, digest:reviewed.digest,
    frozen:Object.isFrozen(reviewed), publicKey, privateExportDenied, receipt}));
} catch (error) { console.log(JSON.stringify({ok:false, error:error.message})); }
'''


def proposal(**changes):
    parameters = {'message': 'Owner reviewed', 'timestamp': 1000,
                  'author_name': 'Owner', 'author_email': 'owner@example.invalid'}
    parameters.update(changes.pop('parameters', {}))
    scope = request(parameters=parameters, **changes)
    return scope, {'request': scope.to_payload(), 'request_sha256': scope.digest}


def run(source):
    result = subprocess.run([NODE, '--input-type=module', '-e', PROGRAM, str(MODULE)],
        input=source, text=True, capture_output=True, timeout=10, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize('message', ['Owner reviewed', 'Ω🙂\u202e<script>\n', 'line\nline\n'])
def test_device_receipt_verifies_in_backend_and_private_key_cannot_export(tmp_path, message):
    scope, data = proposal(parameters={'message': message, 'author_name': 'Owner Ω'})
    result = run(json.dumps(data, ensure_ascii=False))
    assert result['ok'], result
    assert result['payload'].encode() == scope.canonical_payload
    assert result['digest'] == scope.digest
    assert result['frozen'] and result['privateExportDenied']
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(result['publicKey']))
    verifier = GitApprovalVerifier(key, tmp_path / 'owner/claims.db')
    verifier.verify_and_consume(result['receipt'], scope, now=1002)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(result['receipt'], scope, now=1002)


def test_exact_64_bit_filesystem_identity_survives_javascript(tmp_path):
    scope, data = proposal(repository_device=2**63 + 7, repository_inode=2**64 - 1)
    result = run(json.dumps(data))
    assert result['ok'], result
    assert result['payload'].encode() == scope.canonical_payload
    verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(result['publicKey'])),
                                   tmp_path / 'owner/claims.db')
    verifier.verify_and_consume(result['receipt'], scope, now=1002)


@pytest.mark.parametrize('kind', ['digest', 'duplicate', 'operation', 'authority', 'fraction', 'oversize'])
def test_unreviewable_proposals_never_produce_a_key_or_receipt(kind):
    _, data = proposal()
    if kind == 'digest':
        data['request']['parameters']['message'] = 'Changed after preparation'
    elif kind == 'operation':
        _, data = proposal(operation='push')
    elif kind == 'authority':
        data['verification_key'] = 'attacker'
    source = json.dumps(data)
    if kind == 'duplicate':
        source = source.replace('"request_sha256":', '"request_sha256":"duplicate", "request_sha256":')
    elif kind == 'fraction':
        source = source.replace('"repository_inode": 2', '"repository_inode": 2.0')
    elif kind == 'oversize':
        source = ' ' * 131073
    result = run(source)
    assert result['ok'] is False
    assert 'receipt' not in result and 'publicKey' not in result


def push_proposal(**changes):
    parameters = {'remote_id': 'origin', 'remote_url': 'https://example.com/owner/repo.git',
        'remote_ref': 'refs/heads/reviewed', 'old_oid': '0' * 40, 'new_oid': 'a' * 40,
        'pack_sha256': 'c' * 64, 'pack_size': 1024, 'policy_sha256': 'd' * 64}
    parameters.update(changes)
    scope = request(operation='push', parameters=parameters)
    return scope, {'request': scope.to_payload(), 'request_sha256': scope.digest}


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_owner_push_receipt_matches_exact_python_request(tmp_path, algorithm):
    scope, _ = push_proposal(remote_ref='refs/heads/Ω🙂')
    if algorithm == 'sha256':
        payload = scope.to_payload()
        payload.update(expected_head='a' * 64, expected_tree='b' * 64)
        payload['parameters'].update(new_oid='a' * 64, old_oid='0' * 64)
        scope = type(scope).from_payload(payload)
    result = run(json.dumps({'request': scope.to_payload(), 'request_sha256': scope.digest}))
    assert result['ok'], result
    assert result['payload'].encode() == scope.canonical_payload and result['privateExportDenied']
    verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(result['publicKey'])),
                                   tmp_path / 'owner/claims.db')
    verifier.verify_and_consume(result['receipt'], scope, now=1002)


@pytest.mark.parametrize('changes', [
    {'remote_url': 'https://token@example.com/owner/repo.git'},
    {'remote_url': 'http://example.com/owner/repo.git'},
    {'remote_url': 'https://example.com/owner/repo.git?redirect=x'},
    {'remote_url': 'https://example.com/../repo.git'},
    {'remote_ref': 'refs/heads/*'}, {'remote_ref': 'refs/tags/release'},
    {'remote_ref': 'refs/heads/x.lock'}, {'remote_ref': 'refs/heads/x@{1}'},
    {'old_oid': 'a' * 40}, {'new_oid': '0' * 40}, {'new_oid': 'e' * 40},
    {'old_oid': '0' * 64}, {'pack_size': 2**63}, {'pack_size': 0},
    {'policy_sha256': 'not a hash'}, {'force': True}, {'remote_id': '*'},
])
def test_owner_interface_refuses_ambiguous_or_expanded_push_scope(changes):
    _, data = push_proposal(**changes)
    result = run(json.dumps(data))
    assert result['ok'] is False and 'receipt' not in result


def fetch_proposal(**changes):
    parameters = {'remote_id': 'origin', 'remote_url': 'https://example.com/owner/repo.git',
        'remote_ref': 'refs/heads/main', 'remote_oid': 'b' * 40,
        'tracking_ref': 'refs/remotes/origin/main', 'old_oid': '0' * 40,
        'new_oid': 'b' * 40, 'pack_sha256': 'c' * 64, 'pack_size': 1024,
        'policy_sha256': 'd' * 64}
    parameters.update(changes)
    scope = request(operation='fetch', parameters=parameters)
    return scope, {'request': scope.to_payload(), 'request_sha256': scope.digest}


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_owner_fetch_receipt_binds_advertised_object_and_tracking_ref(tmp_path, algorithm):
    scope, _ = fetch_proposal()
    if algorithm == 'sha256':
        payload = scope.to_payload()
        payload.update(expected_head='a' * 64, expected_tree='e' * 64)
        payload['parameters'].update(remote_oid='b' * 64, old_oid='0' * 64, new_oid='b' * 64)
        scope = type(scope).from_payload(payload)
    result = run(json.dumps({'request': scope.to_payload(), 'request_sha256': scope.digest}))
    assert result['ok'], result
    assert result['payload'].encode() == scope.canonical_payload
    verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(result['publicKey'])),
                                   tmp_path / 'owner/claims.db')
    verifier.verify_and_consume(result['receipt'], scope, now=1002)


@pytest.mark.parametrize('changes', [
    {'remote_url': 'https://token@example.com/owner/repo.git'},
    {'remote_url': 'https://example.com/../repo.git'},
    {'remote_ref': 'refs/tags/release'}, {'tracking_ref': 'refs/heads/main'},
    {'tracking_ref': 'refs/remotes/other/main'}, {'remote_oid': 'a' * 40},
    {'new_oid': 'a' * 40}, {'old_oid': 'c' * 64}, {'old_oid': '0' * 64},
    {'pack_size': 2**63}, {'pack_sha256': 'bad'}, {'force': True},
])
def test_owner_interface_refuses_ambiguous_or_expanded_fetch_scope(changes):
    _, data = fetch_proposal(**changes)
    result = run(json.dumps(data))
    assert result['ok'] is False and 'receipt' not in result
