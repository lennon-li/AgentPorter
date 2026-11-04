"""Browser Ed25519 receipts must match the Python backend byte-for-byte."""
from tests.sandbox_support import BWRAP
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


def genuine_job_pull(service):
    from agentporter.git_pulls import JobBoundGitPulls
    import os
    import uuid
    transaction = service._transaction('repo')
    job_id, token = 'job_' + uuid.uuid4().hex[:24], uuid.uuid4().hex
    service.manager._job_transactions[job_id] = transaction
    db = service.manager._get_db()
    try:
        with db:
            db.execute('INSERT INTO jobs (job_id,workspace_id,agent,argv,status,workspace_transaction) VALUES (?,?,?,?,?,?)',
                (job_id, 'repo', 'codex_impl', json.dumps(['confined-development-worker', 'codex_impl']), 'running', str(transaction.directory)))
            db.execute('INSERT INTO job_admissions VALUES (?,?,?,?)', (token, job_id, os.getpid(), 0))
    finally:
        db.close()
    return JobBoundGitPulls(service, job_id, 'repo', 'codex_impl'), transaction


def genuine_pull_proposal(tmp_path, monkeypatch, algorithm='sha1', mode='ff-only', job=False):
    """Produce the exact native backend schema, with only an offline remote broker."""
    if not Path(BWRAP).is_file():
        pytest.skip('Genuine pull proposal requires the installed Gateway native sandbox')
    from tests.security.test_approved_git_pull import backend
    _, service, _, _, _ = backend(tmp_path, monkeypatch, algorithm)
    transaction = None
    try:
        if job:
            adapter, transaction = genuine_job_pull(service)
            scope = adapter.prepare('origin', 'refs/heads/reviewed', mode)
        else:
            scope = service.prepare('repo', 'origin', 'refs/heads/reviewed', mode)
        return scope, {'request': scope.to_payload(), 'request_sha256': scope.digest}
    finally:
        if transaction is not None:
            transaction.close()


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
@pytest.mark.parametrize('job', [False, True])
def test_native_pull_proposal_device_receipt_verifies_exact_request(tmp_path, monkeypatch, algorithm, mode, job):
    scope, data = genuine_pull_proposal(tmp_path, monkeypatch, algorithm, mode, job)
    result = run(json.dumps(data))
    assert result['ok'], result
    assert result['payload'].encode() == scope.canonical_payload
    assert result['privateExportDenied'] and result['frozen']
    verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(result['publicKey'])),
                                   tmp_path / 'device-owner/claims.db')
    verifier.verify_and_consume(result['receipt'], scope, now=1002)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(result['receipt'], scope, now=1002)


@pytest.fixture(scope='module')
def native_job_pull_proposal(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        _, data = genuine_pull_proposal(tmp_path_factory.mktemp('owner-pull'), patch, job=True)
    return data


@pytest.mark.parametrize('path,value', [
    ('mode', 'autostash'), ('object_format', 'sha512'), ('remote_oid', '0' * 40),
    ('remote_oid', 'a' * 64), ('new_oid', 'b' * 40), ('old_oid', '0' * 64),
    ('remote_id', '*'), ('remote_url', 'https://token@example.com/owner/repo.git'),
    ('remote_ref', 'refs/heads/*'), ('tracking_ref', 'refs/remotes/other/reviewed'),
    ('metadata_inode', 0), ('metadata_device', -1), ('pack_size', 0), ('pack_sha256', 'bad'),
    ('private_state.head', 'e' * 40), ('private_state.refs_sha256', 'bad'),
    ('private_state.unmerged', True), ('private_state.extra', 'unreviewed'),
    ('canonical_state.object_format', 'sha256'), ('canonical_state.tree', None),
    ('canonical_state.stash_log_sha256', 1), ('canonical_state.unmerged', 'false'),
    ('job_context.agent', 'unknown'), ('job_context.job_id', 'job_other'),
    ('job_context.admission_token', '*'), ('job_context.transaction_directory', '/tmp/../owner'),
    ('job_context.transaction_inode', 0), ('job_context.extra', 'unreviewed'),
])
def test_owner_interface_refuses_invalid_native_pull_scope(native_job_pull_proposal, path, value):
    from agentporter.git_approvals import GitApprovalRequest
    data = json.loads(json.dumps(native_job_pull_proposal))
    current = data['request']['parameters']
    parts = path.split('.')
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value
    # Recompute the digest so this tests schema validation, not just digest mismatch.
    data['request_sha256'] = GitApprovalRequest.from_payload(data['request']).digest
    result = run(json.dumps(data))
    assert result['ok'] is False and 'receipt' not in result and 'publicKey' not in result


@pytest.mark.parametrize('change', ['digest', 'duplicate', 'large-identity'])
def test_native_pull_exact_digest_duplicate_and_large_identity(native_job_pull_proposal, change):
    from agentporter.git_approvals import GitApprovalRequest
    data = json.loads(json.dumps(native_job_pull_proposal))
    if change == 'large-identity':
        data['request']['parameters']['metadata_inode'] = 2**64 - 1
        data['request']['parameters']['job_context']['transaction_inode'] = 2**63 + 7
        data['request_sha256'] = GitApprovalRequest.from_payload(data['request']).digest
    else:
        data['request']['parameters']['mode'] = 'merge'
    source = json.dumps(data)
    if change == 'duplicate':
        source = source.replace('"mode": "merge"', '"mode": "ff-only", "mode": "merge"')
    result = run(source)
    if change == 'large-identity':
        assert result['ok'], result
        assert result['payload'].encode() == GitApprovalRequest.from_payload(data['request']).canonical_payload
    else:
        assert result['ok'] is False and 'receipt' not in result
