"""Independent owner signatures must bind exact Git state and resist replay."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentporter import git_approvals as approvals


def request(**changes):
    payload = {'operation': 'commit', 'workspace_id': 'repo',
        'repository_path': '/home/yeli/repos/Example', 'repository_device': 1,
        'repository_inode': 2, 'expected_head': 'a' * 40, 'expected_tree': 'b' * 40,
        'branch': 'refs/heads/reviewed', 'parameters': {'message': 'Reviewed change'}}
    payload.update(changes)
    return approvals.GitApprovalRequest.from_payload(payload)


def setup(tmp_path):
    key = Ed25519PrivateKey.generate()
    verifier = approvals.GitApprovalVerifier(key.public_key(), tmp_path / 'private/claims.db')
    return key, verifier


def test_owner_signature_verifies_once(tmp_path):
    key, verifier = setup(tmp_path)
    scope = request()
    receipt = approvals.issue_git_approval(key, scope, now=1000)
    verified = verifier.verify_and_consume(receipt, scope, now=1001)
    assert verified.request_digest == scope.digest
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, scope, now=1001)


@pytest.mark.parametrize('changed', [
    {'operation': 'push'}, {'workspace_id': 'other'},
    {'repository_path': '/home/yeli/repos/Other'}, {'repository_device': 3},
    {'repository_inode': 4}, {'expected_head': 'c' * 40},
    {'expected_tree': 'd' * 40}, {'branch': 'refs/heads/other'},
    {'parameters': {'message': 'Unreviewed change'}},
])
def test_changed_scope_is_rejected_without_consuming_approval(tmp_path, changed):
    key, verifier = setup(tmp_path)
    original = request()
    receipt = approvals.issue_git_approval(key, original, now=1000)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(**changed), now=1001)
    verifier.verify_and_consume(receipt, original, now=1001)


@pytest.mark.parametrize('now', [999, 1300, 2000])
def test_future_or_expired_receipts_fail_closed(tmp_path, now):
    key, verifier = setup(tmp_path)
    receipt = approvals.issue_git_approval(key, request(), now=1000)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=now)


def test_unrelated_signing_key_is_rejected(tmp_path):
    _, verifier = setup(tmp_path)
    receipt = approvals.issue_git_approval(Ed25519PrivateKey.generate(), request(), now=1000)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=1001)


@pytest.mark.parametrize('receipt', ['true', '{"allow_commit":true}', '{}', 'x' * 8193])
def test_flags_or_malformed_receipts_never_authorize(tmp_path, receipt):
    _, verifier = setup(tmp_path)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=1001)


def test_concurrent_replay_has_only_one_success(tmp_path):
    key, verifier = setup(tmp_path)
    scope = request()
    receipt = approvals.issue_git_approval(key, scope, now=1000)
    other = approvals.GitApprovalVerifier(key.public_key(), verifier.ledger_path)
    def attempt(instance):
        try:
            instance.verify_and_consume(receipt, scope, now=1001)
            return True
        except PermissionError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, [verifier, other]))
    assert sum(results) == 1


def test_expiry_during_claim_wait_does_not_consume_receipt(tmp_path, monkeypatch):
    key, verifier = setup(tmp_path)
    scope = request()
    receipt = approvals.issue_git_approval(key, scope, now=1000)
    clock = iter([1001, 1300])
    monkeypatch.setattr(approvals.time, 'time', lambda: next(clock))
    with pytest.raises(PermissionError, match='expired before claim'):
        verifier.verify_and_consume(receipt, scope)
    verifier.verify_and_consume(receipt, scope, now=1002)


def test_recovery_can_only_inspect_an_existing_consumed_claim(tmp_path):
    key, verifier = setup(tmp_path)
    scope = request()
    receipt = approvals.issue_git_approval(key, scope, now=1000)
    nonce = json.loads(receipt)['claims']['nonce']
    with pytest.raises(PermissionError):
        verifier.assert_consumed(nonce, scope)
    verifier.verify_and_consume(receipt, scope, now=1001)
    reopened = approvals.GitApprovalVerifier(key.public_key(), verifier.ledger_path, existing_only=True)
    reopened.assert_consumed(nonce, scope)
    with pytest.raises(PermissionError):
        reopened.verify_and_consume(receipt, scope, now=1002)


def test_recovery_does_not_create_missing_ledger(tmp_path):
    key, verifier = setup(tmp_path)
    missing = verifier.ledger_path.with_name('missing.db')
    with pytest.raises(FileNotFoundError):
        approvals.GitApprovalVerifier(key.public_key(), missing, existing_only=True)
    assert not missing.exists()


def test_request_is_an_immutable_snapshot():
    parameters = {'message': 'Reviewed', 'paths': ['ordinary']}
    scope = request(parameters=parameters)
    original_digest = scope.digest
    parameters['message'] = 'Changed'
    parameters['paths'].append('other')
    exported = scope.to_payload()
    exported['parameters']['message'] = 'Changed again'
    assert scope.digest == original_digest
    assert scope.to_payload()['parameters'] == {'message': 'Reviewed', 'paths': ['ordinary']}


def test_tampered_signed_claims_are_rejected(tmp_path):
    key, verifier = setup(tmp_path)
    envelope = json.loads(approvals.issue_git_approval(key, request(), now=1000))
    envelope['claims']['expires_at'] += 1
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(json.dumps(envelope), request(), now=1001)


def test_writable_ancestor_cannot_host_owner_ledger(tmp_path):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    with pytest.raises(PermissionError):
        approvals.GitApprovalVerifier(Ed25519PrivateKey.generate().public_key(), shared / 'private/claims.db')


def test_replaced_ledger_cannot_reenable_consumed_receipt(tmp_path):
    import os
    import sqlite3
    key, verifier = setup(tmp_path)
    scope = request()
    receipt = approvals.issue_git_approval(key, scope, now=1000)
    verifier.verify_and_consume(receipt, scope, now=1001)
    verifier.ledger_path.rename(verifier.ledger_path.with_suffix('.old'))
    with sqlite3.connect(verifier.ledger_path) as db:
        db.execute('CREATE TABLE consumed (nonce TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, claimed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)')
    os.chmod(verifier.ledger_path, 0o600)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, scope, now=1001)


def test_ledger_directory_must_remain_private(tmp_path):
    key, verifier = setup(tmp_path)
    receipt = approvals.issue_git_approval(key, request(), now=1000)
    verifier.ledger_path.parent.chmod(0o755)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=1001)


def test_replaced_private_directory_is_rejected_even_with_same_ledger(tmp_path):
    import os
    key, verifier = setup(tmp_path)
    receipt = approvals.issue_git_approval(key, request(), now=1000)
    original = verifier.ledger_path.parent
    moved = original.with_name('moved')
    original.rename(moved)
    original.mkdir(mode=0o700)
    os.rename(moved / verifier.ledger_path.name, verifier.ledger_path)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=1001)


@pytest.mark.parametrize('suffix', ['-journal', '-wal', '-shm'])
def test_constructor_rejects_sidecar_alias_before_sqlite_opens_it(tmp_path, suffix):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    ledger = directory / 'claims.db'
    target = tmp_path / 'owner-data'
    target.write_bytes(b'preserve me')
    Path(str(ledger) + suffix).symlink_to(target)
    with pytest.raises(PermissionError):
        approvals.GitApprovalVerifier(Ed25519PrivateKey.generate().public_key(), ledger)
    assert target.read_bytes() == b'preserve me'


@pytest.mark.parametrize('suffix', ['-journal', '-wal', '-shm'])
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public'])
def test_untrusted_sqlite_sidecars_are_rejected(tmp_path, suffix, kind):
    import os
    key, verifier = setup(tmp_path)
    receipt = approvals.issue_git_approval(key, request(), now=1000)
    target = tmp_path / 'unrelated'
    target.write_bytes(b'owner data')
    target.chmod(0o600)
    sidecar = Path(str(verifier.ledger_path) + suffix)
    if kind == 'symlink':
        sidecar.symlink_to(target)
    elif kind == 'hardlink':
        os.link(target, sidecar)
    else:
        sidecar.write_bytes(b'untrusted')
        sidecar.chmod(0o644)
    with pytest.raises(PermissionError):
        verifier.verify_and_consume(receipt, request(), now=1001)
    assert target.read_bytes() == b'owner data'
    sidecar.unlink()
    verifier.verify_and_consume(receipt, request(), now=1001)
