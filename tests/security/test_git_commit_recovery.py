"""Offline owner review may reconcile known Git outcomes without replaying them."""
import json
import os
from pathlib import Path

import pytest

from agentporter import git_commit_recovery as recovery
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox import workspace_recovery
from agentporter.workspaces.leases import mutation_lease
from tests.security.test_approved_git_commit import backend, approve
from tests.security.test_git_approval_state import git

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(),
                               reason='BCC Git recovery requires installed sandbox')


def interrupted(tmp_path, monkeypatch, *, committed, initial=False, message='Reviewed change', author='Owner', branch=None, sha256=False):
    root, service, sandbox, key = backend(tmp_path, committed=not initial)
    if sha256:
        import shutil
        shutil.rmtree(root / '.git')
        git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
        git(root, 'config', 'user.name', 'Fixture')
        git(root, 'config', 'user.email', 'fixture@example.invalid')
        git(root, 'add', 'ordinary')
        if not initial:
            git(root, 'commit', '-qm', 'initial')
    service.author_name = author
    if branch is not None:
        git(root, 'checkout', '-qb', branch)
    sandbox.state_dir.chmod(0o700)
    timestamp, receipt = approve(service, key, message)
    original = sandbox._run_command
    def lose_outcome(**options):
        if options.get('workspace_transaction') is not None:
            if committed:
                original(**options)
            return {'exit_code': 1, 'stdout': '', 'stderr': 'synthetic interruption'}
        return original(**options)
    with monkeypatch.context() as patch:
        patch.setattr(sandbox, '_run_command', lose_outcome)
        with pytest.raises(ResourceCleanupError):
            service.commit('repo', message, timestamp, receipt)
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    return root, service, sandbox, key


@pytest.mark.parametrize('committed,status', [(True, 'approved_commit_at_head'), (False, 'original_head')])
def test_reviewed_recovery_preserves_history_and_permits_next_job(tmp_path, monkeypatch, committed, status):
    root, service, sandbox, key = interrupted(tmp_path, monkeypatch, committed=committed)
    before = git(root, 'rev-parse', 'HEAD')
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == status
    assert git(root, 'rev-parse', 'HEAD') == before
    with pytest.raises(ResourceCleanupError):
        with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
            pytest.fail('Inspection cleared the guard')
    result = recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert result['status'] == 'recovered'
    assert Path(result['receipt']).is_file()
    assert git(root, 'rev-parse', 'HEAD') == before
    timestamp, receipt = approve(service, key, 'next job')
    assert service.commit('repo', 'next job', timestamp, receipt) == git(root, 'rev-parse', 'HEAD')


def test_conflicting_owner_history_is_preserved(tmp_path, monkeypatch):
    root, service, _, _ = interrupted(tmp_path, monkeypatch, committed=False)
    git(root, 'commit', '--allow-empty', '-qm', 'owner change')
    before = git(root, 'rev-parse', 'HEAD')
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == 'conflict'
    with pytest.raises(PermissionError):
        recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert git(root, 'rev-parse', 'HEAD') == before


def test_stale_review_never_clears_guard(tmp_path, monkeypatch):
    root, service, _, _ = interrupted(tmp_path, monkeypatch, committed=False)
    plan = recovery.recover_git(service, 'repo')
    (root / 'ordinary').write_text('owner edit')
    git(root, 'add', 'ordinary')
    with pytest.raises(PermissionError):
        recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])


def test_unconsumed_nonce_cannot_clear_guard(tmp_path, monkeypatch):
    _, service, sandbox, _ = interrupted(tmp_path, monkeypatch, committed=False)
    guard = next((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    data = json.loads(guard.read_text())
    data['approval_nonce'] = '0' * 32
    guard.write_text(json.dumps(data))
    with pytest.raises(PermissionError):
        recovery.recover_git(service, 'repo')
    assert guard.exists()


def test_live_service_blocks_git_recovery(tmp_path, monkeypatch):
    _, service, _, _ = interrupted(tmp_path, monkeypatch, committed=False)
    def active():
        raise PermissionError('Worker service is live')
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', active)
    with pytest.raises(PermissionError, match='live'):
        recovery.recover_git(service, 'repo')


@pytest.mark.parametrize('message', ['trailing\n', 'two\n\n', 'unicode α'])
def test_recovery_uses_exact_message_and_utf8_identity(tmp_path, monkeypatch, message):
    _, service, _, _ = interrupted(tmp_path, monkeypatch, committed=True,
                                  message=message, author='Owner Ω')
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == 'approved_commit_at_head'


@pytest.mark.parametrize('committed', [True, False])
def test_initial_commit_outcomes_can_be_reconciled(tmp_path, monkeypatch, committed):
    _, service, _, _ = interrupted(tmp_path, monkeypatch, committed=committed, initial=True)
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == ('approved_commit_at_head' if committed else 'original_head')


def test_leftover_git_lock_cannot_be_cleared_automatically(tmp_path, monkeypatch):
    root, service, _, _ = interrupted(tmp_path, monkeypatch, committed=False)
    lock = root / '.git/index.lock'
    lock.write_text('unresolved owner or worker lock')
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == 'conflict'
    assert plan['metadata_locks'] == ['index.lock']
    with pytest.raises(PermissionError):
        recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert lock.read_text() == 'unresolved owner or worker lock'


def test_git_recovery_cannot_bypass_live_supervisor_lock(tmp_path, monkeypatch):
    import fcntl
    _, service, sandbox, _ = interrupted(tmp_path, monkeypatch, committed=False)
    descriptor = os.open(sandbox.state_dir / 'job-supervisor.lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(PermissionError, match='supervisor'):
            recovery.recover_git(service, 'repo')
    finally:
        os.close(descriptor)


def test_utf8_branch_commit_and_recovery(tmp_path, monkeypatch):
    _, service, _, _ = interrupted(tmp_path, monkeypatch, committed=True, branch='review-α')
    plan = recovery.recover_git(service, 'repo')
    assert plan['branch'] == 'refs/heads/review-α'
    assert plan['observed_state'] == 'approved_commit_at_head'


@pytest.mark.parametrize('initial', [True, False])
@pytest.mark.parametrize('committed', [True, False])
def test_sha256_recovery_matches_exact_commit_identity(tmp_path, monkeypatch, initial, committed):
    _, service, _, _ = interrupted(tmp_path, monkeypatch, committed=committed, initial=initial, sha256=True)
    plan = recovery.recover_git(service, 'repo')
    assert len(plan['expected_commit']) == 64
    assert plan['observed_state'] == ('approved_commit_at_head' if committed else 'original_head')


def test_failed_outcome_sync_cannot_clear_git_guard(tmp_path, monkeypatch):
    _, service, sandbox, _ = interrupted(tmp_path, monkeypatch, committed=True)
    plan = recovery.recover_git(service, 'repo')
    def fail(*arguments):
        raise OSError('synthetic durability failure')
    monkeypatch.setattr(recovery, '_sync_observed_commit', fail)
    with pytest.raises(OSError, match='durability'):
        recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))


def test_matching_ref_with_changed_commit_bytes_is_a_conflict(tmp_path, monkeypatch):
    import zlib
    root, service, _, _ = interrupted(tmp_path, monkeypatch, committed=True)
    head = git(root, 'rev-parse', 'HEAD')
    path = root / '.git/objects' / head[:2] / head[2:]
    raw = zlib.decompress(path.read_bytes())
    body = raw.split(b'\0', 1)[1].replace(b'Reviewed change', b'Unreviewed contents')
    path.chmod(0o600)
    path.write_bytes(zlib.compress(b'commit ' + str(len(body)).encode() + b'\0' + body))
    plan = recovery.recover_git(service, 'repo')
    assert plan['commit_content_matches'] is False
    assert plan['observed_state'] == 'conflict'
    with pytest.raises(PermissionError):
        recovery.recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
