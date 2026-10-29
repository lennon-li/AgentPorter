"""Approved immutable pushes must not expose credentials or bypass state checks."""
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agentporter import git_remote_policy
from agentporter.git_approvals import issue_git_approval
from agentporter.git_pushes import ApprovedGitPushes
from agentporter.git_smart_http import Advertisement, validate_pack
from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import mutation_lease
from tests.security.test_git_admission import setup, count
from tests.security.test_git_approval_state import git

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='Native BCC sandbox required')


def configured(tmp_path, monkeypatch):
    root, commit, sandbox, key, manager = setup(tmp_path)
    config = tmp_path / 'remote-owner'
    config.mkdir(mode=0o700)
    policy = {'version': 1, 'verification_key': key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        'ledger_path': str(commit.verifier.ledger_path), 'grants': [{'workspace_id': 'repo', 'remote_id': 'origin',
            'url': 'https://example.com/owner/repo.git', 'ref': 'refs/heads/reviewed', 'operations': ['push'],
            'credential_file': None, 'username': 'x-access-token'}]}
    path = config / 'git-remote-policy.json'
    path.write_text(json.dumps(policy))
    path.chmod(0o600)
    authority = git_remote_policy.load_owner_git_remotes(config, commit.registry, sandbox.state_dir)
    state = {'old': None, 'sent': [], 'fail': False}
    class Broker:
        def __init__(self, *args, **kwargs):
            pass
        def discover(self, service):
            assert service == 'git-receive-pack'
            width = len(git(root, 'rev-parse', 'HEAD'))
            return Advertisement({} if state['old'] is None else {'refs/heads/reviewed': state['old']},
                frozenset({'report-status'}), 'sha256' if width == 64 else 'sha1')
        def send_push(self, update, pack):
            state['sent'].append((update, pack))
            if state['fail']:
                raise ResourceCleanupError('synthetic ambiguous remote result')
            state['old'] = update.new_oid
    monkeypatch.setattr(git_remote_policy, 'ScopedGitHTTP', Broker)
    service = ApprovedGitPushes(commit.registry, sandbox, authority, manager)
    return root, service, sandbox, key, manager, state, path


def test_prepare_and_signed_push_bind_exact_state_and_immutable_pack(tmp_path, monkeypatch):
    root, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    before = git(root, 'status', '--porcelain')
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    assert remote['sent'] == [] and count(manager) == 0
    payload = request.to_payload()
    assert payload['operation'] == 'push'
    assert payload['parameters']['old_oid'] == '0' * 40
    result = service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    update, pack = remote['sent'][0]
    assert update.new_oid == result == payload['expected_head'] == git(root, 'rev-parse', 'HEAD')
    assert hashlib.sha256(pack).hexdigest() == payload['parameters']['pack_sha256']
    assert len(pack) == payload['parameters']['pack_size']
    validate_pack(pack, 'sha1')
    assert git(root, 'status', '--porcelain') == before
    assert not list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    assert len(list((sandbox.state_dir / 'workspace-transactions/git-push-receipts').glob('*.json'))) == 1
    assert count(manager) == 0


@pytest.mark.parametrize('changed', ['head', 'index', 'remote', 'policy', 'pack', 'scope'])
def test_changed_signed_state_cannot_publish(tmp_path, monkeypatch, changed):
    root, service, sandbox, key, manager, remote, policy = configured(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    receipt = issue_git_approval(key, request)
    ref = 'refs/heads/reviewed'
    if changed == 'head':
        git(root, 'commit', '--allow-empty', '-qm', 'owner change')
    elif changed == 'index':
        (root / 'ordinary').write_text('other staged data')
        git(root, 'add', 'ordinary')
    elif changed == 'remote':
        remote['old'] = git(root, 'rev-parse', 'HEAD')
    elif changed == 'policy':
        policy.write_text(policy.read_text() + '\n')
    elif changed == 'pack':
        original = service._capture
        def capture(*args):
            body = original(*args)
            return body + b'changed'
        monkeypatch.setattr(service, '_capture', capture)
    elif changed == 'scope':
        ref = 'refs/heads/main'
    with pytest.raises(PermissionError):
        service.push('repo', 'origin', ref, receipt)
    assert remote['sent'] == [] and count(manager) == 0


def test_no_approval_cannot_publish(tmp_path, monkeypatch):
    _, service, _, _, manager, remote, _ = configured(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        service.push('repo', 'origin', 'refs/heads/reviewed', '{}')
    assert remote['sent'] == [] and count(manager) == 0


def test_fast_forward_only_and_hostile_git_config_ignored(tmp_path, monkeypatch):
    root, service, _, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    old = git(root, 'rev-parse', 'HEAD')
    remote['old'] = old
    git(root, 'commit', '--allow-empty', '-qm', 'reviewed child')
    # A configured external pack process or hook must not run.
    hook = root / '.git/hooks/pre-push'
    hook.write_text('#!/bin/sh\nexit 77\n')
    hook.chmod(0o755)
    git(root, 'config', 'core.gitProxy', '/bin/false')
    git(root, 'config', 'pack.threads', '99999')
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    assert len(remote['sent']) == 1 and count(manager) == 0
    git(root, 'reset', '--hard', old)
    # Fabricated grafts must not turn a backwards publication into a FF.
    (root / '.git/info/grafts').write_text(old + ' ' + remote['old'] + '\n')
    with pytest.raises(PermissionError):
        service.prepare('repo', 'origin', 'refs/heads/reviewed')
    assert len(remote['sent']) == 1


def test_ambiguous_push_retains_guard_spent_approval_and_capacity(tmp_path, monkeypatch):
    root, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    receipt = issue_git_approval(key, request)
    remote['fail'] = True
    with pytest.raises(ResourceCleanupError, match='reconciliation'):
        service.push('repo', 'origin', 'refs/heads/reviewed', receipt)
    assert len(remote['sent']) == 1 and count(manager) == 1
    guards = list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    assert len(guards) == 1 and json.loads(guards[0].read_text())['request'] == request.to_payload()
    service.verifier.assert_consumed(json.loads(guards[0].read_text())['approval_nonce'], request)
    with pytest.raises(ResourceCleanupError):
        with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
            pytest.fail('Uncertain publication lost workspace guard')
    with pytest.raises(Exception):
        service.push('repo', 'origin', 'refs/heads/reviewed', receipt)
    assert len(remote['sent']) == 1


def test_publication_uses_shared_admission_and_supervision(tmp_path, monkeypatch):
    _, service, sandbox, key, manager, _, _ = configured(tmp_path, monkeypatch)
    original = sandbox._run_command
    def observed(**kwargs):
        assert count(manager) == 1
        if kwargs.get('workspace_transaction') is not None:
            assert kwargs['require_resources'] is True and kwargs['network_access'] is False
        return original(**kwargs)
    monkeypatch.setattr(sandbox, '_run_command', observed)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    sandbox.resources = None
    with pytest.raises(PermissionError):
        service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    assert count(manager) == 0


@pytest.mark.parametrize('observed,expected', [('new', 'approved_tip'), ('old', 'original_tip'), ('other', 'conflict')])
def test_owner_recovery_observes_remote_without_resending(tmp_path, monkeypatch, observed, expected):
    from agentporter.git_push_recovery import recover_push
    from agentporter.sandbox import workspace_recovery
    root, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    sandbox.state_dir.chmod(0o700)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    receipt = issue_git_approval(key, request)
    remote['fail'] = True
    with pytest.raises(ResourceCleanupError):
        service.push('repo', 'origin', 'refs/heads/reviewed', receipt)
    remote['old'] = request.to_payload()['expected_head'] if observed == 'new' else 'b' * 40 if observed == 'other' else None
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_push(service, 'repo')
    assert plan['observed_state'] == expected and count(manager) == 1
    if observed == 'other':
        with pytest.raises(PermissionError, match='conflicts'):
            recover_push(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
        assert count(manager) == 1
    else:
        result = recover_push(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
        assert Path(result['receipt']).is_file() and count(manager) == 0
        with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
            pass
        with pytest.raises(PermissionError):
            service.push('repo', 'origin', 'refs/heads/reviewed', receipt)
    assert len(remote['sent']) == 1


def test_recovery_refuses_running_worker_and_stale_owner_plan(tmp_path, monkeypatch):
    from agentporter.git_push_recovery import recover_push
    from agentporter.sandbox import workspace_recovery
    _, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    sandbox.state_dir.chmod(0o700)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    remote['fail'] = True
    with pytest.raises(ResourceCleanupError):
        service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    def running():
        raise PermissionError('Worker still running')
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', running)
    with pytest.raises(PermissionError, match='still running'):
        recover_push(service, 'repo')
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_push(service, 'repo')
    remote['old'] = request.to_payload()['expected_head']
    with pytest.raises(PermissionError, match='plan changed'):
        recover_push(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert count(manager) == 1 and len(remote['sent']) == 1


def test_post_guard_binding_failure_is_recoverable_without_publication(tmp_path, monkeypatch):
    from agentporter.git_push_recovery import recover_push
    from agentporter.sandbox import workspace_recovery
    from agentporter import git_pushes
    _, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    sandbox.state_dir.chmod(0o700)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    def failed(*args):
        raise RuntimeError('Synthetic admission storage interruption')
    monkeypatch.setattr(git_pushes, 'bind', failed)
    with pytest.raises(ResourceCleanupError):
        service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_push(service, 'repo')
    assert plan['admission_status'] == 'unbound' and remote['sent'] == []
    recover_push(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert count(manager) == 0 and remote['sent'] == []


@pytest.mark.parametrize('kind', ['nonce', 'scope', 'hash', 'permissions'])
def test_recovery_rejects_tampered_guard(tmp_path, monkeypatch, kind):
    from agentporter.git_push_recovery import recover_push
    from agentporter.sandbox import workspace_recovery
    _, service, sandbox, key, manager, remote, _ = configured(tmp_path, monkeypatch)
    sandbox.state_dir.chmod(0o700)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    remote['fail'] = True
    with pytest.raises(ResourceCleanupError):
        service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    guard = next((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    if kind == 'permissions':
        guard.chmod(0o644)
    else:
        data = json.loads(guard.read_text())
        if kind == 'nonce':
            data['approval_nonce'] = '0' * 32
        elif kind == 'scope':
            data['request']['operation'] = 'fetch'
        elif kind == 'hash':
            data['request_sha256'] = '0' * 64
        guard.write_text(json.dumps(data))
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    with pytest.raises(PermissionError):
        recover_push(service, 'repo')
    assert guard.exists() and count(manager) == 1 and len(remote['sent']) == 1
