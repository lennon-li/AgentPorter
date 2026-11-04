"""Workspace commit authority never requires a phone or permits publication."""
import pytest

from agentporter.git_commits import WorkspaceGitCommits
from agentporter.tools.git import create_git_tools
from tests.security.test_approved_git_commit import backend
from tests.security.test_git_approval_state import git


def test_workspace_commit_without_receipt_preserves_parent_and_staged_tree(tmp_path):
    root, old, sandbox, _ = backend(tmp_path)
    service = WorkspaceGitCommits(old.registry, sandbox)
    previous = git(root, 'rev-parse', 'HEAD')
    (root / 'ordinary').write_text('ordinary autonomous change')
    git(root, 'add', 'ordinary')
    tree = git(root, 'write-tree')
    tools = create_git_tools(old.registry, sandbox, approved_commits=service)
    commit = tools.git_commit('repo', 'Autonomous workspace commit')
    assert git(root, 'rev-parse', 'HEAD') == commit
    assert git(root, 'rev-parse', 'HEAD^') == previous
    assert git(root, 'rev-parse', 'HEAD^{tree}') == tree
    assert git(root, 'status', '--short') == ''


def test_push_is_denied_even_with_installed_backend_and_receipt(tmp_path):
    _, old, sandbox, _ = backend(tmp_path)
    class UnexpectedPush:
        def push(self, *args):
            pytest.fail('Publication backend must never be called')
    tools = create_git_tools(old.registry, sandbox, approved_pushes=UnexpectedPush())
    with pytest.raises(PermissionError, match='push is disabled'):
        tools.git_push('repo', approval_receipt='previously-valid-receipt')


def test_readonly_workspace_cannot_commit_without_receipt(tmp_path):
    root, old, sandbox, _ = backend(tmp_path)
    service = WorkspaceGitCommits(old.registry, sandbox)
    ws = old.registry.get('repo')
    ws.writable = False
    with pytest.raises(PermissionError, match='Workspace policy'):
        service.commit('repo', 'Forbidden read-only commit', 1793289520, '')


def test_operator_cannot_enable_push_with_legacy_backend_flag(tmp_path):
    from agentporter.action_policy import OperatorActionPolicy
    policy = OperatorActionPolicy(tmp_path, approved_git_pushes=True)
    with pytest.raises(PermissionError, match='technically locked'):
        policy.check('git_push', {'workspace_id': 'repo'})


def test_interrupted_workspace_commit_can_be_reconciled_without_phone(tmp_path, monkeypatch):
    from agentporter import git_commit_recovery as recovery
    from agentporter.resources import ResourceCleanupError
    from agentporter.sandbox import workspace_recovery
    root, old, sandbox, _ = backend(tmp_path)
    sandbox.state_dir.chmod(0o700)
    service = WorkspaceGitCommits(old.registry, sandbox)
    original = sandbox._run_command
    def lose_outcome(**options):
        if options.get('workspace_transaction') is not None:
            original(**options)
            return {'exit_code': 1, 'stdout': '', 'stderr': 'synthetic lost result'}
        return original(**options)
    with monkeypatch.context() as patch:
        patch.setattr(sandbox, '_run_command', lose_outcome)
        with pytest.raises(ResourceCleanupError):
            service.commit('repo', 'Local interrupted commit', 1793289520, '')
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recovery.recover_git(service, 'repo')
    assert plan['observed_state'] == 'approved_commit_at_head'
    reconciled = recovery.recover_git(service, 'repo', apply=True,
                                      expected_plan_sha256=plan['plan_sha256'])
    assert reconciled['status'] == 'recovered'
    assert not list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
