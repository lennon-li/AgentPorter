"""Exact owner-approved commits with canonical metadata access only."""
import os
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter.git_approvals import GitApprovalVerifier, issue_git_approval
from agentporter.git_commits import ApprovedGitCommits
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.workspaces.leases import mutation_lease
from tests.security.test_git_approval_state import git, setup
from tests.security.test_workspace_transactions import RecordingResources

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(),
                               reason='BCC approved Git requires installed sandbox')


def backend(tmp_path, *, committed=True):
    root, registry, initial = setup(tmp_path, committed=committed)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    key = Ed25519PrivateKey.generate()
    verifier = GitApprovalVerifier(key.public_key(), tmp_path / 'owner/claims.db')
    service = ApprovedGitCommits(registry, sandbox, verifier,
                                author_name='Owner', author_email='owner@example.invalid')
    return root, service, sandbox, key


def approve(service, key, message='Reviewed change'):
    timestamp = int(time.time())
    request = service.prepare('repo', message, timestamp)
    return timestamp, issue_git_approval(key, request)


def test_signed_commit_contains_exact_staged_tree_and_owner_identity(tmp_path):
    root, service, sandbox, key = backend(tmp_path)
    previous = git(root, 'rev-parse', 'HEAD')
    (root / 'ordinary').write_text('approved')
    git(root, 'add', 'ordinary')
    tree = git(root, 'write-tree')
    timestamp, receipt = approve(service, key)
    result = service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert result == git(root, 'rev-parse', 'HEAD')
    assert git(root, 'rev-parse', 'HEAD^{tree}') == tree
    assert git(root, 'rev-parse', 'HEAD^') == previous
    assert git(root, 'show', '-s', '--format=%an <%ae>') == 'Owner <owner@example.invalid>'
    assert git(root, 'show', '-s', '--format=%at') == str(timestamp)
    assert git(root, 'status', '--short') == ''
    assert git(root, 'reflog', '-1', '--format=%H', 'HEAD') == result
    assert (root / 'ordinary').read_text() == 'approved'
    assert sandbox.resources.lease.closed
    receipts = list((sandbox.state_dir / 'workspace-transactions/git-receipts').glob('*.json'))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())['commit'] == result
    with pytest.raises(PermissionError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)


def test_initial_commit_is_supported(tmp_path):
    root, service, _, key = backend(tmp_path, committed=False)
    timestamp, receipt = approve(service, key)
    result = service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert result == git(root, 'rev-parse', 'HEAD')
    assert git(root, 'rev-list', '--count', 'HEAD') == '1'


@pytest.mark.parametrize('changed', ['message', 'timestamp', 'index'])
def test_changed_approved_action_never_updates_history(tmp_path, changed):
    root, service, _, key = backend(tmp_path)
    previous = git(root, 'rev-parse', 'HEAD')
    timestamp, receipt = approve(service, key)
    message = 'Reviewed change'
    if changed == 'message':
        message = 'Unreviewed'
    elif changed == 'timestamp':
        timestamp += 1
    else:
        (root / 'ordinary').write_text('unreviewed')
        git(root, 'add', 'ordinary')
    with pytest.raises(PermissionError):
        service.commit('repo', message, timestamp, receipt)
    assert git(root, 'rev-parse', 'HEAD') == previous


def test_repository_hooks_filters_and_included_config_are_not_executed(tmp_path):
    root, service, _, key = backend(tmp_path)
    hook = root / '.git/hooks/reference-transaction'
    hook.write_text('#!/bin/sh\nprintf bypass > /workspace/ordinary\nexit 99\n')
    hook.chmod(0o755)
    (root / '.git/hostile-config').write_text('[commit]\n gpgsign = true\n[gpg]\n program = /bin/false\n')
    git(root, 'config', 'include.path', 'hostile-config')
    git(root, 'config', 'filter.hostile.process', '/bin/false')
    timestamp, receipt = approve(service, key)
    service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert (root / 'ordinary').read_text() == 'initial'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'alternates'])
def test_unsafe_metadata_cannot_receive_write_access(tmp_path, kind):
    root, service, _, key = backend(tmp_path)
    previous = git(root, 'rev-parse', 'HEAD')
    timestamp, receipt = approve(service, key)
    if kind == 'symlink':
        (root / '.git/alias').symlink_to(root / 'ordinary')
    elif kind == 'hardlink':
        os.link(root / 'ordinary', root / '.git/alias')
    else:
        (root / '.git/objects/info/alternates').write_text(str(tmp_path) + '\n')
    with pytest.raises(PermissionError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert git(root, 'rev-parse', 'HEAD') == previous
    assert (root / 'ordinary').read_text() == 'initial'


def test_uncertain_resource_cleanup_keeps_workspace_blocked(tmp_path):
    from agentporter.resources import ResourceCleanupError
    root, service, sandbox, key = backend(tmp_path)
    timestamp, receipt = approve(service, key)
    # Inspection and execution have separate resource leases.
    original = sandbox._run_command
    def fail_execution_cleanup(**options):
        if options.get('workspace_transaction') is not None:
            sandbox.resources.lease.fail = True
        return original(**options)
    sandbox._run_command = fail_execution_cleanup
    with pytest.raises(ResourceCleanupError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    with pytest.raises(ResourceCleanupError):
        with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
            pytest.fail('Uncertain Git publication released the workspace')
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    with pytest.raises(ResourceCleanupError):
        WorkspaceTransaction(root, sandbox.state_dir / 'workspace-transactions')


def test_unapproved_commit_cannot_mutate_history(tmp_path):
    root, service, _, _ = backend(tmp_path)
    previous = git(root, 'rev-parse', 'HEAD')
    with pytest.raises(PermissionError):
        service.commit('repo', 'Reviewed change', int(time.time()), '{}')
    assert git(root, 'rev-parse', 'HEAD') == previous


def test_failed_commit_keeps_a_guard_and_spends_approval(tmp_path, monkeypatch):
    from agentporter.resources import ResourceCleanupError
    root, service, sandbox, key = backend(tmp_path)
    timestamp, receipt = approve(service, key)
    previous = git(root, 'rev-parse', 'HEAD')
    original = sandbox._run_command
    def failed(**options):
        if options.get('workspace_transaction') is not None:
            return {'exit_code': 1, 'stdout': '', 'stderr': 'synthetic failure'}
        return original(**options)
    monkeypatch.setattr(sandbox, '_run_command', failed)
    with pytest.raises(ResourceCleanupError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert git(root, 'rev-parse', 'HEAD') == previous
    with pytest.raises(ResourceCleanupError):
        with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
            pytest.fail('Failed Git publication lost its guard')


def test_sha256_commit_is_supported(tmp_path):
    import shutil
    root, service, _, key = backend(tmp_path, committed=False)
    shutil.rmtree(root / '.git')
    git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
    git(root, 'add', 'ordinary')
    timestamp, receipt = approve(service, key)
    result = service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert len(result) == 64
    assert result == git(root, 'rev-parse', 'HEAD')


@pytest.mark.parametrize('changed', ['resources', 'transaction_mode'])
def test_runtime_cannot_fall_back_to_unsupervised_git(tmp_path, changed):
    root, service, sandbox, key = backend(tmp_path)
    previous = git(root, 'rev-parse', 'HEAD')
    timestamp, receipt = approve(service, key)
    if changed == 'resources':
        sandbox.resources = None
    else:
        sandbox.transactional_writes = False
    with pytest.raises(PermissionError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert git(root, 'rev-parse', 'HEAD') == previous


def test_owner_change_after_capture_is_preserved(tmp_path, monkeypatch):
    from agentporter.resources import ResourceCleanupError
    root, service, sandbox, key = backend(tmp_path)
    timestamp, receipt = approve(service, key)
    original = sandbox._run_command
    owner = []
    def owner_commit(**options):
        if options.get('workspace_transaction') is not None:
            git(root, 'commit', '--allow-empty', '-qm', 'owner change')
            owner.append(git(root, 'rev-parse', 'HEAD'))
        return original(**options)
    monkeypatch.setattr(sandbox, '_run_command', owner_commit)
    with pytest.raises(ResourceCleanupError):
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert git(root, 'rev-parse', 'HEAD') == owner[0]


def test_replaced_workspace_cannot_receive_approved_commit(tmp_path, monkeypatch):
    from agentporter.resources import ResourceCleanupError
    root, service, sandbox, key = backend(tmp_path)
    timestamp, receipt = approve(service, key)
    previous = git(root, 'rev-parse', 'HEAD')
    original = sandbox._run_command
    moved = root.with_name('original')
    def replace_root(**options):
        if options.get('workspace_transaction') is not None:
            root.rename(moved)
            root.mkdir()
        return original(**options)
    monkeypatch.setattr(sandbox, '_run_command', replace_root)
    with pytest.raises(ResourceCleanupError, match='guard requires owner inspection') as failure:
        service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert isinstance(failure.value.__cause__, PermissionError)
    assert 'root changed' in str(failure.value.__cause__)
    assert git(moved, 'rev-parse', 'HEAD') == previous
    assert list(root.iterdir()) == []
