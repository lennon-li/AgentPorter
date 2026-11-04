"""Real offline Git integration in disposable private transaction overlays."""
from tests.sandbox_support import BWRAP
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from agentporter.git_pull_integration import PrivateGitPullIntegration
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from tests.security.test_workspace_transactions import RecordingResources

pytestmark = pytest.mark.skipif(not Path(BWRAP).is_file(),
                               reason='Gateway native overlay sandbox required')


def git(root, *args):
    return subprocess.check_output(['/usr/bin/git', *args], cwd=root,
        stderr=subprocess.DEVNULL).decode().strip()


def commit(root, path, value, message):
    (root / path).write_text(value)
    git(root, 'add', path)
    git(root, 'commit', '-qm', message)
    return git(root, 'rev-parse', 'HEAD')


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob('*') if p.is_file()}


def fixture(tmp_path, algorithm='sha1', *, divergent=False, conflict=False):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-q', '-b', 'main', '--object-format=' + algorithm)
    git(root, 'config', 'user.name', 'Fixture')
    git(root, 'config', 'user.email', 'fixture@example.invalid')
    commit(root, 'ordinary', 'base\n', 'base')
    commit(root, 'owner', 'owner base\n', 'owner base')
    git(root, 'branch', 'remote')
    if divergent:
        commit(root, 'ordinary' if conflict else 'local', 'local\n', 'local')
    local = git(root, 'rev-parse', 'HEAD')
    git(root, 'checkout', '-q', 'remote')
    remote = commit(root, 'ordinary', 'remote\n', 'remote')
    git(root, 'checkout', '-q', 'main')
    sandbox = BubblewrapSandbox(tmp_path / 'state', transactional_writes=True)
    sandbox.resources = RecordingResources()
    return root, sandbox, local, remote


def transaction(root, sandbox):
    return WorkspaceTransaction(root, sandbox.state_dir / 'workspace-transactions', git_sandbox=sandbox)


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_all_modes_fast_forward_stay_private(tmp_path, algorithm, mode):
    root, sandbox, local, remote = fixture(tmp_path, algorithm)
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        state = engine.inspect(tx)
        result = engine.run(tx, remote, mode, expected=state)
        assert result['status'] == 'integrated', result
        assert result['after']['head'] == remote
        assert result['private_only'] is True
        assert snapshot(root) == before
        assert git(root, 'rev-parse', 'HEAD') == local
        assert (tx.upper / 'ordinary').read_text() == 'remote\n'
    finally:
        tx.close()
    assert snapshot(root) == before


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_divergent_modes_have_real_graph_semantics(tmp_path, algorithm, mode):
    root, sandbox, local, remote = fixture(tmp_path, algorithm, divergent=True)
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        if mode == 'ff-only':
            assert result['status'] == 'refused'
            assert result['reason'] == 'diverged'
            assert result['before'] == result['after']
        else:
            assert result['status'] == 'integrated', result
            private = tx.git_histories['.git'].private
            parents = git(root, '--git-dir=' + str(private), 'rev-list', '--parents', '-n', '1', 'HEAD').split()
            if mode == 'merge':
                assert parents[1:] == [local, remote]
            else:
                assert parents[1:] == [remote]
                assert parents[0] != local
                assert git(root, '--git-dir=' + str(private), 'show', 'HEAD:local') == 'local'
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['merge', 'rebase'])
def test_conflicts_are_private_distinct_outcomes(tmp_path, algorithm, mode):
    root, sandbox, _, remote = fixture(tmp_path, algorithm, divergent=True, conflict=True)
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert result['status'] == 'conflict', result
        assert result['after']['unmerged'] is True
        assert result['after']['tree'] is None
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
@pytest.mark.parametrize('dirty', ['staged', 'unstaged', 'both', 'untracked'])
def test_owner_dirt_is_preserved_or_refused_without_publication(tmp_path, mode, dirty):
    root, sandbox, _, remote = fixture(tmp_path)
    if dirty in ('staged', 'both'):
        (root / 'owner').write_text('staged owner\n')
        git(root, 'add', 'owner')
    if dirty in ('unstaged', 'both'):
        (root / 'owner').write_text('unstaged owner\n')
    if dirty == 'untracked':
        (root / 'untracked').write_text('untracked owner\n')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        if mode == 'rebase' and dirty != 'untracked':
            assert result['status'] == 'refused', result
            assert result['before'] == result['after']
        else:
            assert result['status'] == 'integrated', result
            # Unrelated index entries and owner file contents remain intact.
            private = tx.git_histories['.git'].private
            owner = git(root, '--git-dir=' + str(private), 'show', ':owner')
            assert owner == ('staged owner' if dirty in ('staged', 'both') else 'owner base')
        assert snapshot(root) == before
    finally:
        tx.close()


def test_divergent_merge_never_commits_owner_staged_edits(tmp_path):
    root, sandbox, _, remote = fixture(tmp_path, divergent=True)
    (root / 'owner').write_text('owner staged\n')
    git(root, 'add', 'owner')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, 'merge', expected=engine.inspect(tx))
        assert result['status'] == 'refused'
        assert result['reason'] == 'dirty_index'
        assert result['before'] == result['after']
    finally:
        tx.close()
    assert snapshot(root) == before


@pytest.mark.parametrize('change', ['worktree', 'index', 'head', 'ref'])
def test_exact_baseline_drift_refuses_before_integration(tmp_path, change):
    root, sandbox, _, remote = fixture(tmp_path)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        expected = engine.inspect(tx)
        if change == 'worktree':
            (tx.upper / 'new').write_text('changed')
        elif change == 'index':
            # Tree stays identical while raw index bytes differ.
            private = tx.git_histories['.git'].private
            git(root, '--git-dir=' + str(private), 'update-index', '--assume-unchanged', 'owner')
        elif change == 'head':
            (tx.git_histories['.git'].private / 'HEAD').write_text(remote + '\n')
        else:
            private = tx.git_histories['.git'].private
            git(root, '--git-dir=' + str(private), 'update-ref', 'refs/tags/extra', remote)
        with pytest.raises(PermissionError, match='discard transaction'):
            engine.run(tx, remote, 'merge', expected=expected)
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['merge', 'rebase'])
def test_hostile_config_hooks_filters_and_rebase_exec_are_not_executed(tmp_path, mode):
    root, sandbox, _, remote = fixture(tmp_path, divergent=True)
    marker = root / 'helper-ran'
    command = 'touch /workspace/helper-ran'
    for key, value in [('core.fsmonitor', command), ('core.editor', command),
            ('core.sshCommand', command), ('credential.helper', '!' + command),
            ('gpg.program', command), ('commit.gpgSign', 'true'),
            ('filter.evil.clean', command), ('filter.evil.smudge', command),
            ('merge.evil.driver', command), ('sequence.editor', command)]:
        git(root, 'config', key, value)
    (root / '.gitattributes').write_text('* filter=evil merge=evil\n')
    for name in ('pre-merge-commit', 'post-merge', 'pre-rebase', 'post-rewrite', 'post-checkout'):
        hook = root / '.git/hooks' / name
        hook.write_text('#!/bin/sh\n' + command + '\n')
        hook.chmod(0o755)
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert result['status'] == 'integrated', result
        assert not (tx.upper / 'helper-ran').exists()
        assert not marker.exists()
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_saved_rebase_exec_is_refused(tmp_path, mode):
    root, sandbox, _, remote = fixture(tmp_path)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        private = tx.git_histories['.git'].private
        (private / 'rebase-merge').mkdir()
        (private / 'rebase-merge/git-rebase-todo').write_text('exec touch /workspace/helper-ran\n')
        with pytest.raises(PermissionError, match='discard transaction'):
            engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert not (tx.upper / 'helper-ran').exists()
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_overlapping_owner_changes_are_never_overwritten(tmp_path, mode):
    root, sandbox, _, remote = fixture(tmp_path)
    (root / 'ordinary').write_text('uncommitted owner\n')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert result['status'] == 'refused', result
        assert result['before'] == result['after']
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_untracked_collision_refuses_without_overwriting_owner(tmp_path, mode):
    root, sandbox, _, remote = fixture(tmp_path)
    git(root, 'checkout', '-q', 'remote')
    remote = commit(root, 'collision', 'remote\n', 'remote new path')
    git(root, 'checkout', '-q', 'main')
    (root / 'collision').write_text('untracked owner\n')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert result['status'] == 'refused', result
        assert result['before'] == result['after']
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_tracking_tags_and_other_branches_remain_exact(tmp_path, mode):
    root, sandbox, local, remote = fixture(tmp_path, divergent=True)
    git(root, 'update-ref', 'refs/remotes/origin/main', local)
    git(root, 'symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main')
    git(root, 'tag', 'owner-tag', local)
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        private = tx.git_histories['.git'].private
        args = ['--git-dir=' + str(private)]
        assert git(root, *args, 'rev-parse', 'refs/remotes/origin/main') == local
        assert git(root, *args, 'symbolic-ref', 'refs/remotes/origin/HEAD') == 'refs/remotes/origin/main'
        assert git(root, *args, 'rev-parse', 'refs/tags/owner-tag') == local
        assert git(root, *args, 'rev-parse', 'refs/heads/remote') == remote
        assert result['status'] == ('refused' if mode == 'ff-only' else 'integrated')
        assert snapshot(root) == before
    finally:
        tx.close()


@pytest.mark.parametrize('kind', ['blob', 'missing', 'missing-tree'])
def test_remote_must_be_a_locally_complete_commit_graph(tmp_path, kind):
    root, sandbox, _, remote = fixture(tmp_path)
    tx = transaction(root, sandbox)
    try:
        private = tx.git_histories['.git'].private
        if kind == 'blob':
            remote = git(root, 'hash-object', 'ordinary')
        elif kind == 'missing':
            remote = '1' * 40
        else:
            tree = git(root, 'rev-parse', remote + '^{tree}')
            (private / 'objects' / tree[:2] / tree[2:]).unlink()
        engine = PrivateGitPullIntegration(sandbox)
        with pytest.raises(PermissionError, match='discard transaction'):
            engine.run(tx, remote, 'merge', expected=engine.inspect(tx))
    finally:
        tx.close()


def test_sensitive_masked_files_do_not_prevent_ordinary_baseline_capture(tmp_path):
    root, sandbox, _, remote = fixture(tmp_path)
    (root / '.env').write_text('owner secret never read by Git\n')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, 'ff-only', expected=engine.inspect(tx))
        assert result['status'] == 'integrated', result
        assert snapshot(root) == before
    finally:
        tx.close()


def test_git_subprocess_environment_cannot_inherit_injected_configuration(tmp_path, monkeypatch):
    root, sandbox, _, remote = fixture(tmp_path, divergent=True)
    monkeypatch.setenv('GIT_CONFIG_COUNT', '2')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'core.hooksPath')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', '/workspace/.git/hooks')
    monkeypatch.setenv('GIT_CONFIG_KEY_1', 'core.sshCommand')
    monkeypatch.setenv('GIT_CONFIG_VALUE_1', 'touch /workspace/helper-ran')
    monkeypatch.setenv('GIT_SEQUENCE_EDITOR', 'touch /workspace/helper-ran')
    hook = root / '.git/hooks/pre-rebase'
    hook.write_text('#!/bin/sh\ntouch /workspace/helper-ran\n')
    hook.chmod(0o755)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, 'rebase', expected=engine.inspect(tx))
        assert result['status'] == 'integrated', result
        assert not (tx.upper / 'helper-ran').exists()
        assert not (root / 'helper-ran').exists()
    finally:
        tx.close()


def test_engine_uses_one_live_lease_and_network_false_for_every_phase(tmp_path, monkeypatch):
    from agentporter.workspaces.leases import mutation_lease
    root, sandbox, _, remote = fixture(tmp_path)
    tx = transaction(root, sandbox)
    calls = []
    original = sandbox._run_command
    def checked(**kwargs):
        calls.append(kwargs)
        with pytest.raises(PermissionError, match='active mutation'):
            with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
                pytest.fail('Transaction did not retain the single mutation lease')
        assert kwargs['network_access'] is False
        assert kwargs['require_resources'] is True
        return original(**kwargs)
    monkeypatch.setattr(sandbox, '_run_command', checked)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, 'ff-only', expected=engine.inspect(tx))
        assert result['status'] == 'integrated'
        assert len(calls) == 2
    finally:
        tx.close()


@pytest.mark.parametrize('mode', ['merge', 'rebase'])
def test_stash_stack_and_owner_tags_remain_exact_in_private_integration(tmp_path, mode):
    root, sandbox, _, remote = fixture(tmp_path, divergent=True)
    (root / 'owner').write_text('owner stash\n')
    git(root, 'stash', 'push', '-qm', 'owner stash entry')
    stash = git(root, 'rev-parse', 'refs/stash')
    stash_log = (root / '.git/logs/refs/stash').read_bytes()
    git(root, 'tag', 'owner-tag')
    tag = git(root, 'rev-parse', 'refs/tags/owner-tag')
    before = snapshot(root)
    tx = transaction(root, sandbox)
    try:
        engine = PrivateGitPullIntegration(sandbox)
        result = engine.run(tx, remote, mode, expected=engine.inspect(tx))
        assert result['status'] == 'integrated'
        private = tx.git_histories['.git'].private
        assert git(root, '--git-dir=' + str(private), 'rev-parse', 'refs/stash') == stash
        assert git(root, '--git-dir=' + str(private), 'rev-parse', 'refs/tags/owner-tag') == tag
        assert (private / 'logs/refs/stash').read_bytes() == stash_log
        assert result['before']['stash_log_sha256'] == result['after']['stash_log_sha256']
        assert snapshot(root) == before
    finally:
        tx.close()
