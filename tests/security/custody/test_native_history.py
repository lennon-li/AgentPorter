"""Real offline import of private worker commits; no metadata publication shortcut."""
from tests.sandbox_support import BWRAP
from pathlib import Path
import subprocess

import pytest

from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_git import WorkspaceGitHistory
from agentporter.sandbox import workspace_git as history_module
from tests.security.test_git_approval_state import git, setup
from tests.security.test_workspace_transactions import RecordingResources

pytestmark = pytest.mark.skipif(not Path(BWRAP).is_file(),
                               reason='Gateway native sandbox required')


def history(tmp_path):
    root, _, initial = setup(tmp_path)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    (sandbox.state_dir / 'workspace-transactions').mkdir(exist_ok=True)
    item = WorkspaceGitHistory(root, tmp_path / 'private-history', sandbox)
    return root, item


def private_git(item, *args):
    return subprocess.check_output(['git', '--git-dir=' + str(item.private),
        '--work-tree=' + str(item.workspace), '-c', 'core.hooksPath=/dev/null', *args]).decode().strip()


def test_private_commit_import_preserves_exact_identity_and_protected_config(tmp_path):
    root, item = history(tmp_path)
    try:
        before = git(root, 'rev-parse', 'HEAD')
        config = (root / '.git/config').read_bytes()
        (root / 'ordinary').write_text('agent edit')
        private_git(item, 'add', 'ordinary')
        private_git(item, 'commit', '-qm', 'Autonomous local commit')
        commit = private_git(item, 'rev-parse', 'HEAD')
        assert git(root, 'rev-parse', 'HEAD') == before
        item.prepare()
        item.guard_publication()
        item.publish()
        item.finish()
        assert git(root, 'rev-parse', 'HEAD') == commit
        assert git(root, 'rev-parse', 'HEAD^') == before
        assert git(root, 'status', '--short') == ''
        assert (root / '.git/config').read_bytes() == config
    finally:
        item.close()


def test_private_hooks_and_remote_configuration_never_import(tmp_path):
    root, item = history(tmp_path)
    try:
        (item.private / 'hooks/pre-commit').write_text('private-only hook')
        private_git(item, 'config', 'remote.attacker.url', 'https://example.invalid/')
        (root / 'ordinary').write_text('agent edit')
        private_git(item, 'add', 'ordinary')
        private_git(item, 'commit', '-qm', 'Commit with private configuration')
        item.prepare()
        item.guard_publication()
        item.publish()
        item.finish()
        assert not (root / '.git/hooks/pre-commit').exists()
        assert b'remote.attacker' not in (root / '.git/config').read_bytes()
        assert b'https://example.invalid/' not in (root / '.git/config').read_bytes()
    finally:
        item.close()


def test_private_history_rewrite_imports_exact_private_identity(tmp_path):
    root, item = history(tmp_path)
    try:
        before = git(root, 'rev-parse', 'HEAD')
        private_git(item, 'commit', '--amend', '-qm', 'Rewritten history')
        expected = private_git(item, 'rev-parse', 'HEAD')
        assert expected != before
        item.prepare()
        item.guard_publication()
        item.publish()
        item.finish()
        assert git(root, 'rev-parse', 'HEAD') == expected
    finally:
        item.close()


def test_private_alternates_are_rejected(tmp_path):
    root, item = history(tmp_path)
    try:
        (item.private / 'objects/info/alternates').write_text('/not/authorized')
        with pytest.raises(PermissionError):
            item.prepare()
    finally:
        item.close()


def test_new_private_branch_is_imported_without_changing_other_branches(tmp_path):
    root, item = history(tmp_path)
    try:
        previous = git(root, 'rev-parse', 'HEAD')
        private_git(item, 'checkout', '-qb', 'agent-feature')
        (root / 'ordinary').write_text('feature edit')
        private_git(item, 'add', 'ordinary')
        private_git(item, 'commit', '-qm', 'Feature commit')
        commit = private_git(item, 'rev-parse', 'HEAD')
        item.prepare()
        item.guard_publication()
        item.publish()
        item.finish()
        assert git(root, 'branch', '--show-current') == 'agent-feature'
        assert git(root, 'rev-parse', 'HEAD') == commit
        assert git(root, 'rev-parse', 'reviewed') == previous
    finally:
        item.close()


def test_native_shell_commit_is_private_until_job_quiesces_then_imported(tmp_path):
    root, _, initial = setup(tmp_path)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    old = git(root, 'rev-parse', 'HEAD')
    sandbox.resources.lease.on_close = lambda: None
    result = sandbox.run(str(root), ['/bin/sh', '-c',
        'cd /workspace && printf "native edit" > ordinary && git add ordinary && git commit -qm "Native agent commit"'])
    assert result['exit_code'] == 0, result
    assert git(root, 'rev-parse', 'HEAD') != old
    assert git(root, 'show', '-s', '--format=%s') == 'Native agent commit'
    assert git(root, 'status', '--short') == ''


def test_nested_repository_native_commit_is_imported(tmp_path):
    root, _, initial = setup(tmp_path)
    outer = tmp_path / 'workspace'
    outer.mkdir()
    root.rename(outer / 'nested')
    root = outer / 'nested'
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(outer), ['/bin/sh', '-c',
        'cd /workspace/nested && printf "nested edit" > ordinary && git -c safe.directory=/workspace/nested add ordinary && git -c safe.directory=/workspace/nested commit -qm "Nested agent commit"'])
    assert result['exit_code'] == 0, result
    assert git(root, 'show', '-s', '--format=%s') == 'Nested agent commit'
    assert git(root, 'status', '--short') == ''


def test_failed_native_job_discards_commit_and_edits(tmp_path):
    root, _, initial = setup(tmp_path)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    old = git(root, 'rev-parse', 'HEAD')
    result = sandbox.run(str(root), ['/bin/sh', '-c',
        'cd /workspace && printf changed > ordinary && git add ordinary && git commit -qm "Discarded commit"; exit 7'])
    assert result['exit_code'] == 7, result
    assert git(root, 'rev-parse', 'HEAD') == old
    assert (root / 'ordinary').read_text() == 'initial'


def test_private_hook_cannot_change_canonical_control_files(tmp_path):
    root, _, initial = setup(tmp_path)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    original = (root / '.git/config').read_bytes()
    result = sandbox.run(str(root), ['/bin/sh', '-c',
        'cd /workspace && printf "bad-hook" > .git/hooks/pre-commit && '
        'printf changed > ordinary && git add ordinary && git commit -qm "Protected canonical controls"'])
    assert result['exit_code'] == 0, result
    assert (root / '.git/config').read_bytes() == original
    assert not (root / '.git/hooks/pre-commit').exists()


def test_native_non_head_refs_tags_stash_and_branch_delete_persist(tmp_path):
    root, item = history(tmp_path)
    try:
        private_git(item, 'branch', 'remove-me')
        private_git(item, 'branch', 'keep-me')
        private_git(item, 'branch', '-D', 'remove-me')
        private_git(item, 'tag', '-a', 'v1', '-m', 'native tag')
        (root / 'ordinary').write_text('synthetic native stash')
        private_git(item, 'stash', 'push', '-m', 'native stack')
        wanted = private_git(item, 'show-ref')
        stash = private_git(item, 'stash', 'list', '--format=%H %gs')
        item.prepare()
        item.guard_publication()
        item.publish()
        item.finish()
        assert git(root, 'show-ref') == wanted
        assert git(root, 'stash', 'list', '--format=%H %gs') == stash
    finally:
        item.close()


def test_native_canonical_non_head_ref_drift_retains_guard(tmp_path):
    root, item = history(tmp_path)
    try:
        private_git(item, 'tag', 'private-only')
        item.prepare()
        item.guard_publication()
        git(root, 'tag', 'owner-later-tag')
        with pytest.raises(Exception, match='recovery'):
            item.publish()
        assert item.guard.exists()
        assert git(root, 'tag', '--list') == 'owner-later-tag'
    finally:
        item.close()


def test_native_interrupted_index_publication_retains_guard(tmp_path, monkeypatch):
    root, item = history(tmp_path)
    try:
        old = git(root, 'rev-parse', 'HEAD')
        (root / 'ordinary').write_text('staged fixture')
        private_git(item, 'add', 'ordinary')
        item.prepare()
        expected_tree = item.plan['after']['tree']
        item.guard_publication()
        assert expected_tree != item.plan['before']['tree']
        original = history_module._IMPORT
        marker = '    head_value = '
        assert original.count(marker) == 1
        injected = original.replace(marker,
            "    print('TEST_INDEX_PUBLICATION_REACHED', flush=True)\n"
            "    raise RuntimeError('Injected interruption after index publication')\n" + marker)
        compile(injected, '<interrupted-index-import>', 'exec')
        monkeypatch.setattr(history_module, '_IMPORT', injected)
        observed_import = []
        original_run = item.sandbox._run_command
        def record_import(*args, **kwargs):
            result = original_run(*args, **kwargs)
            observed_import.append(result)
            return result
        monkeypatch.setattr(item.sandbox, '_run_command', record_import)
        with pytest.raises(Exception, match='recovery'):
            item.publish()
        assert len(observed_import) == 1
        assert observed_import[0]['stdout'].splitlines() == ['TEST_INDEX_PUBLICATION_REACHED']
        assert item.guard.exists()
        assert git(root, 'rev-parse', 'HEAD') == old
        assert (root / '.git/index.lock').is_file()
        inspected_index=tmp_path/'inspected-index'
        inspected_index.write_bytes((root/'.git/index').read_bytes())
        import os
        observed_tree=subprocess.check_output(['git','-c','core.fsmonitor=false','write-tree'],cwd=root,
            env={**os.environ,'GIT_INDEX_FILE':str(inspected_index)}).decode().strip()
        assert observed_tree == expected_tree
        assert item.exchange.exists()
    finally:
        item.close()


def test_native_transaction_detached_checkout_publishes_bytes_and_head(tmp_path):
    root, _, initial = setup(tmp_path)
    first = git(root, 'rev-parse', 'HEAD')
    (root / 'ordinary').write_text('second fixture commit')
    git(root, 'add', 'ordinary')
    git(root, 'commit', '-qm', 'second fixture')
    second = git(root, 'rev-parse', 'HEAD')
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c',
        'cd /workspace && git checkout --detach -q HEAD^'])
    assert result['exit_code'] == 0, result
    assert git(root, 'rev-parse', 'HEAD') == first
    assert git(root, 'rev-parse', 'reviewed') == second
    assert git(root, 'branch', '--show-current') == ''
    assert (root / 'ordinary').read_text() == 'initial'
