"""The private Git boundary must preserve the workspace's .venv exclusion."""

import subprocess

import pytest

from agentporter.sandbox.workspace_git import _reject_excluded_git_paths
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction


def repository(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'config', 'user.name', 'test'], check=True)
    subprocess.run(['git', '-C', str(root), 'config', 'user.email', 'test@example.invalid'], check=True)
    (root / 'ordinary.txt').write_text('baseline')
    subprocess.run(['git', '-C', str(root), 'add', 'ordinary.txt'], check=True)
    subprocess.run(['git', '-C', str(root), 'commit', '--quiet', '-m', 'baseline'], check=True)
    return root, root / '.git'


def git(root, *args, **kwargs):
    return subprocess.run(
        ['git', '-C', str(root), *args], check=True, capture_output=True, **kwargs
    ).stdout.decode().strip()


def test_ordinary_git_history_remains_usable(tmp_path):
    root, metadata = repository(tmp_path)
    _reject_excluded_git_paths(metadata, root)
    (root / 'ordinary.txt').write_text('changed')
    git(root, 'add', 'ordinary.txt')
    git(root, 'commit', '--quiet', '-m', 'ordinary change')
    _reject_excluded_git_paths(metadata, root)


def test_staged_excluded_index_entry_is_rejected(tmp_path):
    root, metadata = repository(tmp_path)
    oid = git(root, 'hash-object', '-w', '--stdin', input=b'synthetic dependency')
    git(root, 'update-index', '--add', '--cacheinfo', f'100644,{oid},.venv/injected.py')
    with pytest.raises(PermissionError, match='excluded .venv'):
        _reject_excluded_git_paths(metadata, root)


def test_excluded_path_in_committed_history_is_rejected(tmp_path):
    root, metadata = repository(tmp_path)
    (root / '.venv').mkdir()
    (root / '.venv/installed.py').write_text('synthetic dependency')
    git(root, 'add', '.venv/installed.py')
    git(root, 'commit', '--quiet', '-m', 'synthetic excluded path')
    with pytest.raises(PermissionError, match='excluded .venv'):
        _reject_excluded_git_paths(metadata, root)


def test_intermediate_excluded_commit_cannot_be_hidden_by_later_delete(tmp_path):
    root, metadata = repository(tmp_path)
    (root / '.venv').mkdir()
    (root / '.venv/installed.py').write_text('synthetic dependency')
    git(root, 'add', '.venv/installed.py')
    git(root, 'commit', '--quiet', '-m', 'add excluded path')
    (root / '.venv/installed.py').unlink()
    (root / '.venv').rmdir()
    git(root, 'add', '-A')
    git(root, 'commit', '--quiet', '-m', 'delete excluded path')
    with pytest.raises(PermissionError, match='excluded .venv'):
        _reject_excluded_git_paths(metadata, root)


def test_excluded_commit_in_head_reflog_is_rejected(tmp_path):
    root, metadata = repository(tmp_path)
    base_branch = git(root, 'branch', '--show-current')
    git(root, 'checkout', '--quiet', '-b', 'excluded-history')
    (root / '.venv').mkdir()
    (root / '.venv/installed.py').write_text('synthetic dependency')
    git(root, 'add', '.venv/installed.py')
    git(root, 'commit', '--quiet', '-m', 'excluded path in reflog')
    git(root, 'checkout', '--quiet', base_branch)
    git(root, 'branch', '-D', 'excluded-history')
    with pytest.raises(PermissionError, match='excluded .venv'):
        _reject_excluded_git_paths(metadata, root)


def test_readonly_transaction_rejects_git_history_exposing_excluded_path(tmp_path):
    root, _ = repository(tmp_path)
    (root / '.venv').mkdir()
    (root / '.venv/installed.py').write_text('synthetic dependency')
    git(root, 'add', '.venv/installed.py')
    git(root, 'commit', '--quiet', '-m', 'synthetic excluded path')
    with pytest.raises(PermissionError, match='excluded .venv'):
        WorkspaceTransaction(root, tmp_path / 'state', writable=False)
