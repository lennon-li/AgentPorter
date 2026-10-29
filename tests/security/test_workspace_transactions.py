"""Host writes must be published only after a complete bounded validation."""
import os
from pathlib import Path

import pytest

from agentporter.workspace_transactions import WorkspaceTransaction, WorkspaceTransactionError


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'a.txt').write_text('original')
    state = tmp_path / 'state'
    return root, state


def transaction(setup, **kwargs):
    root, state = setup
    return WorkspaceTransaction(root, state, 'task-1', **kwargs)


def test_publish_write_file_and_directory(setup):
    root, _ = setup
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'a.txt').write_text('changed')
    (stage / 'sub').mkdir()
    (stage / 'sub' / 'new').write_text('new')
    assert (root / 'a.txt').read_text() == 'original'
    summary = tx.apply()
    assert (root / 'a.txt').read_text() == 'changed'
    assert (root / 'sub' / 'new').read_text() == 'new'
    assert summary['written'] == ['a.txt', 'sub/new']
    assert 'original' not in repr(summary)
    tx.cleanup()
    tx.cleanup()
    assert not stage.exists()


@pytest.mark.parametrize('approved', [False, True])
def test_delete_requires_separate_approval(setup, approved):
    root, _ = setup
    tx = transaction(setup, allow_delete=approved)
    stage = tx.prepare()
    (stage / 'a.txt').unlink()
    if approved:
        assert tx.apply()['deleted'] == ['a.txt']
        assert not (root / 'a.txt').exists()
    else:
        with pytest.raises(WorkspaceTransactionError):
            tx.apply()
        assert (root / 'a.txt').read_text() == 'original'
    tx.cleanup()


@pytest.mark.parametrize('path', ['../escape', '/absolute', 'a/../b', '.', 'a//b', '.git/config'])
def test_unsafe_allowlist_rejected(setup, path):
    with pytest.raises(WorkspaceTransactionError):
        transaction(setup, allowed_paths=[path])


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'mode', 'git', 'protected'])
def test_validation_prevents_all_writes(setup, kind):
    root, _ = setup
    tx = transaction(setup, protected_paths=['secret'])
    stage = tx.prepare()
    (stage / 'a.txt').write_text('changed')
    if kind == 'symlink':
        (stage / 'evil').symlink_to(root.parent)
    elif kind == 'hardlink':
        os.link(stage / 'a.txt', stage / 'evil')
    elif kind == 'fifo':
        os.mkfifo(stage / 'evil')
    elif kind == 'mode':
        (stage / 'a.txt').chmod(0o4755)
    elif kind == 'git':
        (stage / 'nested').mkdir()
        (stage / 'nested' / '.git').mkdir()
    else:
        (stage / 'secret').write_text('private')
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert (root / 'a.txt').read_text() == 'original'
    tx.cleanup()


@pytest.mark.parametrize('kind', ['file', 'root', 'ancestor'])
def test_concurrent_source_changes_are_preserved(setup, kind):
    root, _ = setup
    (root / 'sub').mkdir()
    (root / 'sub' / 'b').write_text('before')
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'sub' / 'b').write_text('after')
    if kind == 'file':
        (root / 'sub' / 'b').write_text('external')
    elif kind == 'root':
        root.rename(root.with_name('old'))
        root.mkdir()
    else:
        (root / 'sub').rename(root / 'old-sub')
        (root / 'sub').symlink_to(root / 'old-sub', target_is_directory=True)
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    tx.cleanup()


def test_cancel_does_not_apply(setup):
    root, _ = setup
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'a.txt').write_text('changed')
    tx.cleanup()
    assert (root / 'a.txt').read_text() == 'original'
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()


@pytest.mark.parametrize('limit', [{'max_files': 0}, {'max_bytes': 1}])
def test_snapshot_budget_fails_closed(setup, limit):
    with pytest.raises(WorkspaceTransactionError):
        transaction(setup, **limit).prepare()


def test_stage_budget_fails_before_publication(setup):
    root, _ = setup
    tx = transaction(setup, max_bytes=10)
    stage = tx.prepare()
    (stage / 'a.txt').write_text('too many bytes')
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert (root / 'a.txt').read_text() == 'original'
    tx.cleanup()


def test_symlink_source_copied_without_following(setup):
    root, _ = setup
    (root / 'link').symlink_to(root.parent)
    tx = transaction(setup)
    stage = tx.prepare()
    assert (stage / 'link').is_symlink()
    tx.cleanup()


def test_nested_git_excluded_and_preserved(setup):
    root, _ = setup
    (root / 'nested' / '.git').mkdir(parents=True)
    (root / 'nested' / '.git' / 'config').write_text('metadata')
    tx = transaction(setup)
    stage = tx.prepare()
    assert not (stage / 'nested' / '.git').exists()
    tx.apply()
    assert (root / 'nested' / '.git' / 'config').read_text() == 'metadata'
    tx.cleanup()


def test_allowlist_and_task_lock(setup):
    root, _ = setup
    tx = transaction(setup, allowed_paths=['sub'])
    stage = tx.prepare()
    with pytest.raises(WorkspaceTransactionError):
        transaction(setup).prepare()
    (stage / 'a.txt').write_text('denied')
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert (root / 'a.txt').read_text() == 'original'
    tx.cleanup()


def test_publication_failure_rolls_back_all_applied_changes(setup, monkeypatch):
    root, _ = setup
    (root / 'b.txt').write_text('second')
    tx = transaction(setup, allow_delete=True)
    stage = tx.prepare()
    (stage / 'a.txt').unlink()
    (stage / 'b.txt').write_text('changed')
    original = os.replace
    failed = False
    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError('injected publish failure')
        return original(*args, **kwargs)
    monkeypatch.setattr(os, 'replace', fail_once)
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert (root / 'a.txt').read_text() == 'original'
    assert (root / 'b.txt').read_text() == 'second'
    tx.cleanup()


def test_existing_symlinks_are_inert_and_cannot_be_modified(setup):
    root, _ = setup
    (root / 'dependency').symlink_to('/outside/dependency')
    tx = transaction(setup)
    stage = tx.prepare()
    assert (stage / 'dependency').is_symlink()
    assert os.readlink(stage / 'dependency') == '/outside/dependency'
    (stage / 'a.txt').write_text('changed')
    tx.apply()
    assert os.readlink(root / 'dependency') == '/outside/dependency'
    tx.cleanup()
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'dependency').unlink()
    (stage / 'dependency').symlink_to('a.txt')
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert os.readlink(root / 'dependency') == '/outside/dependency'
    tx.cleanup()


def test_directory_deletion_rolls_back_on_later_failure(setup, monkeypatch):
    root, _ = setup
    (root / 'sub').mkdir()
    (root / 'sub' / 'file').write_text('keep')
    tx = transaction(setup, allow_delete=True)
    stage = tx.prepare()
    (stage / 'sub' / 'file').unlink()
    (stage / 'sub').rmdir()
    (stage / 'a.txt').write_text('new')
    original = os.replace
    failed = False
    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError('injected')
        return original(*args, **kwargs)
    monkeypatch.setattr(os, 'replace', fail_once)
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert (root / 'sub' / 'file').read_text() == 'keep'
    assert (root / 'a.txt').read_text() == 'original'
    tx.cleanup()


def test_interrupt_during_publication_restores_originals(setup, monkeypatch):
    root, _ = setup
    (root / 'b.txt').write_text('second')
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'a.txt').write_text('new-a')
    (stage / 'b.txt').write_text('new-b')
    original = os.replace
    calls = 0
    def interrupt_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original(*args, **kwargs)
    monkeypatch.setattr(os, 'replace', interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        tx.apply()
    assert (root / 'a.txt').read_text() == 'original'
    assert (root / 'b.txt').read_text() == 'second'
    tx.cleanup()


def test_workspace_lease_serializes_distinct_tasks(setup):
    root, state = setup
    first = transaction(setup)
    first.prepare()
    second = WorkspaceTransaction(root, state, 'task-2')
    with pytest.raises(WorkspaceTransactionError):
        second.prepare()
    first.cleanup()
    second = WorkspaceTransaction(root, state, 'task-2')
    second.prepare()
    second.cleanup()


def test_new_world_writable_file_is_refused(setup):
    root, _ = setup
    tx = transaction(setup)
    stage = tx.prepare()
    (stage / 'new').write_text('new')
    (stage / 'new').chmod(0o666)
    with pytest.raises(WorkspaceTransactionError):
        tx.apply()
    assert not (root / 'new').exists()
    tx.cleanup()


def test_cleanup_refuses_replaced_private_task_directory(setup):
    root, state = setup
    tx = transaction(setup)
    stage = tx.prepare()
    owned = stage.parent
    moved = state / 'moved-owned'
    owned.rename(moved)
    owned.mkdir()
    (owned / 'unowned').write_text('preserve')
    with pytest.raises(WorkspaceTransactionError):
        tx.cleanup()
    assert (owned / 'unowned').read_text() == 'preserve'
    owned.rename(state / 'unowned-replacement')
    moved.rename(owned)
    tx.cleanup()
