"""Regression tests for action-map security and truthful Git metadata.

Run on the host's project test environment; no network, credentials, or host
service changes are required. Linux renameat2 is deliberately required.
"""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentporter.tools.files import create_file_tools
from agentporter.workspaces.registry import WorkspaceRegistry


def _tools(tmp_path: Path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    registry = WorkspaceRegistry({"test": {"path": str(workspace), "writable": True}})
    return workspace, create_file_tools(registry)


def test_trash_file_remains_in_workspace(tmp_path: Path):
    root, tools = _tools(tmp_path)
    (root / "example.txt").write_text("original")
    result = tools[-1]("test", "example.txt")
    assert result["status"] == "trashed"
    location = result["trash_location"]
    assert location.startswith(".trash/")
    assert not (root / "example.txt").exists()
    assert (root / location).read_text() == "original"


def test_trash_nested_directory(tmp_path: Path):
    root, tools = _tools(tmp_path)
    (root / "nested").mkdir()
    (root / "nested" / "example.txt").write_text("contents")
    result = tools[-1]("test", "nested")
    assert (root / result["trash_location"] / "example.txt").read_text() == "contents"
    assert not (root / "nested").exists()


def test_trash_rejects_symlinked_trash_directory(tmp_path: Path):
    root, tools = _tools(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / ".trash").symlink_to(outside, target_is_directory=True)
    (root / "safe.txt").write_text("do not move")
    with pytest.raises((OSError, ValueError)):
        tools[-1]("test", "safe.txt")
    assert (root / "safe.txt").read_text() == "do not move"
    assert list(outside.iterdir()) == []


def test_trash_rejects_symlinked_source_ancestor(tmp_path: Path):
    root, tools = _tools(tmp_path)
    (root / "real").mkdir()
    (root / "real" / "file.txt").write_text("safe")
    (root / "shortcut").symlink_to(root / "real", target_is_directory=True)
    with pytest.raises(OSError):
        tools[-1]("test", "shortcut/file.txt")
    assert (root / "real" / "file.txt").read_text() == "safe"


def test_trash_refuses_internal_trash_source(tmp_path: Path):
    root, tools = _tools(tmp_path)
    (root / ".trash").mkdir()
    (root / ".trash" / "keep.txt").write_text("safe")
    with pytest.raises(ValueError, match="trash directory"):
        tools[-1]("test", ".trash/keep.txt")
    assert (root / ".trash" / "keep.txt").exists()


def test_trash_does_not_overwrite_existing_collision(tmp_path: Path, monkeypatch):
    root, tools = _tools(tmp_path)
    (root / ".trash").mkdir()
    (root / "target.txt").write_text("original")
    (root / ".trash" / ("a" * 32 + "_target.txt")).write_text("existing")
    monkeypatch.setattr("agentporter.tools.files.uuid.uuid4", lambda: SimpleNamespace(hex="a" * 32))
    with pytest.raises(FileExistsError):
        tools[-1]("test", "target.txt")
    assert (root / "target.txt").read_text() == "original"
    assert (root / ".trash" / ("a" * 32 + "_target.txt")).read_text() == "existing"


def test_workspace_git_failure_is_not_clean(tmp_path: Path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()
    registry = WorkspaceRegistry({"test": {"path": str(root)}})
    def fail_git(command, *args, **kwargs):
        if command[0] == "git":
            raise AssertionError("workspace_info must not execute host Git")
        raise AssertionError("unexpected subprocess")

    monkeypatch.setattr("agentporter.workspaces.registry.subprocess.run", fail_git)
    result = registry.get_info("test")["git"]
    assert result["is_repo"] is True
    assert result["branch"] is None
    assert result["dirty"] is None
    assert result["error"] == "Git inspection unavailable (use confined Git status)"


def test_workspace_git_metadata_is_unknown_without_confined_backend(tmp_path: Path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    (root / "README.md").write_text("tracked original\n")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "base"], check=True)
    (root / "README.md").write_text("tracked changed!\n")
    (root / "untracked.txt").write_text("untracked\n")
    marker = tmp_path / "filter-was-run"
    subprocess.run(["git", "-C", str(root), "config", "filter.hostile.clean",
                    f"sh -c 'touch {marker}; cat'"], check=True)
    (root / ".gitattributes").write_text("README.md filter=hostile\n")
    subprocess.run(["git", "-C", str(root), "add", ".gitattributes"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "attributes"], check=True)
    # Ignore fixture setup's own clean-filter invocation.
    marker.unlink(missing_ok=True)
    registry = WorkspaceRegistry({"test": {"path": str(root)}})
    def forbidden(*args, **kwargs):
        raise AssertionError("host subprocess executed")
    monkeypatch.setattr("agentporter.workspaces.registry.subprocess.run", forbidden)
    result = registry.get_info("test")["git"]
    assert result["is_repo"] and result["branch"] is None and result["dirty"] is None
    assert result["error"]
    assert not marker.exists()


@pytest.mark.parametrize('operation', ['move', 'mkdir', 'trash'])
def test_mutations_reject_in_workspace_symlink_parents(tmp_path, operation):
    root, tools = _tools(tmp_path)
    (root / 'real').mkdir()
    (root / 'real/file').write_text('original')
    (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
    with pytest.raises((OSError, ValueError)):
        if operation == 'move':
            tools[-2]('test', 'real/file', 'alias/new')
        elif operation == 'mkdir':
            tools[-3]('test', 'alias/new')
        else:
            tools[-1]('test', 'alias/file')
    assert (root / 'real/file').read_text() == 'original'
    assert not (root / 'real/new').exists()


@pytest.mark.parametrize('directory', [False, True])
def test_move_collision_never_overwrites_or_nests(tmp_path, directory):
    root, tools = _tools(tmp_path)
    (root / 'source').write_text('original')
    if directory:
        (root / 'destination').mkdir()
    else:
        (root / 'destination').write_text('existing')
    with pytest.raises(FileExistsError):
        tools[-2]('test', 'source', 'destination')
    assert (root / 'source').read_text() == 'original'
    if directory:
        assert list((root / 'destination').iterdir()) == []
    else:
        assert (root / 'destination').read_text() == 'existing'


def test_move_creates_shared_parents_and_preserves_file(tmp_path):
    root, tools = _tools(tmp_path)
    (root / 'file').write_text('original')
    inode = (root / 'file').stat().st_ino
    tools[-2]('test', 'file', 'new/nested/file')
    assert (root / 'new/nested/file').read_text() == 'original'
    assert (root / 'new/nested/file').stat().st_ino == inode
    assert not (root / 'file').exists()


def test_new_mutation_directory_uses_parent_default_acl(tmp_path, monkeypatch):
    root, tools = _tools(tmp_path)
    inherited = [['user', '23456', 'rwx'], ['group', '', '---'], ['other', '', '---']]
    seen = []
    monkeypatch.setattr('agentporter.tools.files.acl',
                        lambda fd, default=False: inherited if default else [])
    def fake_share(fd, owner, entries=None, *, directory=False, previous_owner=None):
        seen.append((entries, directory))
    monkeypatch.setattr('agentporter.tools.files.share', fake_share)
    monkeypatch.setattr('agentporter.tools.files.human_can_traverse', lambda fd, owner: True)
    tools[-3]('test', 'new/nested')
    assert seen == [(inherited, True), (inherited, True)]


def test_new_mutation_directory_is_removed_when_acl_sharing_fails(tmp_path, monkeypatch):
    root, tools = _tools(tmp_path)
    monkeypatch.setattr('agentporter.tools.files.acl', lambda fd, default=False: [])
    def fail_share(*args, **kwargs):
        raise PermissionError('injected ACL failure')
    monkeypatch.setattr('agentporter.tools.files.share', fail_share)
    with pytest.raises(PermissionError, match='injected ACL failure'):
        tools[-3]('test', 'new')
    assert not (root / 'new').exists()


@pytest.mark.parametrize('failure_call', [1, 2])
def test_directory_acl_access_and_default_failures_never_report_success(tmp_path, monkeypatch, failure_call):
    from agentporter.workspaces import shared_access
    root, _ = _tools(tmp_path)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    calls = 0
    monkeypatch.setattr(shared_access, 'acl', lambda fd, default=False: [
        ['user', '', 'rwx'], ['group', '', 'r-x'], ['other', '', '---']])
    def fail_at_selected_acl_update(*args, **kwargs):
        nonlocal calls
        calls += 1
        command = args[0]
        is_default = '-d' in command
        if is_default == (failure_call == 2):
            raise subprocess.CalledProcessError(1, 'setfacl')
    monkeypatch.setattr(shared_access.subprocess, 'run', fail_at_selected_acl_update)
    try:
        for _ in range(2):  # a retry cannot turn either failed operation into success
            with pytest.raises(subprocess.CalledProcessError):
                shared_access.share(fd, os.fstat(fd).st_uid, directory=True)
    finally:
        os.close(fd)
    assert calls == (2 if failure_call == 1 else 4)


@pytest.mark.parametrize('tool_index', [-1, -2])
def test_move_and_trash_reject_source_symlinks(tmp_path, tool_index):
    root, tools = _tools(tmp_path)
    (root / 'file').write_text('original')
    (root / 'link').symlink_to(root / 'file')
    with pytest.raises(ValueError, match='symlinks'):
        tools[tool_index]('test', 'link', *(['new'] if tool_index == -2 else []))
    assert (root / 'link').is_symlink()
    assert (root / 'file').read_text() == 'original'


@pytest.mark.parametrize("name", ["f" * 255, "😀" * 63])
def test_trash_maximum_length_basename(tmp_path, name):
    root, tools = _tools(tmp_path)
    (root / name).write_text('original')
    result = tools[-1]('test', name)
    assert (root / result['trash_location']).read_text() == 'original'
    assert len(Path(result['trash_location']).name.encode('utf-8')) <= os.pathconf(root, 'PC_NAME_MAX')


@pytest.mark.parametrize('path', ['', '.', 'folder/..', '../outside', '.git/new'])
def test_mkdir_rejects_root_escape_and_protected_paths(tmp_path, path):
    root, tools = _tools(tmp_path)
    with pytest.raises(ValueError):
        tools[-3]('test', path)
    assert list(root.iterdir()) == []


def test_cross_device_move_fails_without_copy_or_delete(tmp_path, monkeypatch):
    import errno
    root, tools = _tools(tmp_path)
    (root / 'file').write_text('original')
    def unsupported(*args):
        raise OSError(errno.EXDEV, 'synthetic cross-device rename')
    monkeypatch.setattr('agentporter.tools.files._rename_noreplace', unsupported)
    with pytest.raises(OSError) as error:
        tools[-2]('test', 'file', 'new')
    assert error.value.errno == errno.EXDEV
    assert (root / 'file').read_text() == 'original'
    assert not (root / 'new').exists()


@pytest.mark.parametrize('failure', [FileNotFoundError, subprocess.TimeoutExpired])
def test_git_unavailable_metadata_is_unknown(tmp_path, monkeypatch, failure):
    root, _ = _tools(tmp_path)
    (root / '.git').mkdir()
    def unavailable(command, *args, **kwargs):
        if command[0] == 'git':
            if failure is subprocess.TimeoutExpired:
                raise failure(command, 5, stderr='private')
            raise failure('private')
        raise AssertionError('unexpected subprocess')
    monkeypatch.setattr('agentporter.workspaces.registry.subprocess.run', unavailable)
    result = WorkspaceRegistry({'test': {'path': str(root)}}).get_info('test')['git']
    assert result['dirty'] is None and result['branch'] is None
    assert 'private' not in str(result)
    assert result['error'] == 'Git inspection unavailable (use confined Git status)'


def test_fake_repository_and_non_repository(tmp_path):
    root, _ = _tools(tmp_path)
    registry = WorkspaceRegistry({'test': {'path': str(root)}})
    result = registry.get_info('test')['git']
    assert result == {'is_repo': False, 'branch': None, 'dirty': None}
    (root / '.git').mkdir()
    result = registry.get_info('test')['git']
    assert result['is_repo'] and result['dirty'] is None and result['error']


def test_detached_head_is_explicit(tmp_path):
    root, _ = _tools(tmp_path)
    for args in [('init', '-q'), ('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'fixture'), ('checkout', '--detach', '-q')]:
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    result = WorkspaceRegistry({'test': {'path': str(root)}}).get_info('test')['git']
    assert result['dirty'] is None and result['branch'] is None and result['error']


def test_trash_acl_names_human_and_preserves_masked_rights(tmp_path, monkeypatch):
    from agentporter.workspaces import shared_access
    if not any(int(line.split()[2]) > 1 for line in Path("/proc/self/uid_map").read_text().splitlines()):
        pytest.skip("Named second UID requires host ACL validation")
    root, tools = _tools(tmp_path)
    (root / 'file').write_text('original')
    (root / '.trash').mkdir(mode=0o700)
    subprocess.run(['setfacl', '-m', 'u:12345:rwx,g::rwx,m::---,o::---', str(root / '.trash')], check=True)
    original = os.fstat
    root_info = root.stat()
    def human_owner(fd):
        info = original(fd)
        if (info.st_dev, info.st_ino) == (root_info.st_dev, root_info.st_ino):
            return SimpleNamespace(st_uid=12346, st_dev=info.st_dev)
        return info
    monkeypatch.setattr('agentporter.tools.files.os.fstat', human_owner)
    result = tools[-1]('test', 'file')
    assert (root / result['trash_location']).read_text() == 'original'
    fd = os.open(root / '.trash', os.O_RDONLY | os.O_DIRECTORY)
    try:
        access = {tuple(row[:2]): row[2] for row in shared_access.acl(fd)}
        defaults = {tuple(row[:2]): row[2] for row in shared_access.acl(fd, default=True)}
    finally:
        os.close(fd)
    assert access[('user', '12346')] == 'rwx'
    assert defaults[('user', '12346')] == 'rwx'
    assert access[('user', '12345')] == '---'
    assert access[('group', '')] == '---'


@pytest.mark.parametrize('operation', ['move', 'mkdir', 'trash'])
def test_ancestor_symlink_swap_after_validation_fails_closed(tmp_path, monkeypatch, operation):
    root, tools = _tools(tmp_path)
    (root / 'parent').mkdir()
    (root / 'parent/file').write_text('inside')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'file').write_text('outside')
    real_open = os.open
    swapped = False
    def swap(name, flags, *args, **kwargs):
        nonlocal swapped
        if name == 'parent' and not swapped:
            swapped = True
            (root / 'parent').rename(root / 'saved')
            (root / 'parent').symlink_to(outside, target_is_directory=True)
        return real_open(name, flags, *args, **kwargs)
    monkeypatch.setattr('agentporter.tools.files.os.open', swap)
    with pytest.raises(OSError):
        if operation == 'move':
            tools[-2]('test', 'parent/file', 'new')
        elif operation == 'trash':
            tools[-1]('test', 'parent/file')
        else:
            tools[-3]('test', 'parent/new')
    assert (outside / 'file').read_text() == 'outside'
    assert not (outside / 'new').exists()
    assert (root / 'saved/file').read_text() == 'inside'


def test_missing_renameat2_fails_closed(tmp_path, monkeypatch):
    root, tools = _tools(tmp_path)
    (root / 'file').write_text('original')
    monkeypatch.setattr('agentporter.tools.files.ctypes.CDLL', lambda *a, **k: SimpleNamespace())
    with pytest.raises(OSError) as error:
        tools[-2]('test', 'file', 'new')
    import errno
    assert error.value.errno == errno.ENOSYS
    assert (root / 'file').read_text() == 'original'


def test_registered_root_only_git_owner_trust(tmp_path, monkeypatch):
    root, _ = _tools(tmp_path)
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)
    (root / 'file').write_text('untracked')
    monkeypatch.setenv('GIT_TEST_ASSUME_DIFFERENT_OWNER', '1')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', '/dev/null')
    monkeypatch.setenv('GIT_CONFIG_SYSTEM', '/dev/null')
    control = subprocess.run(['git', 'status', '--porcelain=v1'], cwd=root, capture_output=True)
    assert control.returncode != 0
    assert b'dubious ownership' in control.stderr
    result = WorkspaceRegistry({'test': {'path': str(root)}}).get_info('test')['git']
    assert result['branch'] is None and result['dirty'] is None
    assert result['error'] == 'Git inspection unavailable (use confined Git status)'
