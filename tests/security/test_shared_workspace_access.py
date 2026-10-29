"""Real filesystem ACL regressions; no mock chmod/setfacl success claims."""
import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from agentporter.tools.files import create_file_tools
from agentporter.workspaces import shared_access
from agentporter.workspaces.registry import WorkspaceRegistry


UID = str(os.getuid())


def set_acl(path, value):
    value = value.replace('12345', UID).replace('12346', UID)
    subprocess.run(['setfacl', '-m', value, '--', str(path)], check=True)


def access(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        return {tuple(row[:2]): row[2] for row in shared_access.acl(fd)}
    finally:
        os.close(fd)


@pytest.fixture
def tools(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    registry = WorkspaceRegistry()
    registry.register('shared', str(root), writable=True)
    return root, create_file_tools(registry)


def test_new_nested_write_under_private_umask(tools):
    root, ops = tools
    set_acl(root, f'd:u:{os.getuid()}:rwx,d:u:12345:r-x,d:g::---,d:o::---')
    old = os.umask(0o077)
    try:
        ops[3]('shared', 'docs/nested/handoff.md', 'hello\n')
    finally:
        os.umask(old)
    target = root / 'docs/nested/handoff.md'
    assert target.read_text() == 'hello\n'
    assert target.stat().st_mode & 0o600 == 0o600
    assert not target.stat().st_mode & 0o007
    assert access(target)[('user', UID)] == 'rw-'
    assert (root / 'docs/nested').stat().st_mode & 0o700 == 0o700
    fd = os.open(root / 'docs/nested', os.O_RDONLY | os.O_DIRECTORY)
    try:
        defaults = {tuple(row[:2]): row[2] for row in shared_access.acl(fd, default=True)}
    finally:
        os.close(fd)
    assert defaults[('user', UID)] == 'rwx'


def test_new_directories_default_acl_explicitly_names_human_for_other_creators(tools):
    root, ops = tools
    ops[3]('shared', 'new/sub/handoff.md', 'hello\n')
    fd = os.open(root / 'new/sub', os.O_RDONLY | os.O_DIRECTORY)
    try:
        defaults = {tuple(row[:2]): row[2] for row in shared_access.acl(fd, default=True)}
    finally:
        os.close(fd)
    assert defaults[('user', UID)] == 'rwx'
    assert defaults[('group', '')] == '---'
    assert defaults[('other', '')] == '---'
    assert defaults[('mask', '')] == 'rwx'


def test_default_acl_grant_does_not_unmask_other_named_rights(tmp_path):
    directory = tmp_path / 'shared'
    directory.mkdir()
    set_acl(directory, 'd:u:12345:rwx,d:g::rwx,d:m::---,d:o::---')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        shared_access.share_default(fd, os.getuid())
        defaults = {tuple(row[:2]): row[2] for row in shared_access.acl(fd, default=True)}
    finally:
        os.close(fd)
    assert defaults[('user', UID)] == 'rwx'
    assert defaults[('group', '')] == '---'
    assert defaults[('other', '')] == '---'


def test_existing_creator_owned_private_parents_gain_human_traversal(tools, monkeypatch):
    root, ops = tools
    mapping = Path('/proc/self/uid_map').read_text().splitlines()
    if not any(int(line.split()[2]) > 1 for line in mapping):
        pytest.skip('Named second UID requires the host ACL validation gate')
    human = 12346
    parent = root / 'existing'
    parent.mkdir(mode=0o700)
    set_acl(parent, 'u:12345:rwx,g::rwx,m::---,o::---')
    # Simulate the root collaborator being a different UID from this writer;
    # the directory and its ACL changes remain real host filesystem operations.
    original = os.fstat
    root_id = (root.stat().st_dev, root.stat().st_ino)
    def different_root_owner(fd):
        info = original(fd)
        if (info.st_dev, info.st_ino) == root_id:
            return SimpleNamespace(st_uid=human)
        return info
    monkeypatch.setattr(shared_access.os, 'fstat', different_root_owner)
    # The search evaluator needs the actual root metadata for its owner check.
    original_search = shared_access.human_can_traverse
    monkeypatch.setattr(shared_access, 'human_can_traverse', lambda fd, uid:
                        True if (original(fd).st_dev, original(fd).st_ino) == root_id
                        else original_search(fd, uid))
    ops[3]('shared', 'existing/handoff.md', 'readable\n')
    assert access(parent)[('user', str(human))] == 'rwx'
    assert access(parent)[('group', '')] == '---'
    assert access(parent)[('user', UID)] == '---'
    assert access(parent / 'handoff.md')[('user', str(human))] == 'rw-'
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert {tuple(r[:2]): r[2] for r in shared_access.acl(fd, default=True)}[('user', str(human))] == 'rwx'
    finally:
        os.close(fd)


def test_untraversable_human_parent_fails_before_file_publication(tools, monkeypatch):
    root, ops = tools
    parent = root / 'private'
    parent.mkdir()
    original = shared_access.human_can_traverse
    inode = parent.stat().st_ino
    monkeypatch.setattr(shared_access, 'human_can_traverse', lambda fd, uid:
                        False if os.fstat(fd).st_ino == inode else original(fd, uid))
    before = access(parent)
    with pytest.raises(ValueError, match='traversal'):
        ops[3]('shared', 'private/handoff.md', 'hidden')
    assert not (parent / 'handoff.md').exists()
    assert access(parent) == before


def test_preexisting_private_mutation_ancestor_fails_closed(tools, monkeypatch):
    root, ops = tools
    from agentporter.tools import files

    parent = root / 'service-owned'
    parent.mkdir(mode=0o700)
    inode = parent.stat().st_ino
    original = files.human_can_traverse
    monkeypatch.setattr(
        files, 'human_can_traverse',
        lambda fd, uid: False if os.fstat(fd).st_ino == inode else original(fd, uid),
    )
    before = access(parent)

    with pytest.raises(PermissionError, match='existing mutation parent'):
        ops[5]('shared', 'service-owned')

    assert not (parent / 'child').exists()
    assert access(parent) == before


def test_share_grants_collaborator_without_unmasking_other_users():
    entries = [['user', '', 'rw-'], ['user', '12345', 'rwx'],
               ['group', '', 'rwx'], ['mask', '', '---'], ['other', '', '---']]
    value = shared_access.shared_acl(entries, 12346, 994, previous_owner=994)
    assert 'user:12346:rw-' in value
    assert 'user:12345:---' in value
    assert 'group::---' in value
    assert 'other::---' in value
    assert 'mask::rw-' in value


def test_named_collaborator_acl_survives_atomic_replacement(tools):
    root, ops = tools
    target = root / 'handoff.md'
    target.write_text('before')
    # A real second UID, rather than a mocked chmod/setfacl invocation. The
    # restricted single-UID harness cannot represent it; the host deploy gate can.
    mapping = Path('/proc/self/uid_map').read_text().splitlines()
    if not any(int(line.split()[2]) > 1 for line in mapping):
        pytest.skip('Named second UID requires the host ACL validation gate')
    fd = os.open(target, os.O_RDONLY)
    try:
        shared_access.share(fd, 12346)
    finally:
        os.close(fd)
    assert access(target)[('user', '12346')] == 'rw-'
    ops[3]('shared', 'handoff.md', 'after')
    entries = access(target)
    assert entries[('user', '12346')] == 'rw-'
    assert shared_access.bits(entries[('mask', '')]) & 6 == 6


def test_atomic_replacement_preserves_effective_acl_and_execute(tools):
    root, ops = tools
    target = root / 'script.sh'
    target.write_text('before\n')
    target.chmod(0o700)
    set_acl(target, 'u:12345:rwx,g:12346:rw-,g::rwx,m::r-x,o::---')
    inode = target.stat().st_ino
    ops[3]('shared', 'script.sh', 'after\n', hashlib.sha256(b'before\n').hexdigest())
    assert target.stat().st_ino != inode
    assert target.stat().st_mode & 0o700 == 0o700
    entries = access(target)
    assert entries[('user', UID)] == 'r-x'
    assert entries[('group', UID)] == 'r--'
    assert entries[('group', '')] == 'r-x'
    assert entries[('other', '')] == '---'


def test_patch_replace_create_and_delete_preserve_access(tools):
    root, ops = tools
    ops[3]('shared', 'old.txt', 'before\n')
    set_acl(root / 'old.txt', 'u:12345:rw-,g::---,o::---')
    inode = (root / 'old.txt').stat().st_ino
    patch = ('--- a/old.txt\n+++ b/old.txt\n@@ -1 +1 @@\n-before\n+after\n'
             '--- /dev/null\n+++ b/docs/new.txt\n@@ -0,0 +1 @@\n+new\n')
    assert ops[4]('shared', patch)['status'] == 'applied'
    assert (root / 'old.txt').stat().st_ino != inode
    assert access(root / 'old.txt')[('user', UID)] == 'rw-'
    assert (root / 'docs/new.txt').read_text() == 'new\n'
    assert ops[4]('shared', '--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-after\n')['status'] == 'applied'
    assert not (root / 'old.txt').exists()


@pytest.mark.parametrize('path', ['.env', 'secrets.env', 'nested/local.env', 'auth.json',
                                 'nested/credentials.json', '.ssh/key', 'TLS.KEY', '.git/config',
                                 '.aws/credentials', '.codex/config.toml', '.codex-liz/config.toml',
                                 '.claude/.credentials.json', '.copilot/config.json',
                                 '.config/github-copilot/hosts.json', '.config/opencode/wei-key',
                                 '.local/share/opencode/auth.json'])
def test_secret_paths_remain_restricted(tools, path):
    root, ops = tools
    sentinel = root / path
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.write_text('synthetic private fixture')
    sentinel.chmod(0o600)
    before = (sentinel.stat().st_mode, access(sentinel))
    with pytest.raises(ValueError, match='sensitive'):
        ops[3]('shared', path, 'bad')
    with pytest.raises(ValueError, match='sensitive'):
        ops[4]('shared', f'--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+bad\n')
    assert (sentinel.stat().st_mode, access(sentinel)) == before


def test_acl_failure_leaves_original_and_no_temporary_file(tools, monkeypatch):
    root, ops = tools
    target = root / 'file'
    target.write_text('before')
    before = target.stat().st_ino
    def denied(*args, **kwargs):
        raise PermissionError('synthetic ACL failure')
    monkeypatch.setattr(shared_access, 'share', denied)
    with pytest.raises(PermissionError):
        ops[3]('shared', 'file', 'after')
    assert target.read_text() == 'before'
    assert target.stat().st_ino == before
    assert not list(root.glob('.agentporter-write-*'))


def test_new_file_does_not_overwrite_concurrent_creator(tools, monkeypatch):
    root, ops = tools
    real_share = shared_access.share
    def concurrent(*args, **kwargs):
        real_share(*args, **kwargs)
        (root / 'file').write_text('concurrent creator')
    monkeypatch.setattr(shared_access, 'share', concurrent)
    with pytest.raises(FileExistsError):
        ops[3]('shared', 'file', 'replacement')
    assert (root / 'file').read_text() == 'concurrent creator'
    assert not list(root.glob('.agentporter-write-*'))


def test_existing_file_changed_during_acl_work_is_not_overwritten(tools, monkeypatch):
    root, ops = tools
    target = root / 'file'
    target.write_text('before')
    real_share = shared_access.share
    def concurrent(*args, **kwargs):
        real_share(*args, **kwargs)
        target.write_text('concurrent edit')
    monkeypatch.setattr(shared_access, 'share', concurrent)
    with pytest.raises(ValueError, match='Stale'):
        ops[3]('shared', 'file', 'replacement')
    assert target.read_text() == 'concurrent edit'
    assert not list(root.glob('.agentporter-write-*'))


def test_stale_failure_and_failed_patch_do_not_change_files(tools):
    root, ops = tools
    target = root / 'file'
    target.write_text('before\n')
    with pytest.raises(ValueError, match='Stale'):
        ops[3]('shared', 'file', 'after', '0' * 64)
    result = ops[4]('shared', '--- a/file\n+++ b/file\n@@ -1 +1 @@\n-absent\n+after\n')
    assert result['status'] == 'failed'
    assert target.read_text() == 'before\n'
    assert sorted(p.name for p in root.iterdir()) == ['file']


def test_write_refuses_hardlinks_and_symlink_escape(tools, tmp_path):
    root, ops = tools
    outside = tmp_path / 'outside'
    outside.write_text('private')
    os.link(outside, root / 'alias')
    with pytest.raises(ValueError, match='hardlink'):
        ops[3]('shared', 'alias', 'bad')
    (root / 'escape').symlink_to(outside)
    with pytest.raises(ValueError, match='escape'):
        ops[3]('shared', 'escape', 'bad')
    assert outside.read_text() == 'private'


def test_patch_hunk_lines_resembling_headers_are_not_paths(tools):
    root, ops = tools
    (root / 'file').write_text('-- .env\n')
    result = ops[4]('shared', '--- a/file\n+++ b/file\n@@ -1 +1 @@\n--- .env\n+++ harmless\n')
    assert result['status'] == 'applied'
    assert (root / 'file').read_text() == '++ harmless\n'
