"""Atomic workspace writes preserving effective POSIX ACLs.

The registered workspace's owner is its human collaborator (yeli on A7Dev).
This does not chown files, grant world access, or operate on service secrets.
ACL tools must be installed; failures abort before publishing a replacement.
"""
import contextlib
import os
import pwd
import secrets
import stat
import subprocess

from agentporter.workspaces.paths import validate_workspace_path


def acl(fd, *, default=False):
    result = subprocess.run(
        ['getfacl', '-cpnE', '-d' if default else '-a', '--', f'/proc/self/fd/{fd}'],
        pass_fds=(fd,), capture_output=True, text=True, check=True, timeout=5,
    )
    return [line.removeprefix('default:').split(':') for line in result.stdout.splitlines()
            if line and not line.startswith('#')]


def bits(value):
    return sum(bit for char, bit in zip(value, (4, 2, 1)) if char != '-')


def permissions(value):
    return ''.join(char if value & bit else '-' for char, bit in zip('rwx', (4, 2, 1)))


def shared_acl(entries, owner_uid, file_uid, *, directory=False, previous_owner=None):
    """Add the collaborator without unmasking anyone else's latent ACL rights."""
    allowed = 7 if directory else 6
    mask = next((bits(row[2]) for row in entries if row[0] == 'mask'), 7)
    effective = {}
    for kind, qualifier, value in entries:
        if kind == 'mask':
            continue
        value = bits(value)
        if kind == 'group' or (kind == 'user' and qualifier):
            value &= mask
        effective[(kind, qualifier)] = value
    if not effective:
        effective = {('user', ''): allowed, ('group', ''): 0, ('other', ''): 0}
    if previous_owner is not None and previous_owner != file_uid:
        effective[('user', str(previous_owner))] = effective[('user', '')]
    key = ('user', '' if owner_uid == file_uid else str(owner_uid))
    effective[key] = effective.get(key, 0) | allowed
    # Inherited directory execute rights are inapplicable to new regular files.
    if entries and previous_owner is None and not directory:
        effective = {key: value & 6 for key, value in effective.items()}
    group_mask = 0
    for (kind, qualifier), value in effective.items():
        if kind == 'group' or (kind == 'user' and qualifier):
            group_mask |= value
    lines = [f'{kind}:{qualifier}:{permissions(value)}'
             for (kind, qualifier), value in effective.items()]
    lines.append(f'mask::{permissions(group_mask)}')
    return '\n'.join(lines) + '\n'


def share(fd, owner_uid, entries=None, *, directory=False, previous_owner=None):
    entries = acl(fd) if entries is None else entries
    value = shared_acl(entries, owner_uid, os.fstat(fd).st_uid,
                       directory=directory, previous_owner=previous_owner)
    subprocess.run(['setfacl', '-n', '--set-file=-', '--', f'/proc/self/fd/{fd}'],
                   input=value, text=True, capture_output=True,
                   pass_fds=(fd,), check=True, timeout=5)
    if directory:
        share_default(fd, owner_uid)


def share_default(fd, owner_uid):
    """Future creators can differ from the directory owner: use a named UID.

    Otherwise user:: follows the service creating a child and the human silently
    loses edit access, even though the directory's access ACL was correct.
    """
    value = shared_acl(acl(fd, default=True), owner_uid, -1, directory=True)
    subprocess.run(['setfacl', '-d', '-n', '--set-file=-', '--', f'/proc/self/fd/{fd}'],
                   input=value, text=True, capture_output=True,
                   pass_fds=(fd,), check=True, timeout=5)


def human_can_traverse(fd, human_uid):
    """Evaluate POSIX ACL search access for the designated collaborator."""
    info = os.fstat(fd)
    entries = {(kind, qualifier): bits(value) for kind, qualifier, value in acl(fd)}
    if human_uid == 0:
        return True
    if info.st_uid == human_uid:
        return bool(entries[('user', '')] & 1)
    mask = entries.get(('mask', ''), 7)
    named = entries.get(('user', str(human_uid)))
    if named is not None:
        return bool(named & mask & 1)
    try:
        account = pwd.getpwuid(human_uid)
        groups = set(os.getgrouplist(account.pw_name, account.pw_gid))
    except KeyError:
        groups = set()
    matching = [value for (kind, qualifier), value in entries.items()
                if kind == 'group' and (info.st_gid if not qualifier else int(qualifier)) in groups]
    if matching:
        return any(value & mask & 1 for value in matching)
    return bool(entries[('other', '')] & 1)


@contextlib.contextmanager
def parent_directory(root, path):
    """Pin parents; share ordinary service-owned ancestors without chmod/chown."""
    target = validate_workspace_path(root, path)
    relative = os.path.relpath(target, os.path.realpath(root)).split(os.sep)
    fd = os.open(os.path.realpath(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owner_uid = os.fstat(fd).st_uid
    try:
        if not human_can_traverse(fd, owner_uid):
            raise ValueError('Workspace owner lacks directory traversal; repair owner permissions first')
        for name in relative[:-1]:
            created = False
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if created:
                    share(child, owner_uid, acl(fd, default=True), directory=True)
                elif os.fstat(child).st_uid == os.geteuid() != owner_uid:
                    # A preexisting service-owned 0700 parent would otherwise
                    # hide even a correctly shared new file from the human.
                    share(child, owner_uid, directory=True)
                if not human_can_traverse(child, owner_uid):
                    raise ValueError('Workspace owner lacks directory traversal; repair owner permissions first')
            except BaseException:
                os.close(child)
                if created:
                    try:
                        os.rmdir(name, dir_fd=fd)
                    except OSError:
                        pass  # A concurrent writer may already be using it.
                raise
            os.close(fd)
            fd = child
        yield fd, relative[-1], owner_uid
    finally:
        os.close(fd)


def atomic_write(root, path, content, expected_sha256=None):
    import hashlib
    with parent_directory(root, path) as (parent, name, owner_uid):
        original = None
        try:
            original = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            pass
        temporary = '.agentporter-write-' + secrets.token_hex(16)
        fd = None
        try:
            if original is not None:
                info = os.fstat(original)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('Write requires a regular file with no hardlink aliases')
                if expected_sha256:
                    if info.st_size > 5 * 1024**2:
                        raise ValueError('File exceeds bounded read/hash budget')
                    data = os.read(original, 5 * 1024**2 + 1)
                    if hashlib.sha256(data).hexdigest().lower() != expected_sha256.lower():
                        raise ValueError('Stale file protection: current sha256 does not match expected')
                entries = acl(original)
                previous_owner = info.st_uid
            else:
                if expected_sha256:
                    raise ValueError('Stale file protection: expected file is missing')
                entries = acl(parent, default=True)
                previous_owner = None
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(content)
                stream.flush()
                share(fd, owner_uid, entries, previous_owner=previous_owner)
                os.fsync(fd)
            if original is None:
                # A new file must never overwrite a concurrent creator.
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                        follow_symlinks=False)
            else:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                         item.st_mtime_ns, item.st_ctime_ns)
                if identity(current) != identity(info):
                    raise ValueError('Stale file protection: file changed during write')
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            if original is not None:
                os.close(original)
            if fd is not None:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
