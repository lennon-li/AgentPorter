"""Fail-closed validation of a quiescent workspace overlay before publication.

The caller must first stop the entire job cgroup and retain exclusive control of
its overlay. Validation alone does not publish data or grant commit authority.
"""
import os
import stat
from pathlib import Path
from contextlib import contextmanager

from agentporter.workspaces.paths import check_sensitive_components


class UnsafeWorkspaceDelta(PermissionError):
    """An overlay contains a change that must not be published."""


def _require_public_path(relative_path: str) -> None:
    parts = relative_path.replace('\\', '/').split('/')
    if parts and parts[0] == '.venv':
        raise UnsafeWorkspaceDelta('Excluded development environment changed')
    try:
        check_sensitive_components(relative_path, relative_path)
    except ValueError as error:
        raise UnsafeWorkspaceDelta('Protected workspace path changed') from error


def validate_workspace_delta(root: Path, *, max_entries: int = 100_000,
                             deletion_baseline=None, repository_births=None) -> set[str]:
    """Validate a quiescent upper; only native whiteouts with a baseline delete.

    Callers supplying no baseline retain fail-closed rejection of all devices.
    A native 0:0 character whiteout is absence in the merged overlay.
    """
    if max_entries <= 0:
        raise ValueError('max_entries must be positive')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    metadata_prefixes = ()
    if repository_births is not None:
        from agentporter.sandbox.repository_birth import RepositoryBirths
        if not isinstance(repository_births, RepositoryBirths) or Path(root) != repository_births._transaction.upper:
            raise UnsafeWorkspaceDelta("Git birth delta requires the exact host capability")
        metadata_prefixes = repository_births.validate()
    base_fd = os.open(root, flags)
    remaining = max_entries
    deletions = set()
    try:
        def inspect(fd: int, depth: int, parts: tuple[str, ...] = ()) -> None:
            nonlocal remaining
            if depth > 128:
                raise UnsafeWorkspaceDelta('Workspace delta exceeds depth limit')
            if any(name.startswith(('user.overlay.', 'trusted.overlay.'))
                   for name in os.listxattr(fd) if name not in {'user.overlay.origin', 'trusted.overlay.origin',
                                         'user.overlay.uuid', 'trusted.overlay.uuid',
                                         'user.overlay.impure', 'trusted.overlay.impure'}):
                raise UnsafeWorkspaceDelta('Unsupported overlay metadata')
            with os.scandir(fd) as entries:
                for entry in entries:
                    remaining -= 1
                    if remaining < 0:
                        raise UnsafeWorkspaceDelta('Workspace delta exceeds entry limit')
                    relative_parts = parts + (entry.name,)
                    if '/'.join(relative_parts) in metadata_prefixes:
                        continue  # independently validated exact newborn Git subtree
                    _require_public_path('/'.join(relative_parts))
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(0, 0):
                        relative = '/'.join(relative_parts)
                        original = (deletion_baseline or {}).get(relative)
                        if (original is None or not stat.S_ISREG(original[2])
                                or original[3] != 1 or original[2] & 0o7000
                                or original[4] > 64 * 1024 * 1024
                                or info.st_nlink < 1 or info.st_mode != stat.S_IFCHR
                                or info.st_size != 0):
                            raise UnsafeWorkspaceDelta('Deletion requires an ordinary captured baseline file')
                        # Native overlayfs shares whiteout inodes with its work
                        # directory (observed nlink=2 for plain unlink). Marker
                        # aliases contain no bytes and are never opened/imported;
                        # ordinary baseline and published files stay single-link.
                        names = os.listxattr(f'/proc/self/fd/{fd}/{entry.name}', follow_symlinks=False)
                        if any(name.startswith(('user.overlay.', 'trusted.overlay.')) for name in names):
                            raise UnsafeWorkspaceDelta('Unsupported whiteout metadata')
                        deletions.add(relative)
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            inspect(child, depth + 1, relative_parts)
                        finally:
                            os.close(child)
                    elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                          or info.st_mode & 0o7000 or info.st_size > 64 * 1024 * 1024):
                        raise UnsafeWorkspaceDelta('Unsupported workspace delta entry')
                    else:
                        child = os.open(entry.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                        dir_fd=fd)
                        try:
                            if any(name.startswith(('user.overlay.', 'trusted.overlay.'))
                                   for name in os.listxattr(child) if name not in {'user.overlay.origin', 'trusted.overlay.origin',
                                         'user.overlay.uuid', 'trusted.overlay.uuid',
                                         'user.overlay.impure', 'trusted.overlay.impure'}):
                                raise UnsafeWorkspaceDelta('Unsupported overlay metadata')
                        finally:
                            os.close(child)
        inspect(base_fd, 0)
    finally:
        os.close(base_fd)
    return deletions


def publish_workspace_file(workspace, relative, source, *, expected_sha256=None,
                           original=None, custody_operation=None, expected_support=None,
                           on_prepared=None):
    """Create-only publication; replacement needs journaled protected custody.

    Legacy callers must not select an arbitrary fresh inode by its bytes alone.
    """
    if expected_sha256 is not None and (original is None or custody_operation is None
            or original['sha256'] != expected_sha256):
        raise UnsafeWorkspaceDelta('Replacement requires recorded original identity and protected custody')
    return publish_rollbackable_workspace_file(workspace,relative,source,original=original,
        custody_operation=custody_operation,expected_support=expected_support,
        on_prepared=on_prepared or (lambda candidate:None))


def _file_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _workspace_parent(workspace, relative):
    parts = relative.split('/')
    if not relative or any(part in {'', '.', '..'} for part in parts):
        raise UnsafeWorkspaceDelta('Invalid relative workspace path')
    _require_public_path(relative)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(workspace, flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


def _read_deletion_file(descriptor, *, expected_signature=None, expected_sha256=None, expected_links=1):
    import hashlib
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != expected_links
            or before.st_mode & 0o7000 or before.st_size > 64 * 1024 * 1024):
        raise UnsafeWorkspaceDelta('Deletion source must be an ordinary single-link file')
    if expected_signature is not None and _file_signature(before) != tuple(expected_signature):
        raise UnsafeWorkspaceDelta('Deletion conflicts with owner identity or metadata changes')
    content = bytearray()
    while chunk := os.read(descriptor, min(65536, 64 * 1024 * 1024 + 1 - len(content))):
        content.extend(chunk)
        if len(content) > 64 * 1024 * 1024:
            raise UnsafeWorkspaceDelta('Deletion source exceeds size limit')
    if _file_signature(os.fstat(descriptor)) != _file_signature(before):
        raise UnsafeWorkspaceDelta('Deletion source changed during inspection')
    digest = hashlib.sha256(content).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise UnsafeWorkspaceDelta('Deletion conflicts with owner content changes')
    return bytes(content), before, digest


def backup_workspace_deletion(workspace, relative, backup, *, expected_signature):
    """Verify original bytes and durably copy privately before journaling delete."""
    import base64
    with _workspace_parent(workspace, relative) as (parent, name):
        source = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            data, info, digest = _read_deletion_file(source, expected_signature=expected_signature)
            attributes = {key: base64.b64encode(os.getxattr(source, key)).decode('ascii')
                          for key in os.listxattr(source)}
            if _file_signature(os.fstat(source)) != _file_signature(info):
                raise UnsafeWorkspaceDelta('Deletion metadata changed during backup')
        finally:
            os.close(source)
    backup = Path(backup)
    parent = os.open(backup.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent_info = os.fstat(parent)
        if parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o077:
            raise UnsafeWorkspaceDelta('Deletion backup storage must be private')
        space = os.fstatvfs(parent)
        if space.f_bavail * space.f_frsize < len(data) + 4096:
            raise UnsafeWorkspaceDelta('Insufficient deletion backup space')
        output = os.open(backup.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        try:
            with os.fdopen(os.dup(output), 'wb') as stream:
                stream.write(data)
                stream.flush()
            os.lseek(output, 0, os.SEEK_SET)
            _read_deletion_file(output, expected_sha256=digest)
            os.fchmod(output, 0o400)
            os.fsync(output)
            backup_signature = _file_signature(os.fstat(output))
        finally:
            os.close(output)
        os.fsync(parent)
    finally:
        os.close(parent)
    return {'signature': list(_file_signature(info)), 'sha256': digest,
            'backup_signature': list(backup_signature), 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'atime_ns': info.st_atime_ns,
            'mtime_ns': info.st_mtime_ns, 'xattrs': attributes}


def delete_workspace_file(workspace, relative, *, expected_signature, expected_sha256,
                          custody_operation=None, expected_record=None, expected_support=None):
    """Retain the exact entry atomically; never unlink a workspace pathname."""
    if (custody_operation is None or expected_record is None
            or list(expected_record['signature']) != list(expected_signature)
            or expected_record['sha256'] != expected_sha256):
        raise UnsafeWorkspaceDelta('Removal requires recorded identity and protected custody')
    from agentporter.sandbox.workspace_custody import capture_workspace_entry
    return capture_workspace_entry(workspace,relative,custody_operation,
        expected_record=expected_record,expected_support=expected_support)


def _restore_intent(path, document):
    """Durably identify the exact prepared inode before create-only publication."""
    import json
    import secrets
    path = Path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise UnsafeWorkspaceDelta('Restoration intent storage must be private')
        temporary = '.restore-intent-' + secrets.token_hex(16)
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        with os.fdopen(output, 'wb') as stream:
            stream.write(json.dumps(document, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        os.fsync(parent)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def _publish_restore_fd(parent, source, destination):
    """Create a name for the exact anonymous O_TMPFILE inode, never a source path.

    AT_SYMLINK_FOLLOW follows the kernel-owned /proc/self/fd capability. A project
    owner has no source directory entry to replace. linkat preserves create-only
    destination semantics and never follows an existing destination symlink.
    """
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    link = libc.linkat
    link.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    link.restype = ctypes.c_int
    if link(-100, os.fsencode(f'/proc/self/fd/{source}'), parent, os.fsencode(destination), 0x400):
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value), destination)


def restore_workspace_deletion(workspace, relative, backup, *, record, intent_path=None,
                               replace_record=None, on_prepared=None, custody_operation=None, expected_support=None):
    """Restore verified original content to absence only; never overwrite."""
    import base64
    with _workspace_parent(Path(backup).parent, Path(backup).name) as (storage, name):
        source = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=storage)
        try:
            content, _, _ = _read_deletion_file(source,
                expected_signature=record['backup_signature'], expected_sha256=record['sha256'])
        finally:
            os.close(source)
    with _workspace_parent(workspace, relative) as (parent, name):
        if expected_support is not None and [os.fstat(parent).st_dev,os.fstat(parent).st_ino] != expected_support['source_parent']:
            raise UnsafeWorkspaceDelta('Publication parent differs from protected preflight')
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if replace_record is not None:
                original = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    _read_deletion_file(original, expected_signature=replace_record['signature'],
                                        expected_sha256=replace_record['sha256'])
                finally:
                    os.close(original)
            else:
                raise UnsafeWorkspaceDelta('Restoration refuses an existing destination')
        # No workspace-visible temporary name exists at any point. A crash
        # before publication closes this anonymous inode automatically; retry
        # reconstructs from the independently verified durable original backup.
        output = os.open('.', os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            with os.fdopen(os.dup(output), 'wb') as stream:
                stream.write(content)
                stream.flush()
            os.fchown(output, record['uid'], record['gid'])
            os.fchmod(output, record['mode'])
            for key, value in record['xattrs'].items():
                os.setxattr(output, key, base64.b64decode(value, validate=True))
            os.utime(output, ns=(record['atime_ns'], record['mtime_ns']))
            os.fsync(output)
            info = os.fstat(output)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns) != (
                    record['uid'], record['gid'], record['mode'], record['mtime_ns']):
                raise UnsafeWorkspaceDelta('Restoration cannot preserve original access metadata')
            if {key: base64.b64encode(os.getxattr(output, key)).decode('ascii')
                    for key in os.listxattr(output)} != record['xattrs']:
                raise UnsafeWorkspaceDelta('Restoration xattrs differ from original')
            if intent_path is not None:
                _restore_intent(intent_path, {'path': relative, 'signature': list(_file_signature(info)),
                                             'sha256': record['sha256']})
            if on_prepared is not None:
                on_prepared({'signature': list(_file_signature(info)), 'sha256': record['sha256'],
                             'mode': record['mode'], 'uid': record['uid'], 'gid': record['gid'],
                             'mtime_ns': record['mtime_ns'], 'xattrs': record['xattrs']})
            os.lseek(output, 0, os.SEEK_SET)
            _read_deletion_file(output, expected_signature=list(_file_signature(info)),
                                expected_sha256=record['sha256'], expected_links=0)
            if replace_record is not None:
                # A mixed transaction has durable original bytes and prepared
                # candidate identity before its first mutation. Unlink+create
                # deliberately favors an owner destination appearing in the
                # gap, rather than overwriting it with an unchecked rename.
                delete_workspace_file(workspace, relative,
                    expected_signature=replace_record['signature'], expected_sha256=replace_record['sha256'],
                    custody_operation=custody_operation,expected_record=replace_record,expected_support=expected_support)
            _publish_restore_fd(parent, output, name)
            os.fsync(parent)
            # Do not issue a receipt for the still-open source fd alone. Pin and
            # verify the actual destination's type, identity, bytes and access
            # metadata; preserve any later owner entry on ambiguity.
            published = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                expected = os.fstat(output)
                actual = os.fstat(published)
                if _file_signature(actual) != _file_signature(expected):
                    raise UnsafeWorkspaceDelta('Published restoration differs from its prepared inode')
                _read_deletion_file(published, expected_signature=_file_signature(expected),
                                    expected_sha256=record['sha256'])
                if (actual.st_uid, actual.st_gid, stat.S_IMODE(actual.st_mode), actual.st_mtime_ns) != (
                        record['uid'], record['gid'], record['mode'], record['mtime_ns']):
                    raise UnsafeWorkspaceDelta('Published restoration access metadata differs')
                if {key: base64.b64encode(os.getxattr(published, key)).decode('ascii')
                        for key in os.listxattr(published)} != record['xattrs']:
                    raise UnsafeWorkspaceDelta('Published restoration xattrs differ')
                if _file_signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _file_signature(os.fstat(output)):
                    raise UnsafeWorkspaceDelta('Restored destination changed during final verification')
                return list(_file_signature(os.fstat(published)))
            finally:
                os.close(published)
        finally:
            os.close(output)


def publish_rollbackable_workspace_file(workspace, relative, source, *, original=None, on_prepared,
                                        custody_operation=None, expected_support=None):
    """Publish one schema3 create/replace with descriptor custody and recovery intent."""
    import base64
    descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _, info, digest = _read_deletion_file(descriptor)
        attrs = {key: base64.b64encode(os.getxattr(descriptor, key)).decode('ascii') for key in os.listxattr(descriptor)}
        record = {'backup_signature': list(_file_signature(info)), 'sha256': digest,
                  'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                  'atime_ns': info.st_atime_ns, 'mtime_ns': info.st_mtime_ns, 'xattrs': attrs}
        if original is not None:
            for field in ('mode', 'uid', 'gid', 'xattrs'):
                record[field] = original[field]
    finally:
        os.close(descriptor)
    return restore_workspace_deletion(workspace, relative, source, record=record,
                                      replace_record=original, on_prepared=on_prepared,
                                      custody_operation=custody_operation,expected_support=expected_support)
