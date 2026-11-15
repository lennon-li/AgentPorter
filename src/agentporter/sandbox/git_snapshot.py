"""Bounded private copies of Git metadata; no canonical mutation or cleanup API."""
import hashlib
import os
from pathlib import Path
import re
import stat
import time

BASE_SNAPSHOT_LIMIT = 640 * 1024 * 1024
RAW_SNAPSHOT_LIMIT = 256 * 1024 * 1024
ENTRY_LIMIT = 1_000_000
COPY_SECONDS = 60
FREE_HEADROOM = 256 * 1024 * 1024
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def signature(i):
    # Normal reads may update atime. Every write/alias-relevant field is bound.
    return (i.st_dev, i.st_ino, i.st_mode, i.st_uid, i.st_gid, i.st_nlink,
            i.st_size, i.st_mtime_ns, i.st_ctime_ns)


def source_object(path, info, owner):
    return (stat.S_ISREG(info.st_mode) and info.st_nlink > 1
            and (info.st_uid, info.st_gid) == owner and not info.st_mode & 0o7333
            and re.fullmatch(r'objects/(?:[0-9a-f]{2}/(?:[0-9a-f]{38}|[0-9a-f]{62})|pack/pack-(?:[0-9a-f]{40}|[0-9a-f]{64})\.(?:pack|idx))', path) is not None)


class SnapshotBudget:
    """One protected budget shared by all histories in a workspace transaction.

    Free-space checks include already retained custody through f_bavail. They
    are headroom checks, not a filesystem reservation or a lifetime disk quota.
    """
    def __init__(self):
        self.bytes = BASE_SNAPSHOT_LIMIT
        self.raw_bytes = RAW_SNAPSHOT_LIMIT
        self.entries = ENTRY_LIMIT
        self.deadline = time.monotonic() + COPY_SECONDS

    def check(self):
        if time.monotonic() >= self.deadline:
            raise PermissionError('Private Git snapshot exceeds preparation deadline')

    def guard_write(self, descriptor, size):
        self.check()
        space = os.fstatvfs(descriptor)
        if space.f_bavail * space.f_frsize < FREE_HEADROOM + size:
            raise PermissionError('Private Git snapshot lost free-space headroom')

    def guard_raw_write(self, descriptor, size):
        self.raw_bytes -= size
        if self.raw_bytes < 0:
            raise PermissionError('Initial raw Git snapshots exceed aggregate byte budget')
        self.guard_write(descriptor, size)

    def preflight(self, root, destination):
        from agentporter.git_commits import _mount_id
        self.check()
        mount = _mount_id(root)
        owner = os.fstat(root)
        owner = (owner.st_uid, owner.st_gid)
        records = {}
        total = raw = 0
        def walk(fd, prefix='', depth=0):
            nonlocal total, raw
            self.check()
            if _mount_id(fd) != mount:
                raise PermissionError('Git snapshot crosses a source mount boundary')
            if depth > 128:
                raise PermissionError('Private Git snapshot exceeds depth budget')
            records[prefix] = signature(os.fstat(fd))
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.check()
                    path = prefix + entry.name
                    info = entry.stat(follow_symlinks=False)
                    if path in {'commondir', 'reftable', 'objects/info/alternates',
                                'objects/info/http-alternates'} or entry.name.endswith('.lock'):
                        raise PermissionError('Unsupported Git snapshot layout or active lock')
                    if len(records) > self.entries:
                        raise PermissionError('Private Git snapshot exceeds aggregate entry budget')
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, FLAGS, dir_fd=fd)
                        try:
                            if signature(os.fstat(child)) != signature(info):
                                raise PermissionError('Git source directory changed')
                            walk(child, path + '/', depth + 1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode) and (info.st_nlink == 1 or source_object(path, info, owner)):
                        records[path] = signature(info)
                        total += info.st_size
                        if not path.startswith('objects/'):
                            raw += info.st_size
                        if total > self.bytes:
                            raise PermissionError('Private Git snapshot exceeds aggregate byte budget')
                    else:
                        raise PermissionError('Git snapshot source alias is not an immutable object')
            if signature(os.fstat(fd)) != records[prefix]:
                raise PermissionError('Git source directory changed during preflight')
        walk(root)
        if len(records) - 1 > self.entries:
            raise PermissionError('Private Git snapshot exceeds aggregate entry budget')
        if raw > self.raw_bytes:
            raise PermissionError('Initial raw Git snapshots exceed aggregate byte budget')
        space = os.statvfs(destination)
        if space.f_bavail * space.f_frsize < total + raw + FREE_HEADROOM:
            raise PermissionError('Insufficient private Git snapshot headroom; custody retained')
        return records

    def copy(self, root, destination, records):
        from agentporter.git_commits import _mount_id
        mount = _mount_id(root)
        shared = {}
        owner = os.fstat(root)
        owner = (owner.st_uid, owner.st_gid)
        children = {}
        for key in records:
            self.check()
            if not key:
                continue
            relative = key.rstrip('/')
            parent = relative.rsplit('/', 1)[0] + '/' if '/' in relative else ''
            children.setdefault(parent, set()).add(key)
        def walk(fd, target, prefix=''):
            self.check()
            if _mount_id(fd) != mount:
                raise PermissionError('Git copy crosses a source mount boundary')
            if signature(os.fstat(fd)) != records.get(prefix):
                raise PermissionError('Git source directory changed before copy')
            space = os.statvfs(target.parent)
            if space.f_bavail * space.f_frsize < FREE_HEADROOM + 4096:
                raise PermissionError('Private Git directory lost free-space headroom')
            target.mkdir(mode=0o700)
            seen = set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.check()
                    path = prefix + entry.name
                    info = entry.stat(follow_symlinks=False)
                    key = path + '/' if stat.S_ISDIR(info.st_mode) else path
                    if signature(info) != records.get(key):
                        raise PermissionError('Git source changed after preflight')
                    seen.add(key)
                    self.entries -= 1
                    if self.entries < 0:
                        raise PermissionError('Private Git snapshot exceeds aggregate entry budget')
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, FLAGS, dir_fd=fd)
                        try:
                            walk(child, target / entry.name, key)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode) and (info.st_nlink == 1 or source_object(path, info, owner)):
                        source = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            if signature(os.fstat(source)) != records[path] or _mount_id(source) != mount:
                                raise PermissionError('Git source inode changed before copy')
                            digest = hashlib.sha256()
                            copied = 0
                            with open(target / entry.name, 'xb') as output:
                                os.fchmod(output.fileno(), 0o600)
                                self.guard_write(output.fileno(), 4096)
                                while True:
                                    self.check()
                                    data = os.read(source, 65536)
                                    if not data:
                                        break
                                    self.bytes -= len(data)
                                    copied += len(data)
                                    if self.bytes < 0:
                                        raise PermissionError('Private Git snapshot exceeds aggregate byte budget')
                                    self.guard_write(output.fileno(), len(data))
                                    digest.update(data)
                                    output.write(data)
                                if os.fstat(output.fileno()).st_nlink != 1:
                                    raise PermissionError('Private Git copy acquired an alias')
                            if (copied != info.st_size or signature(os.fstat(source)) != records[path]
                                    or signature(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != records[path]):
                                raise PermissionError('Git source changed while copying')
                            if info.st_nlink > 1:
                                shared[path] = {'signature': records[path], 'sha256': digest.hexdigest()}
                        finally:
                            os.close(source)
                    else:
                        raise PermissionError('Git snapshot forbids aliases and special files')
            expected = children.get(prefix, set())
            if seen != expected or signature(os.fstat(fd)) != records[prefix]:
                raise PermissionError('Git source directory changed during copy')
        walk(root, Path(destination))
        return shared
