"""Lazy workspace transactions: bound changed output, never the workspace size.

The view service owns the FUSE mount. Only its merged directory is passed into
Bubblewrap; all backing directories and its socket remain outside the sandbox.
Original filesystem ctime and pinned ancestors detect concurrent host changes.
As with the snapshot backend, non-cooperating host writers must be quiescent
during publication. No mount or privileged operation runs in a model process.
"""
from __future__ import annotations

import array
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import time

from agentporter.resources import ResourceCleanupError
from agentporter.workspace_transactions import WorkspaceTransaction, WorkspaceTransactionError, _Entry
from agentporter.workspace_view_service import endpoint, private_directory
from agentporter.workspaces.shared_access import acl, share, human_can_traverse, bits, permissions


class CowWorkspaceTransaction(WorkspaceTransaction):
    """A whole-workspace view with a bounded, explicitly validated write set."""

    contains_git_metadata = True

    def __init__(self, *args, view_endpoint=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.view_endpoint = Path(view_endpoint) if view_endpoint else endpoint()
        self._channel = None
        self._view_fd = None
        self._lease_dir = None
        self._source_acl = {}
        self._source_times = {}
        self._baseline = {}
        self._started_ns = None

    def prepare(self):
        if self._channel is not None or self._root_fd is not None or self._applied:
            raise WorkspaceTransactionError('transaction already prepared or closed')
        try:
            private_directory(self.private_state_root)
            for path in (self.source_root, *self.source_root.parents):
                if path.is_symlink():
                    raise WorkspaceTransactionError('symlink in workspace path')
            self._root_fd = self._open_dir(self.source_root)
            self._root_identity = os.fstat(self._root_fd)
            identity = f'{self._root_identity.st_dev}:{self._root_identity.st_ino}'.encode()
            self._workspace_lock = os.open(
                self.private_state_root / ('workspace-' + hashlib.sha256(identity).hexdigest() + '.lock'),
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._workspace_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock = os.open(self.private_state_root / (self.task_id + '.lock'),
                                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            private_directory(self.view_endpoint.parent)
            info = self.view_endpoint.lstat()
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise WorkspaceTransactionError('Untrusted workspace view endpoint')
            channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._channel = channel
            channel.settimeout(10)
            channel.connect(str(self.view_endpoint))
            channel.send(json.dumps({'operation': 'create', 'workspace_root': str(self.source_root)}).encode())
            packet, ancillary, flags, _ = channel.recvmsg(4096, socket.CMSG_SPACE(16))
            descriptors = array.array('i')
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
            try:
                response = json.loads(packet)
                if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) != 1
                        or set(response) != {'status', 'lease_dir', 'started_ns'}
                        or response['status'] != 'created'
                        or type(response['started_ns']) is not int):
                    raise WorkspaceTransactionError('Workspace view creation refused')
                view_fd = descriptors.pop()
                self._view_fd = view_fd
                if not stat.S_ISDIR(os.fstat(view_fd).st_mode):
                    raise WorkspaceTransactionError('Invalid workspace view descriptor')
                owned = private_directory(response['lease_dir'])
                if owned == self.source_root or owned.is_relative_to(self.source_root):
                    raise WorkspaceTransactionError('Workspace view overlaps source')
                self._lease_dir = owned
                self._lease_identity = owned.stat()
                self._started_ns = response['started_ns']
                if not 0 < self._started_ns <= time.time_ns():
                    raise WorkspaceTransactionError('Invalid workspace view timestamp')
                self.staging_root = Path(f'/proc/self/fd/{view_fd}')
                return self.staging_root
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
        except BaseException as exc:
            self.cleanup()
            if isinstance(exc, (OSError, ValueError)):
                raise WorkspaceTransactionError('Private workspace view unavailable') from exc
            raise

    @property
    def view_descriptor(self):
        if self._view_fd is None:
            raise WorkspaceTransactionError('Workspace view is not prepared')
        return self._view_fd

    def _parent_fd(self, root_fd, rel, *, source=False):
        fd = os.dup(root_fd)
        prefix = ''
        try:
            if source:
                self._unchanged_time(os.fstat(fd))
            for component in rel.split('/')[:-1]:
                prefix = f'{prefix}/{component}' if prefix else component
                child = self._open_dir(component, dir_fd=fd)
                os.close(fd)
                fd = child
                if source:
                    info = os.fstat(fd)
                    self._unchanged_time(info)
                    self._baseline[prefix] = self._entry(info)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _unchanged_time(self, info):
        if info.st_ctime_ns > self._started_ns:
            raise WorkspaceTransactionError('Concurrent source change')

    @staticmethod
    def _entry(info, data=b''):
        return _Entry(stat.S_ISDIR(info.st_mode), stat.S_IMODE(info.st_mode), info.st_uid,
                      info.st_gid, info.st_dev, info.st_ino, data, stat.S_ISLNK(info.st_mode))

    def _read(self, root_fd, rel, *, source=False):
        try:
            parent = self._parent_fd(root_fd, rel, source=source)
        except FileNotFoundError:
            return None
        try:
            name = rel.split('/')[-1]
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if source:
                self._unchanged_time(info)
            if info.st_mode & 0o7000 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise WorkspaceTransactionError('Unsupported file type or privileged mode')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise WorkspaceTransactionError('Hardlink mutation refused')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(info.st_mode):
                flags |= os.O_DIRECTORY
            descriptor = os.open(name, flags, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                    raise WorkspaceTransactionError('File identity changed')
                if source:
                    self._source_acl[rel] = acl(descriptor)
                    self._source_times[rel] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                data = b''
                if not stat.S_ISDIR(info.st_mode):
                    if info.st_size > self.max_bytes:
                        raise WorkspaceTransactionError('Changed file exceeds job byte budget')
                    chunks = []
                    total = 0
                    while True:
                        block = os.read(descriptor, min(65536, self.max_bytes - total + 1))
                        if not block:
                            break
                        chunks.append(block)
                        total += len(block)
                        if total > self.max_bytes:
                            raise WorkspaceTransactionError('Changed file exceeds job byte budget')
                    data = b''.join(chunks)
                    after = os.fstat(descriptor)
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise WorkspaceTransactionError('File changed during validation')
                return self._entry(info, data)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def _candidates(self):
        result = set()
        opaque = set()
        upper = self._lease_dir / 'upper'
        for current, dirs, files in os.walk(upper, followlinks=False):
            prefix = Path(current).relative_to(upper).as_posix()
            prefix = '' if prefix == '.' else prefix
            for name in dirs + files:
                rel = f'{prefix}/{name}' if prefix else name
                item = Path(current) / name
                info = item.lstat()
                if name in {'.wh..opq', '.wh..wh..opq'}:
                    opaque.add(prefix)
                    continue
                if name.startswith('.wh.'):
                    rel = f'{prefix}/{name[4:]}' if prefix else name[4:]
                self._path(rel)
                if stat.S_ISCHR(info.st_mode):
                    if os.major(info.st_rdev) != 0 or os.minor(info.st_rdev) != 0:
                        raise WorkspaceTransactionError('Special output file refused')
                elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise WorkspaceTransactionError('Symlink or special output refused')
                if info.st_mode & 0o7000 or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    raise WorkspaceTransactionError('Privileged or hardlinked output refused')
                if stat.S_ISDIR(info.st_mode):
                    try:
                        if os.getxattr(item, 'user.fuseoverlayfs.opaque') == b'y':
                            opaque.add(rel)
                    except OSError as exc:
                        if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                            raise
                result.add(rel)
                if len(result) > self.max_files:
                    raise WorkspaceTransactionError('Job change entry budget exceeded')
        # An opaque directory can hide original descendants without individual
        # whiteouts. Enumerate only that changed subtree, never all workspaces.
        for rel in opaque:
            if not rel:
                raise WorkspaceTransactionError('Opaque workspace root refused')
            try:
                parent = self._parent_fd(self._root_fd, rel, source=True)
            except FileNotFoundError:
                continue
            try:
                try:
                    source_fd = self._open_dir(rel.split('/')[-1], dir_fd=parent)
                except FileNotFoundError:
                    continue
                try:
                    def walk(fd, prefix):
                        for name in os.listdir(fd):
                            path = f'{prefix}/{name}'
                            self._path(path)
                            result.add(path)
                            if len(result) > self.max_files:
                                raise WorkspaceTransactionError('Job change entry budget exceeded')
                            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                child = self._open_dir(name, dir_fd=fd)
                                try: walk(child, path)
                                finally: os.close(child)
                    walk(source_fd, rel)
                finally:
                    os.close(source_fd)
            finally:
                os.close(parent)
        return sorted(result)

    def _publish(self, rel, entry):
        """Publish through pinned parents and retain effective collaborator ACLs."""
        self._check_root()
        fd = self._parent(rel)
        name = rel.split('/')[-1]
        owner = self._root_identity.st_uid
        old = self._baseline.get(rel)
        try:
            if not human_can_traverse(fd, owner):
                raise WorkspaceTransactionError('Collaborator cannot traverse publication parent')
            if entry is None:
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(current.st_mode):
                    os.rmdir(name, dir_fd=fd)
                else:
                    os.unlink(name, dir_fd=fd)
            elif entry.directory:
                os.mkdir(name, mode=0o700, dir_fd=fd)
                child = self._open_dir(name, dir_fd=fd)
                try:
                    os.fchmod(child, entry.mode)
                    share(child, owner, self._source_acl.get(rel, acl(fd, default=True)),
                          directory=True, previous_owner=entry.uid if old else None)
                    info = os.fstat(child)
                    self._published_dirs[rel] = (info.st_dev, info.st_ino)
                finally:
                    os.close(child)
            else:
                temporary = '.agentporter-' + os.urandom(16).hex()
                handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                try:
                    with os.fdopen(handle, 'wb') as stream:
                        stream.write(entry.data)
                        os.fchmod(stream.fileno(), entry.mode)
                        share(stream.fileno(), owner, self._source_acl.get(rel, acl(fd, default=True)),
                              previous_owner=old.uid if old else None)
                        if old is None and entry.mode & 0o100:
                            # Inherited directory ACLs are first reduced to file
                            # rights. Preserve an explicitly created executable
                            # for its creator/collaborator without unmasking
                            # execute rights for any unrelated named user/group.
                            entries = acl(stream.fileno())
                            owner_key = '' if owner == os.getuid() else str(owner)
                            for row in entries:
                                if (row[0] == 'user' and row[1] in {'', owner_key}) or row[0] == 'mask':
                                    row[2] = permissions(bits(row[2]) | 1)
                            share(stream.fileno(), owner, entries, previous_owner=os.getuid())
                        os.fsync(stream.fileno())
                    if old is None and not getattr(self, '_rolling_back', False):
                        # New outputs never overwrite a concurrent creator.
                        os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd,
                                follow_symlinks=False)
                    else:
                        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(fd)

    def apply(self):
        if self._view_fd is None or self._root_fd is None or self._applied:
            raise WorkspaceTransactionError('Transaction is not pending')
        applied = []
        try:
            self._check_root()
            owned = self._lease_dir.stat()
            if (owned.st_dev, owned.st_ino) != (self._lease_identity.st_dev, self._lease_identity.st_ino):
                raise WorkspaceTransactionError('View lease directory changed')
            changes = {}
            old_bytes = new_bytes = 0
            for rel in self._candidates():
                if (any(rel == path or rel.startswith(path + '/') for path in self.protected_paths)
                        or self.allowed_paths is not None and not any(
                            rel == path or rel.startswith(path + '/') for path in self.allowed_paths)):
                    raise WorkspaceTransactionError('Path outside writable policy')
                old = self._read(self._root_fd, rel, source=True)
                new = self._read(self._view_fd, rel)
                # UID/GID in the private view intentionally belong to this
                # service, independently of the original collaborator's UID.
                content = lambda item: None if item is None else (item.directory, item.mode, item.data)
                if content(old) == content(new):
                    continue
                if old is not None:
                    self._baseline[rel] = old
                    old_bytes += len(old.data)
                if new is not None:
                    new_bytes += len(new.data)
                if max(old_bytes, new_bytes) > self.max_bytes:
                    raise WorkspaceTransactionError('Job change byte budget exceeded')
                if new is None and old is not None and not self.allow_delete:
                    raise WorkspaceTransactionError('Deletion requires separate approval')
                if old and new and (old.directory != new.directory or old.mode != new.mode):
                    raise WorkspaceTransactionError('File type or mode mutation refused')
                if new and new.mode & 0o002:
                    raise WorkspaceTransactionError('World writable output refused')
                if new and (new.uid != os.getuid() or new.gid != os.getgid()):
                    raise WorkspaceTransactionError('Unexpected view identity')
                changes[rel] = new
            deleted = sorted((p for p, e in changes.items() if e is None), key=lambda p: (-p.count('/'), p))
            directories = sorted((p for p, e in changes.items() if e and e.directory), key=lambda p: (p.count('/'), p))
            written = sorted(p for p, e in changes.items() if e and not e.directory)
            for rel in deleted + directories + written:
                self._publish(rel, changes[rel])
                applied.append(rel)
            self._applied = True
            return {'written': written, 'created_directories': directories, 'deleted': deleted,
                    'bytes_written': new_bytes}
        except BaseException as exc:
            try:
                self._rolling_back = True
                for rel in reversed(applied):
                    self._publish(rel, self._baseline.get(rel))
            except BaseException as rollback_error:
                raise WorkspaceTransactionError('Publication and rollback failed; retain private state') from rollback_error
            if isinstance(exc, (OSError, ValueError)):
                raise WorkspaceTransactionError('Workspace publication refused') from exc
            raise

    def cleanup(self):
        failure = None
        if self._view_fd is not None:
            os.close(self._view_fd)
            self._view_fd = None
        if self._channel is not None:
            try:
                try: self._channel.send(b'close')
                except (BrokenPipeError, ConnectionResetError): pass
                self._channel.settimeout(10)
                reply = self._channel.recv(4096)
                # A rejected/budget-exceeded view still sends a separate final
                # cleanup acknowledgement; rejection is not a cleanup failure.
                if reply == b'{"status":"denied"}': reply = self._channel.recv(4096)
                if reply != b'closed': failure = ResourceCleanupError('Workspace view cleanup unverified')
            except OSError as exc:
                failure = ResourceCleanupError('Workspace view cleanup unverified')
            finally:
                self._channel.close()
                self._channel = None
        for name in ('_root_fd', '_workspace_lock', '_lock'):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)
        if failure is not None:
            raise failure
