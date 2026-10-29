"""Bounded, explicit workspace publication for untrusted sandbox output.

The caller must stop the producer before apply/cleanup, keep private_state_root
outside the sandbox, and mount only prepare()'s staging directory writable.
Existing symlinks are copied as inert links without following their targets;
symlink mutations, hardlinks and special files fail closed. Git metadata is never copied or published. Transactions are not a
filesystem sandbox or a crash-atomic multi-file commit: external writers must be
quiescent during publication. Per-file replacement is atomic; ordinary Python
exceptions trigger rollback. Task and workspace leases serialize cooperating
transactions using the same private state root. The caller MUST ensure host
writers are quiescent; advisory leases cannot restrain unrelated processes.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass


class WorkspaceTransactionError(RuntimeError):
    """Snapshot, validation or publication was refused."""


@dataclass(frozen=True)
class _Entry:
    directory: bool
    mode: int
    uid: int
    gid: int
    dev: int
    ino: int
    data: bytes = b''
    symlink: bool = False

    def content(self):
        return self.directory, self.mode, self.uid, self.gid, self.data, self.symlink


class WorkspaceTransaction:
    """Own a private snapshot and validate every change before publication.

    allowed_paths is None for the whole workspace, or exact relative file/directory
    prefixes. protected_paths always wins. Empty allowed_paths permits no changes.
    max_files bounds all entries (directories included); max_bytes bounds contents.
    apply() returns path-only audit metadata; it never returns file contents.
    """

    def __init__(self, source_root, private_state_root, task_id, *, allow_delete=False,
                 allowed_paths=None, protected_paths=(), max_files=10000,
                 max_bytes=64 * 1024 * 1024):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', task_id):
            raise WorkspaceTransactionError('invalid task ID')
        self.source_root = Path(os.path.abspath(source_root))
        self.private_state_root = Path(os.path.abspath(private_state_root))
        if (self.source_root == self.private_state_root or
                self.source_root in self.private_state_root.parents or
                self.private_state_root in self.source_root.parents):
            raise WorkspaceTransactionError('private state and workspace must be disjoint')
        self.task_id = task_id
        self.allow_delete = allow_delete
        self.allowed_paths = None if allowed_paths is None else tuple(self._path(p) for p in allowed_paths)
        self.protected_paths = tuple(self._path(p) for p in protected_paths)
        if max_files < 0 or max_bytes < 0:
            raise WorkspaceTransactionError('invalid resource budget')
        self.max_files, self.max_bytes = max_files, max_bytes
        self._owned = None
        self._lock = None
        self._workspace_lock = None
        self._root_fd = None
        self._baseline = None
        self._applied = False
        self._published_dirs = {}

    @staticmethod
    def _path(value):
        if not isinstance(value, str) or not value or '\x00' in value or '\\' in value:
            raise WorkspaceTransactionError('invalid relative path')
        parts = value.split('/')
        if any(p in ('', '.', '..', '.git') for p in parts) or value.startswith('/'):
            raise WorkspaceTransactionError('invalid relative path')
        return value

    @staticmethod
    def _open_dir(path, *, dir_fd=None):
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)

    def _scan(self, fd, *, stage=False):
        entries = {}
        total = 0

        def walk(parent, prefix):
            nonlocal total
            for name in sorted(os.listdir(parent)):
                rel = f'{prefix}/{name}' if prefix else name
                if name == '.git':
                    if stage:
                        raise WorkspaceTransactionError('Git metadata in staged output')
                    continue
                self._path(rel)
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                directory = stat.S_ISDIR(info.st_mode)
                symlink = stat.S_ISLNK(info.st_mode)
                if not directory and not symlink and not stat.S_ISREG(info.st_mode):
                    raise WorkspaceTransactionError('symlink or special file is unsupported')
                if info.st_mode & 0o7000 or (not directory and info.st_nlink != 1):
                    raise WorkspaceTransactionError('unsafe file mode or hardlink')
                if len(entries) >= self.max_files:
                    raise WorkspaceTransactionError('workspace entry budget exceeded')
                data = b''
                if symlink:
                    data = os.fsencode(os.readlink(name, dir_fd=parent))
                    total += len(data)
                    if total > self.max_bytes:
                        raise WorkspaceTransactionError('workspace byte budget exceeded')
                elif not directory:
                    if total + info.st_size > self.max_bytes:
                        raise WorkspaceTransactionError('workspace byte budget exceeded')
                    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        before = os.fstat(handle)
                        if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink) != (
                                info.st_dev, info.st_ino, info.st_mode, 1):
                            raise WorkspaceTransactionError('file changed during snapshot')
                        chunks = []
                        remaining = self.max_bytes - total
                        while True:
                            chunk = os.read(handle, min(65536, remaining + 1))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                            if remaining < 0:
                                raise WorkspaceTransactionError('workspace byte budget exceeded')
                            chunks.append(chunk)
                        after = os.fstat(handle)
                        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            raise WorkspaceTransactionError('file changed during snapshot')
                        data = b''.join(chunks)
                    finally:
                        os.close(handle)
                    total += len(data)
                entries[rel] = _Entry(directory, stat.S_IMODE(info.st_mode), info.st_uid,
                                      info.st_gid, info.st_dev, info.st_ino, data, symlink)
                if directory:
                    child = self._open_dir(name, dir_fd=parent)
                    try:
                        now = os.fstat(child)
                        if (now.st_dev, now.st_ino) != (info.st_dev, info.st_ino):
                            raise WorkspaceTransactionError('directory changed during snapshot')
                        walk(child, rel)
                    finally:
                        os.close(child)
        walk(fd, '')
        return entries

    def prepare(self):
        if self._owned is not None or self._baseline is not None:
            raise WorkspaceTransactionError('transaction already prepared or closed')
        try:
            # Resolve no symlink components, including ancestors of the root/state.
            for path in (self.source_root, self.private_state_root):
                for component in (path, *path.parents):
                    if component.is_symlink():
                        raise WorkspaceTransactionError('symlink in workspace/state path')
            self.private_state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_info = self.private_state_root.stat()
            if state_info.st_uid != os.getuid() or state_info.st_mode & 0o022:
                raise WorkspaceTransactionError('private state must be owned and not publicly writable')
            self._lock = os.open(self.private_state_root / (self.task_id + '.lock'),
                                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._root_fd = self._open_dir(self.source_root)
            self._root_identity = os.fstat(self._root_fd)
            identity = f'{self._root_identity.st_dev}:{self._root_identity.st_ino}'.encode()
            lease_name = 'workspace-' + hashlib.sha256(identity).hexdigest() + '.lock'
            self._workspace_lock = os.open(self.private_state_root / lease_name,
                                           os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._workspace_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._baseline = self._scan(self._root_fd)
            self._owned = Path(tempfile.mkdtemp(prefix=self.task_id + '-', dir=self.private_state_root))
            self._owned_identity = self._owned.lstat()
            self._state_identity = self.private_state_root.lstat()
            self.staging_root = self._owned / 'workspace'
            self.staging_root.mkdir(mode=0o700)
            for path, entry in self._baseline.items():
                target = self.staging_root / path
                if entry.directory:
                    target.mkdir(mode=0o700)
                elif entry.symlink:
                    target.symlink_to(os.fsdecode(entry.data))
                else:
                    target.write_bytes(entry.data)
                    target.chmod(entry.mode)
            for path, entry in reversed(list(self._baseline.items())):
                if entry.directory:
                    (self.staging_root / path).chmod(entry.mode)
            return self.staging_root
        except BaseException as exc:
            self.cleanup()
            if not isinstance(exc, (OSError, WorkspaceTransactionError)):
                raise
            raise WorkspaceTransactionError(f'workspace snapshot refused: {exc}') from exc

    def _check_root(self):
        if any(p.is_symlink() for p in (self.source_root, *self.source_root.parents)):
            raise WorkspaceTransactionError('symlink in source root path')
        current = self.source_root.lstat()
        if (current.st_dev, current.st_ino) != (self._root_identity.st_dev, self._root_identity.st_ino):
            raise WorkspaceTransactionError('source root changed')

    def _parent(self, rel):
        fd = os.dup(self._root_fd)
        try:
            prefix = ''
            for component in rel.split('/')[:-1]:
                prefix = f'{prefix}/{component}' if prefix else component
                child = self._open_dir(component, dir_fd=fd)
                os.close(fd)
                fd = child
                old = self._baseline.get(prefix)
                if old:
                    now = os.fstat(fd)
                    if (now.st_dev, now.st_ino) != self._published_dirs.get(prefix, (old.dev, old.ino)):
                        raise WorkspaceTransactionError('source ancestor changed')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _publish(self, rel, entry):
        self._check_root()
        fd = self._parent(rel)
        name = rel.split('/')[-1]
        try:
            if entry is None:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    os.rmdir(name, dir_fd=fd)
                else:
                    os.unlink(name, dir_fd=fd)
            elif entry.directory:
                os.mkdir(name, mode=entry.mode, dir_fd=fd)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                self._published_dirs[rel] = (info.st_dev, info.st_ino)
            else:
                temporary = '.agentporter-' + os.urandom(16).hex()
                handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                try:
                    with os.fdopen(handle, 'wb') as stream:
                        stream.write(entry.data)
                        os.fchmod(stream.fileno(), entry.mode)
                        os.fsync(stream.fileno())
                    os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(fd)

    def apply(self):
        if self._root_fd is None or self._baseline is None or self._applied:
            raise WorkspaceTransactionError('transaction is not pending')
        applied = []
        try:
            self._check_root()
            stage_fd = self._open_dir(self.staging_root)
            try:
                staged = self._scan(stage_fd, stage=True)
            finally:
                os.close(stage_fd)
            changes = sorted(p for p in self._baseline.keys() | staged.keys()
                             if p not in self._baseline or p not in staged or
                             self._baseline[p].content() != staged[p].content())
            current = self._scan(self._root_fd)
            for path in changes:
                if (any(path == p or path.startswith(p + '/') for p in self.protected_paths) or
                        self.allowed_paths is not None and not any(
                            path == p or path.startswith(p + '/') for p in self.allowed_paths)):
                    raise WorkspaceTransactionError('path outside writable policy')
                old, new = self._baseline.get(path), staged.get(path)
                if (old and old.symlink) or (new and new.symlink):
                    raise WorkspaceTransactionError('symlink mutation refused')
                if new is None and not self.allow_delete:
                    raise WorkspaceTransactionError('deletion requires separate approval')
                if old and new and (old.directory != new.directory or old.mode != new.mode or
                                   old.uid != new.uid or old.gid != new.gid):
                    raise WorkspaceTransactionError('file type/ownership/mode mutation refused')
                if new and old is None and new.mode & 0o002:
                    raise WorkspaceTransactionError('new world writable entry refused')
                if new and (new.uid != os.getuid() or new.gid != os.getgid()):
                    raise WorkspaceTransactionError('unexpected staged owner')
                now = current.get(path)
                if old != now:
                    raise WorkspaceTransactionError('concurrent source change')
                # Ancestors must still be the originally snapshotted directories.
                parts = path.split('/')
                for i in range(1, len(parts)):
                    parent = '/'.join(parts[:i])
                    if parent in self._baseline and self._baseline[parent] != current.get(parent):
                        raise WorkspaceTransactionError('concurrent source ancestor change')
                if old and old.directory and new is None:
                    # Excluded metadata must never be removed indirectly.
                    directory_fd = self._parent(path + '/placeholder')
                    try:
                        if '.git' in os.listdir(directory_fd):
                            raise WorkspaceTransactionError('directory contains protected Git metadata')
                    finally:
                        os.close(directory_fd)
            deleted = sorted((p for p in changes if p not in staged), key=lambda p: (-p.count('/'), p))
            created_dirs = sorted((p for p in changes if p in staged and staged[p].directory),
                                  key=lambda p: (p.count('/'), p))
            written = sorted(p for p in changes if p in staged and not staged[p].directory)
            for path in deleted + created_dirs + written:
                self._publish(path, staged.get(path))
                applied.append(path)
            self._applied = True
            return {'written': written, 'created_directories': created_dirs, 'deleted': deleted,
                    'bytes_written': sum(len(staged[p].data) for p in written)}
        except BaseException as exc:
            try:
                for path in reversed(applied):
                    self._publish(path, self._baseline.get(path))
            except (OSError, WorkspaceTransactionError) as rollback_exc:
                raise WorkspaceTransactionError('publication failed; rollback failed; retain private state') from rollback_exc
            if not isinstance(exc, (OSError, WorkspaceTransactionError)):
                raise
            raise WorkspaceTransactionError(f'workspace publication refused: {exc}') from exc

    def cleanup(self):
        """Cancel unapplied output and remove only the uniquely owned task directory."""
        if self._owned is not None:
            state = self.private_state_root.lstat()
            owned = self._owned.lstat()
            if (any(p.is_symlink() for p in (self.private_state_root, *self.private_state_root.parents))
                    or (state.st_dev, state.st_ino) != (self._state_identity.st_dev, self._state_identity.st_ino)
                    or (owned.st_dev, owned.st_ino) != (self._owned_identity.st_dev, self._owned_identity.st_ino)):
                raise WorkspaceTransactionError('private task directory identity changed; cleanup refused')
            shutil.rmtree(self._owned)
            self._owned = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None
        if self._workspace_lock is not None:
            os.close(self._workspace_lock)
            self._workspace_lock = None
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None
