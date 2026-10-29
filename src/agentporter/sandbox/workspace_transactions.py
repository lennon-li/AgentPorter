"""Private overlay storage and controlled application for one workspace job.

Internal callers must stop and verify the complete job envelope before publish
or close. An interrupted publication retains a durable guard for owner recovery.
This serializes transactional jobs; other mutation tools must share the lease
before this can be enabled for a production workspace.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import workspace_key
from agentporter.sandbox.workspace_delta import (
    UnsafeWorkspaceDelta, _require_public_path, publish_workspace_file,
    validate_workspace_delta,
)


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _fingerprint(path: Path, *, expected_signature=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if expected_signature is not None and _signature(before) != expected_signature:
            raise UnsafeWorkspaceDelta('Workspace edit conflicts with owner changes')
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024 * 1024:
            raise UnsafeWorkspaceDelta('Unsupported workspace baseline file')
        digest = hashlib.sha256()
        remaining = 64 * 1024 * 1024 + 1
        while chunk := os.read(descriptor, min(65536, remaining)):
            remaining -= len(chunk)
            if remaining <= 0:
                raise UnsafeWorkspaceDelta('Workspace baseline file exceeds size limit')
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise UnsafeWorkspaceDelta('Workspace file changed during baseline capture')
        return digest.hexdigest()
    finally:
        os.close(descriptor)


class WorkspaceTransaction:
    def __init__(self, workspace: Path, state: Path, *, max_entries=1_000_000, writable=True, git_sandbox=None):
        self.writable = writable
        self.git_histories = {}
        self.workspace = Path(workspace).resolve(strict=True)
        state = Path(state).resolve()
        if state == self.workspace or state.is_relative_to(self.workspace):
            raise PermissionError('Workspace transaction state must be outside the workspace')
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity = self.workspace.stat()
        key = workspace_key(identity)
        self._lock = os.open(state / (key + '.lock'), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        self._pending = state / (key + '.pending.json')
        self._started = False
        self._closed = False
        self._applied = False
        self.directory = None
        self._root_fd = None
        self._projection_fd = None
        self._publication_fd = None
        try:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PermissionError('Workspace already has an active transaction') from error
            if os.path.lexists(self._pending) or os.path.lexists(state / (key + '.git-pending.json')):
                raise ResourceCleanupError('Workspace publication requires owner recovery')
            # Foreign-owned roots can be private (0700). Pin their identity with
            # O_PATH; data access occurs through the verified idmapped views.
            access = os.O_PATH if writable and identity.st_uid != os.getuid() else os.O_RDONLY
            self._root_fd = os.open(self.workspace, access | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            pinned = os.fstat(self._root_fd)
            if (pinned.st_dev, pinned.st_ino) != (identity.st_dev, identity.st_ino):
                raise PermissionError('Workspace root changed during transaction creation')
            if writable and pinned.st_uid != os.getuid():
                from agentporter.sandbox.workspace_projections import open_workspace_projection, open_workspace_publication
                self._projection_fd = open_workspace_projection(self._root_fd)
                self._publication_fd = open_workspace_publication(self._root_fd)
            publication_fd = self._publication_fd if self._publication_fd is not None else self._root_fd
            self._root_path = f'/proc/self/fd/{publication_fd}/.'
            self.directory = Path(tempfile.mkdtemp(prefix=key[:12] + '-', dir=state))
            self.upper = self.directory / 'upper'
            self.work = self.directory / 'work'
            self.upper.mkdir(mode=0o700)
            self.work.mkdir(mode=0o700)
            self.baseline = {}
            self.masks = []
            remaining = max_entries
            scan_deadline = time.monotonic() + 30
            def failed(error):
                raise PermissionError('Cannot inspect workspace baseline') from error
            for root, directories, files in os.walk(self._root_path, followlinks=False, onerror=failed):
                for name in list(directories) + files:
                    remaining -= 1
                    if remaining < 0 or time.monotonic() >= scan_deadline:
                        raise PermissionError('Workspace baseline exceeds scan budget')
                    path = Path(root) / name
                    relative = path.relative_to(Path(self._root_path)).as_posix()
                    try:
                        _require_public_path(relative)
                    except PermissionError:
                        if name in directories:
                            directories.remove(name)
                        # Git metadata stays available for read-only Git inspection;
                        # any private overlay changes are rejected before application.
                        if name.lower() == '.git' and path.is_symlink():
                            raise PermissionError('Symlinked Git metadata cannot be delegated')
                        if (name == '.git' and writable and git_sandbox is not None
                                and (path / 'HEAD').is_file() and (path / 'config').is_file()):
                            from agentporter.sandbox.workspace_git import WorkspaceGitHistory
                            # Trusted imports need the same owner-mapped view
                            # as ordinary publication, never the foreign-owned
                            # canonical mount. Both have the same dev/inode key.
                            repository = Path(self._root_path) / Path(relative).parent
                            self.git_histories[relative] = WorkspaceGitHistory(
                                repository, self.directory / ('git-' + str(len(self.git_histories))),
                                git_sandbox, nested=Path(relative).parent != Path('.'))
                        if name.lower() != '.git':
                            self.masks.append((relative, path.is_dir() and not path.is_symlink()))
                        continue
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    if stat.S_ISREG(info.st_mode):
                        if info.st_nlink != 1:
                            raise PermissionError('Workspace file has unsupported inode aliases')
                        if writable:
                            self.baseline[relative] = _signature(info)
                    elif not stat.S_ISDIR(info.st_mode):
                        raise PermissionError('Unsupported workspace baseline entry')
        except BaseException:
            for history in self.git_histories.values():
                history.close()
            if self.directory is not None:
                shutil.rmtree(self.directory)
            if self._publication_fd is not None:
                os.close(self._publication_fd)
            if self._projection_fd is not None:
                os.close(self._projection_fd)
            if self._root_fd is not None:
                os.close(self._root_fd)
            os.close(self._lock)
            self._closed = True
            raise

    def wrap_command(self, command, *, workspace_fd=None):
        """Replace only the exact authorized workspace bind with its overlay."""
        if self._closed or self._applied:
            raise PermissionError('Workspace transaction is no longer executable')
        command = list(command)
        self._check_root_identity()
        source = str(self.workspace)
        lower_fd = self._projection_fd if self._projection_fd is not None else self._root_fd
        overlay_source = f'/proc/self/fd/{lower_fd}'
        if workspace_fd is not None:
            pinned = os.fstat(workspace_fd)
            expected = os.fstat(self._root_fd)
            if (pinned.st_dev, pinned.st_ino) != (expected.st_dev, expected.st_ino):
                raise PermissionError('Pinned workspace does not match transaction identity')
            source = f'/proc/self/fd/{workspace_fd}'
            if self._projection_fd is None:
                overlay_source = source
        mounts = {'--bind', '--ro-bind'} if self.writable else {'--ro-bind'}
        matches = [i for i in range(len(command) - 2)
                   if command[i] in mounts and command[i + 1:i + 3] == [source, '/workspace']]
        if len(matches) != 1 or '--' in command:
            raise PermissionError('Expected one authorized workspace mount before command boundary')
        index = matches[0]
        if self.writable:
            command[index:index + 3] = ['--overlay-src', overlay_source, '--overlay', str(self.upper), str(self.work), '/workspace']
        else:
            command[index:index + 3] = ['--ro-bind', overlay_source, '/workspace']
        for i in range(len(command) - 2):
            if command[i:i + 2] == ['--ro-bind', str(self.workspace / '.git')]:
                command[i + 1] = overlay_source + '/.git'
        for relative, directory in self.masks:
            destination = '/workspace/' + relative
            command += ['--tmpfs', destination, '--remount-ro', destination] if directory else ['--ro-bind', '/dev/null', destination]
        # This is private metadata, not a writable canonical .git mount. The
        # ordinary delta validator remains unchanged and still refuses .git.
        for relative, history in self.git_histories.items():
            destination = '/workspace/' + relative
            command += ['--bind', str(history.private), destination,
                        '--ro-bind', str(history.clean_config), destination + '/config']
        return command

    @property
    def launch_fds(self):
        return (self._root_fd,) if self._projection_fd is None else (self._root_fd, self._projection_fd)

    @property
    def inspection_fd(self):
        """The exact read-only lower used for foreign-owner job visibility."""
        return self._projection_fd if self._projection_fd is not None else self._root_fd

    @staticmethod
    def wrap_argv(argv):
        # Bubblewrap needs the pinned mount FD, but the requested command must
        # never receive a host directory capability. Close before exec.
        closer = """import os, sys
for item in os.listdir('/proc/self/fd'):
    descriptor = int(item)
    if descriptor > 2:
        try:
            os.close(descriptor)
        except OSError:
            pass
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
"""
        return ['/usr/bin/python3', '-I', '-S', '-c', closer, *argv]

    def _check_root_identity(self):
        pinned = os.fstat(self._root_fd)
        current = self.workspace.stat()
        if (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino):
            raise PermissionError('Workspace root identity changed')

    def _journal(self, changes):
        data = json.dumps({'workspace': str(self.workspace), 'transaction': str(self.directory), 'changes': changes}).encode()
        descriptor = os.open(self._pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self._sync_state()
        except BaseException as error:
            raise ResourceCleanupError('Workspace publication journal requires recovery') from error

    def _sync_state(self):
        descriptor = os.open(self._pending.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def publish(self):
        """Apply validated edits only after caller proves full process cleanup."""
        if self._closed or self._started or self._applied:
            raise PermissionError('Workspace transaction cannot be published twice')
        self._check_root_identity()
        if not self.writable:
            self._applied = True
            return
        validate_workspace_delta(self.upper)
        for history in self.git_histories.values():
            history.prepare()
        changes = []
        directories = []
        for root, dirs, files in os.walk(self.upper):
            for name in dirs:
                directories.append((Path(root) / name).relative_to(self.upper).as_posix())
            for name in files:
                relative = (Path(root) / name).relative_to(self.upper).as_posix()
                target = Path(self._root_path) / relative
                expected = self.baseline.get(relative)
                if expected is None:
                    if os.path.lexists(target):
                        raise UnsafeWorkspaceDelta('New workspace destination already exists')
                else:
                    expected = _fingerprint(target, expected_signature=expected)
                changes.append((relative, expected))
        self._journal(changes)
        self._started = True
        try:
            for history in self.git_histories.values():
                history.guard_publication()
            # Descriptor traversal prevents symlink parents from redirecting edits.
            for relative in sorted(directories, key=lambda path: len(path.split('/'))):
                descriptor = os.open(self._root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    for part in relative.split('/'):
                        try:
                            os.mkdir(part, 0o755, dir_fd=descriptor)
                        except FileExistsError:
                            pass
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                        os.fsync(descriptor)
                        os.close(descriptor)
                        descriptor = child
                finally:
                    os.close(descriptor)
            for relative, expected in changes:
                publish_workspace_file(self._root_path, relative, self.upper / relative, expected_sha256=expected)
            for history in self.git_histories.values():
                history.publish()
            for history in self.git_histories.values():
                history.finish()
            self._pending.unlink()
            self._sync_state()
            self._applied = True
        except BaseException as error:
            raise ResourceCleanupError('Workspace publication interrupted; owner recovery required') from error

    def _restore_cleanup_access(self):
        # The job envelope must be quiescent before close. Operate only through
        # pinned directory descriptors; never chmod a staged symlink target.
        remaining = 1_000_000
        deadline = time.monotonic() + 30
        def restore(descriptor, depth):
            nonlocal remaining
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or depth > 128:
                raise ResourceCleanupError('Private directory cleanup requires owner inspection')
            os.chmod(f'/proc/self/fd/{descriptor}', 0o700)
            readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                with os.scandir(readable) as entries:
                    for entry in entries:
                        remaining -= 1
                        if remaining < 0 or time.monotonic() >= deadline:
                            raise ResourceCleanupError('Private directory cleanup exceeds scan budget')
                        if entry.is_dir(follow_symlinks=False):
                            child = os.open(entry.name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=readable)
                            try:
                                restore(child, depth + 1)
                            finally:
                                os.close(child)
            finally:
                os.close(readable)
        descriptor = os.open(self.directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            restore(descriptor, 0)
        finally:
            os.close(descriptor)

    def close(self):
        if self._closed:
            return
        if self._started and not self._applied:
            raise ResourceCleanupError('Workspace publication recovery guard must remain held')
        for history in self.git_histories.values():
            history.close()
        try:
            self._restore_cleanup_access()
            shutil.rmtree(self.directory)
        except ResourceCleanupError:
            raise
        except Exception as error:
            raise ResourceCleanupError('Private workspace cleanup remains unverified') from error
        if self._publication_fd is not None:
            os.close(self._publication_fd)
        if self._projection_fd is not None:
            os.close(self._projection_fd)
        os.close(self._root_fd)
        os.close(self._lock)
        self._closed = True
