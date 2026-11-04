"""Bounded, descriptor-based reads and traversal for untrusted workspaces."""
import os
import fcntl
from contextlib import contextmanager
import logging
import stat
import selectors
import signal
import shutil
import subprocess
import time
from pathlib import Path

from agentporter.workspaces.paths import validate_workspace_path

MAX_SCAN_ENTRIES = 5000
MAX_SCAN_DEPTH = 16
logger = logging.getLogger(__name__)


def capture_bounded(command, limit=512 * 1024, timeout=10, *, workspace_fd=None, workspace_relative=False):
    inherited = ()
    child_cwd = None
    if type(workspace_relative) is not bool or workspace_relative and workspace_fd is None:
        raise ValueError('Relative search requires a pinned workspace descriptor')
    if workspace_fd is not None:
        if (type(workspace_fd) is not int or workspace_fd < 0
                or not stat.S_ISDIR(os.fstat(workspace_fd).st_mode)
                or fcntl.fcntl(workspace_fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH)
                or not command or command[0] != 'rg'
                or command[-1] != f'/proc/self/fd/{workspace_fd}/.'):
            raise ValueError('Invalid pinned workspace search descriptor')
        inherited = (workspace_fd,)
        if workspace_relative:
            # Slash-containing globs are anchored to the search root. Keep the
            # child cwd on the exact held view and give rg a relative root.
            child_cwd = command[-1]
            # Resolve the host executable before changing the child cwd; a
            # relative PATH entry must never select an executable in workspace.
            executable = shutil.which(command[0])
            if executable is None:
                raise FileNotFoundError('ripgrep is unavailable')
            command = [os.path.abspath(executable), *command[1:-1], '.']
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            process_group=0, pass_fds=inherited, cwd=child_cwd)
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((proc.stdout, proc.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Search exceeded time budget')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        if sum(map(len, output)) + len(chunk) > limit:
                            raise ValueError('Search exceeded output budget')
                        output[key.data].extend(chunk)
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, *(item.decode('utf-8', errors='replace') for item in output)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)
        proc.stdout.close()
        proc.stderr.close()


@contextmanager
def read_workspace_root(root):
    """Pin canonical authority, use only its verified read-only lower for foreign UID."""
    canonical = Path(root).resolve(strict=True)
    source = os.open(canonical, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    view = None
    try:
        identity = os.fstat(source)
        named = canonical.stat()
        if not stat.S_ISDIR(identity.st_mode) or (identity.st_dev, identity.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError('Workspace root changed before read')
        if identity.st_uid != os.getuid():
            from agentporter.sandbox.workspace_projections import open_workspace_projection
            view = open_workspace_projection(source)
        else:
            view = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source)
        yield view
    finally:
        if view is not None:
            os.close(view)
        os.close(source)


def _directory_at(root_fd, parts):
    directory = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        result, directory = directory, None
        return result
    finally:
        if directory is not None:
            os.close(directory)


def _read_regular_at(root_fd, path, limit):
    """Internal pinned-root read; callers validate the canonical relative path."""
    relative = Path(os.path.normpath(path))
    directory = _directory_at(root_fd, relative.parts[:-1])
    file = None
    try:
        file = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(file)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Read requires a regular file with no hardlink aliases')
        if before.st_size > limit:
            raise ValueError(f'File exceeds bounded read/hash budget of {limit} bytes')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(file, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(file)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(data) > limit or len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError('File changed or exceeded read budget')
        return bytes(data)
    finally:
        if file is not None:
            os.close(file)
        os.close(directory)


def read_regular(root, path, limit):
    validate_workspace_path(root, path)
    # Keep original components: resolving a symlink must not erase NOFOLLOW.
    with read_workspace_root(root) as root_fd:
        return _read_regular_at(root_fd, path, limit)


def walk_files(root, path='', depth=1, *, skip_hidden=True):
    """Do not materialize directory listings or follow directory symlinks."""
    if depth is None:
        depth = MAX_SCAN_DEPTH
    if type(depth) is not int or not 0 <= depth <= MAX_SCAN_DEPTH:
        raise ValueError(f'Traversal depth must be between 0 and {MAX_SCAN_DEPTH}')
    validate_workspace_path(root, path, allow_root=True)
    relative_start = Path(os.path.normpath(path or '.'))
    visited = 0
    def scan(fd, prefix, level):
        nonlocal visited
        with os.scandir(fd) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_SCAN_ENTRIES:
                    raise ValueError('Directory traversal exceeds entry budget')
                if entry.is_symlink() or (skip_hidden and entry.name.startswith('.')):
                    continue
                relative = str(Path(prefix) / entry.name)
                try:
                    validate_workspace_path(root, relative)
                except ValueError:
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if level < depth and entry.name not in {'__pycache__', 'node_modules', 'venv', '.venv'}:
                        try:
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        except PermissionError:
                            logger.warning('Skipping unreadable workspace directory: %s', relative)
                            continue
                        try:
                            yield from scan(child, relative, level + 1)
                        finally:
                            os.close(child)
                elif entry.is_file(follow_symlinks=False):
                    yield relative
    with read_workspace_root(root) as root_fd:
        directory = _directory_at(root_fd, relative_start.parts)
        try:
            prefix = str(relative_start)
            yield from scan(directory, '' if prefix == '.' else prefix, 0)
        finally:
            os.close(directory)
