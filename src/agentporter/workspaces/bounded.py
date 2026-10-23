"""Bounded, descriptor-based reads and traversal for untrusted workspaces."""
import os
import logging
import stat
import selectors
import signal
import subprocess
import time
from pathlib import Path

from agentporter.workspaces.paths import validate_workspace_path

MAX_SCAN_ENTRIES = 5000
MAX_SCAN_DEPTH = 16
logger = logging.getLogger(__name__)


def capture_bounded(command, limit=512 * 1024, timeout=10):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, process_group=0)
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


def read_regular(root, path, limit):
    target = validate_workspace_path(root, path)
    relative = Path(target).relative_to(Path(root).resolve())
    directory = os.open(Path(root).resolve(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    file = None
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        file = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
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


def walk_files(root, path='', depth=1, *, skip_hidden=True):
    """Do not materialize directory listings or follow directory symlinks."""
    if depth is None:
        depth = MAX_SCAN_DEPTH
    if type(depth) is not int or not 0 <= depth <= MAX_SCAN_DEPTH:
        raise ValueError(f'Traversal depth must be between 0 and {MAX_SCAN_DEPTH}')
    start = validate_workspace_path(root, path, allow_root=True)
    root_fd = os.open(start, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
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
    try:
        prefix = os.path.relpath(start, Path(root).resolve())
        yield from scan(root_fd, '' if prefix == '.' else prefix, 0)
    finally:
        os.close(root_fd)
