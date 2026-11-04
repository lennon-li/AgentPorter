"""Per-job Unix-socket transport for ``WorkerGitChannel`` plus a bounded client.

Importing this module starts nothing. A trusted service creates one
``WorkerGitSocket(rpc, job_id, directory)`` per live job. The channel is taken
from the service's own ``rpc.channel(job_id)`` (the pre-issued grant), so a
connection never chooses a job or any authority. The socket lives in a private
directory that only this job's launch mounts, as ``/run/agentporter-git.sock``.
It never listens on TCP and never exposes another job's channel.
"""
from __future__ import annotations

import ctypes
import json
import os
import socket
import stat
import struct
import threading
import time

from agentporter.worker_git_rpc import MAX_FRAME, VERSION, WorkerGitChannel, WorkerGitRPC

SOCKET_NAME = 'agentporter-git.sock'
CONTAINER_PATH = '/run/agentporter-git.sock'
MAX_RESPONSE = 1048576
MAX_CONNECTIONS = 2
MAX_FRAMES_PER_CONNECTION = 16
IO_TIMEOUT = 5.0
CONNECTION_TIMEOUT = 300.0
CLIENT_TIMEOUT = 300.0
POLL = 0.2
_DIRECT_PATH_LIMIT = 100
CUSTODY_NAME = '.custody'
_RENAME_NOREPLACE = 1
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class WorkerGitTransportError(Exception):
    pass


def _open_pinned(path):
    """Open an absolute directory component by component without following symlinks."""
    if not isinstance(path, str) or not path.startswith('/') or '\0' in path:
        raise WorkerGitTransportError('Socket directory must be an absolute path')
    parts = [p for p in path.split('/') if p]
    if '..' in parts or '.' in parts:
        raise WorkerGitTransportError('Socket directory must be canonical')
    fd = os.open('/', _DIR_FLAGS)
    try:
        for part in parts:
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as error:
                raise WorkerGitTransportError('Socket directory is unavailable') from error
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _alias(fd):
    # Reaches the pinned directory without a global chdir; keeps sun_path short.
    return f'/proc/self/fd/{fd}/{SOCKET_NAME}'


def _identity(info):
    return info.st_dev, info.st_ino


def _renameat2_noreplace(old_fd, old, new_fd, new):
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as error:
        raise WorkerGitTransportError('Atomic create-only rename is unavailable') from error
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(old_fd, os.fsencode(old), new_fd, os.fsencode(new), _RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _open_custody(fd):
    """Service-private custody inside the already 0700 pinned directory (same mount)."""
    try:
        os.mkdir(CUSTODY_NAME, 0o700, dir_fd=fd)
    except FileExistsError:
        pass
    custody = os.open(CUSTODY_NAME, _DIR_FLAGS, dir_fd=fd)
    try:
        info = os.fstat(custody)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise WorkerGitTransportError('Socket custody must be private and owned by the service')
        return custody
    except BaseException:
        os.close(custody)
        raise


def _retire_socket(fd, expected, hook=None):
    """Remove ``SOCKET_NAME`` only if it is the ``expected`` socket inode.

    The pathname is never unlinked directly. The entry is atomically moved
    (create-only) into private custody, its real identity is checked there, and
    only then is the custody name unlinked. A different entry is moved back
    create-only, or left retained in custody if the name was taken again.
    Returns True when ours was retired.
    """
    custody = _open_custody(fd)
    try:
        if hook is not None:
            hook()
        held = f'{os.getpid()}-{time.monotonic_ns()}-{os.urandom(4).hex()}'
        try:
            _renameat2_noreplace(fd, SOCKET_NAME, custody, held)
        except FileNotFoundError:
            return False
        info = os.stat(held, dir_fd=custody, follow_symlinks=False)
        if stat.S_ISSOCK(info.st_mode) and _identity(info) == expected:
            os.unlink(held, dir_fd=custody)
            return True
        try:
            _renameat2_noreplace(custody, held, fd, SOCKET_NAME)
        except OSError:
            pass
        return False
    finally:
        os.close(custody)


class WorkerGitSocket:
    """One listening socket serving exactly one job's channel."""

    def __init__(self, rpc: WorkerGitRPC, job_id: str, directory: str, *,
                 max_connections: int = MAX_CONNECTIONS, io_timeout: float = IO_TIMEOUT,
                 connection_timeout: float = CONNECTION_TIMEOUT,
                 max_frames: int = MAX_FRAMES_PER_CONNECTION, on_close=None):
        if not isinstance(rpc, WorkerGitRPC):
            raise TypeError('A trusted WorkerGitRPC is required')
        if (type(max_connections) is not int or not 1 <= max_connections <= 8
                or not 0 < io_timeout <= 60 or not 0 < connection_timeout <= 3600
                or type(max_frames) is not int or not 1 <= max_frames <= 256):
            raise ValueError('Invalid transport bounds')
        self._channel: WorkerGitChannel = rpc.channel(job_id)
        self._directory = directory
        self._max_connections = max_connections
        self._io_timeout = io_timeout
        self._connection_timeout = connection_timeout
        self._max_frames = max_frames
        self._on_close = on_close
        self._slots = threading.BoundedSemaphore(max_connections)
        self._serial = threading.Lock()
        self._state = threading.Lock()
        self._conns: set = set()
        self._threads: set = set()
        self._dir_fd = None
        self._listener = None
        self._identity = None
        self._accept_thread = None
        self._closed = False
        self._started = False

    _pre_retire_hook = None  # test seam: runs after the last check, before retirement

    @property
    def job_id(self):
        return self._channel.job_id

    @property
    def host_path(self):
        """Host path of the socket; mount only into this job as ``CONTAINER_PATH``."""
        return os.path.join(self._directory, SOCKET_NAME)

    @property
    def container_path(self):
        return CONTAINER_PATH

    @property
    def running(self):
        return self._started and not self._closed

    def start(self):
        with self._state:
            if self._started:
                raise WorkerGitTransportError('Transport already started')
            self._started = True
        try:
            self._bind()
        except BaseException:
            self._teardown()
            raise
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True,
                                               name='agentporter-git-accept')
        self._accept_thread.start()
        return self

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    def _bind(self):
        if not self._channel.active():
            raise WorkerGitTransportError('Job is not live')
        fd = _open_pinned(self._directory)
        self._dir_fd = fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise WorkerGitTransportError('Socket directory must be private and owned by the service')
        self._clear_stale(fd)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        listener.bind(_alias(fd))
        # The directory is already 0700, so the brief umask-mode window is unreachable.
        os.chmod(_alias(fd), 0o600)
        made = os.stat(SOCKET_NAME, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISSOCK(made.st_mode) or made.st_uid != os.geteuid() or stat.S_IMODE(made.st_mode) != 0o600:
            raise WorkerGitTransportError('Socket was not created privately')
        self._identity = _identity(made)
        listener.listen(self._max_connections)
        listener.settimeout(POLL)

    def _clear_stale(self, fd):
        try:
            existing = os.stat(SOCKET_NAME, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(existing.st_mode):
            raise WorkerGitTransportError('Refusing to replace a non-socket path')
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1.0)
        try:
            probe.connect(_alias(fd))
        except (ConnectionRefusedError, FileNotFoundError):
            try:
                retired = _retire_socket(fd, _identity(existing), self._pre_retire_hook)
            except OSError as error:
                raise WorkerGitTransportError('Cannot retire stale socket') from error
            if not retired:
                raise WorkerGitTransportError('Socket path changed during stale check')
            return
        except OSError as error:
            raise WorkerGitTransportError('Cannot prove socket is stale') from error
        finally:
            probe.close()
        raise WorkerGitTransportError('Another live owner holds this socket')

    def _accept_loop(self):
        while not self._closed:
            if not self._channel.active():
                break
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                conn.close()
                continue
            with self._state:
                if self._closed:
                    self._slots.release()
                    conn.close()
                    break
                self._conns.add(conn)
                thread = threading.Thread(target=self._serve, args=(conn,), daemon=True,
                                          name='agentporter-git-conn')
                self._threads.add(thread)
            thread.start()
        if not self._closed:
            threading.Thread(target=self.close, daemon=True).start()

    def _serve(self, conn):
        try:
            deadline = time.monotonic() + self._connection_timeout
            for _ in range(self._max_frames):
                if self._closed or not self._channel.active():
                    return
                try:
                    header = _recv_frame_header(conn, self._io_timeout, deadline)
                except (EOFError, OSError, TimeoutError, socket.timeout):
                    return
                if header is None:
                    return
                if header > MAX_FRAME:
                    _send(conn, self._denied('invalid_request'), self._io_timeout)
                    return
                try:
                    raw = _recv_exact(conn, header, self._io_timeout, deadline)
                except (EOFError, OSError, TimeoutError, socket.timeout):
                    return
                with self._serial:
                    body = self._channel.handle_bytes(raw)
                if len(body) > MAX_RESPONSE:
                    body = self._denied('response_too_large')
                _send(conn, body, self._io_timeout)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._state:
                self._conns.discard(conn)
                self._threads.discard(threading.current_thread())
            self._slots.release()

    @staticmethod
    def _denied(code):
        return json.dumps({'version': VERSION, 'ok': False, 'status': 'denied', 'code': code},
                          sort_keys=True, separators=(',', ':')).encode()

    def close(self):
        with self._state:
            if self._closed:
                return
            self._closed = True
            conns = list(self._conns)
            threads = list(self._threads)
        self._teardown(conns)
        current = threading.current_thread()
        for thread in [self._accept_thread, *threads]:
            if thread is not None and thread is not current and thread.is_alive():
                thread.join(1.0)
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception:
                pass

    def _teardown(self, conns=()):
        self._closed = True
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        fd, self._dir_fd = self._dir_fd, None
        if fd is not None:
            try:
                # Retire only the exact inode we created, via private custody; a
                # later owner's replacement is restored or retained, never unlinked.
                if self._identity is not None:
                    try:
                        _retire_socket(fd, self._identity, self._pre_retire_hook)
                    except (OSError, WorkerGitTransportError):
                        pass
            finally:
                os.close(fd)


def _recv_exact(conn, size, io_timeout, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('connection deadline')
        conn.settimeout(min(io_timeout, remaining))
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError('short frame')
        data += chunk
    return bytes(data)


def _recv_frame_header(conn, io_timeout, deadline):
    """Return the next frame size, or None on a clean close between frames."""
    first = bytearray()
    while len(first) < 4:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('connection deadline')
        conn.settimeout(min(io_timeout, remaining))
        chunk = conn.recv(4 - len(first))
        if not chunk:
            if not first:
                return None
            raise EOFError('short header')
        first += chunk
    return struct.unpack('>I', bytes(first))[0]


def _send(conn, body, io_timeout):
    conn.settimeout(io_timeout)
    conn.sendall(struct.pack('>I', len(body)) + body)


class WorkerGitClient:
    """Small bounded client for the worker side (or tests)."""

    def __init__(self, path, *, timeout=CLIENT_TIMEOUT, max_response=MAX_RESPONSE):
        if not isinstance(path, str) or not path.startswith('/') or not 0 < timeout <= 3600:
            raise ValueError('Invalid client settings')
        self._path = path
        self._timeout = timeout
        self._max_response = min(max_response, MAX_RESPONSE)

    def request(self, payload) -> dict:
        body = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(body) > MAX_FRAME:
            raise WorkerGitTransportError('Request too large')
        deadline = time.monotonic() + self._timeout
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        dir_fd = None
        try:
            conn.settimeout(min(self._timeout, 10.0))
            target = self._path
            if len(target.encode()) > _DIRECT_PATH_LIMIT:
                directory, name = os.path.split(target)
                dir_fd = _open_pinned(directory)
                target = f'/proc/self/fd/{dir_fd}/{name}'
            conn.connect(target)
            conn.sendall(struct.pack('>I', len(body)) + body)
            (size,) = struct.unpack('>I', _recv_exact(conn, 4, self._timeout, deadline))
            if size > self._max_response:
                raise WorkerGitTransportError('Response too large')
            data = _recv_exact(conn, size, self._timeout, deadline)
        except (OSError, EOFError, TimeoutError) as error:
            raise WorkerGitTransportError('Git transport unavailable') from error
        finally:
            conn.close()
            if dir_fd is not None:
                os.close(dir_fd)
        try:
            result = json.loads(data)
        except ValueError as error:
            raise WorkerGitTransportError('Invalid response') from error
        if not isinstance(result, dict):
            raise WorkerGitTransportError('Invalid response')
        return result
