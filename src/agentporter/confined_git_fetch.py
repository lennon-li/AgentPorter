"""Fixed-purpose public HTTPS Git fetch; workspace configuration is data only.

No original repository Git command is ever executed. Pack validation and network
access use a freshly initialized private bare repository inside Bubblewrap.
"""
from __future__ import annotations

import configparser
import ctypes
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shutil
import stat
import socket
import threading
import contextlib
import subprocess
import tempfile
from contextlib import ExitStack
from urllib.parse import urlsplit

from agentporter.scoped_https import _resolve_public_addresses
from agentporter.agents.development_egress import PublicEgress, _read_connect, _relay
from agentporter.agents import development_egress

_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
_PACK = re.compile(r'pack-[0-9a-f]{40}\.(pack|idx)\Z')
_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
        'GIT_ASKPASS': '/bin/false', 'GIT_ALLOW_PROTOCOL': 'https',
        'GIT_CONFIG_COUNT': '0', 'GIT_EXEC_PATH': '/usr/lib/git-core'}


def _directory(path=None, *, parent=None, name=None):
    fd = os.open(path if parent is None else name,
                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    value = os.fstat(fd)
    if value.st_uid != os.getuid() or value.st_mode & 0o002:
        os.close(fd)
        raise PermissionError('Unsafe metadata owner or permissions')
    return fd


def _read(fd, name, limit):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(child)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > limit:
            raise PermissionError('Unsafe metadata file')
        value = os.read(child, limit + 1)
        if len(value) > limit:
            raise PermissionError('Oversized metadata')
        return value
    finally:
        os.close(child)


def _url(config, remote):
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    parser.read_string(config.decode('utf-8', errors='strict'))
    if parser.has_section('extensions') or parser.get('core', 'repositoryformatversion', fallback='0') != '0':
        raise PermissionError('Unsupported Git storage format')
    value = parser.get(f'remote "{remote}"', 'url', raw=True)
    if len(value) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise PermissionError('Invalid remote URL')
    parts = urlsplit(value)
    if parts.username is not None or parts.password is not None:
        raise AuthenticationUnavailable()
    host = parts.hostname
    if (parts.scheme != 'https' or not host or parts.port not in (None, 443)
            or parts.query or parts.fragment or '\\' in value
            or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host)
            or '.' not in host or host.endswith('.')):
        raise PermissionError('Public HTTPS remote required')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PermissionError('DNS hostname required')
    return value, host.lower()


class AuthenticationUnavailable(Exception):
    """Owner credentials are deliberately unavailable to fetch."""



def _connect_pinned(address):
    connection = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(10)
        connection.connect((address, 443))
        return connection
    except BaseException:
        connection.close()
        raise


class OriginEgress(PublicEgress):
    """CONNECT only to one prevalidated numeric destination; no second DNS lookup."""

    def __init__(self, socket_path, host, address):
        super().__init__(socket_path)
        self.host = host
        self.address = address

    def _handle(self, client):
        upstream = None
        connected = False
        try:
            host, remainder = _read_connect(client)
            if host.lower() != self.host:
                raise PermissionError('Alternate origin forbidden')
            upstream = _connect_pinned(self.address)
            with self._lock:
                if self._stop.is_set():
                    return
                self._connections.add(upstream)
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            connected = True
            if remainder:
                upstream.sendall(remainder)
            _relay(client, upstream, self._stop)
        except (ValueError, PermissionError, OSError):
            if not connected:
                with contextlib.suppress(OSError):
                    client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        finally:
            with self._lock:
                self._connections.discard(client)
                self._connections.discard(upstream)
                self._threads.discard(threading.current_thread())
            client.close()
            if upstream is not None:
                upstream.close()
            self._slots.release()

def _sandbox(bare, shared_net):
    cmd = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-all']
    # No host networking: all HTTP must traverse the exact-origin Unix proxy.
    for path in ('/usr', '/lib', '/lib64', '/bin', '/etc/ssl/certs'):
        if Path(path).exists():
            cmd += ['--ro-bind', path, path]
    cmd += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--dir', '/work', '--bind', str(bare), '/work/repo',
            '--chdir', '/work/repo', '--clearenv']
    for key, value in _ENV.items():
        cmd += ['--setenv', key, value]
    return cmd


def _run(bare, args, *, timeout_seconds, max_pack_bytes, resources=None, network=False, origin=None):
    # The small fixed runner sets hard limits without preexec_fn in a threaded server.
    runner = Path(__file__).with_name('git_fetch_runner.py').read_bytes()
    runner_path = bare / 'runner.py'
    runner_path.write_bytes(runner)
    (bare / 'egress.py').write_bytes(Path(development_egress.__file__).read_bytes())
    command = _sandbox(bare, network) + [
        '/usr/bin/python3', '-I', '/work/repo/runner.py', str(max_pack_bytes),
        *(['--proxy'] if network else []), '/usr/bin/git', '--git-dir=/work/repo', '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.fsmonitor=false', '-c', 'credential.helper=',
        '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
        '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false',
        '-c', 'http.extraHeader=', '-c', 'fetch.uriprotocols=', *args]
    lease = resources.create() if resources is not None else None
    try:
        proxy = OriginEgress(bare / 'egress.sock', *origin) if network else contextlib.nullcontext()
        with proxy, tempfile.TemporaryFile(dir=bare) as output:
            result = subprocess.run(lease.command(command) if lease else command,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                env=_ENV, timeout=timeout_seconds, start_new_session=True)
            if result.returncode:
                raise AuthenticationUnavailable() if network else PermissionError('Validation failed')
            output.seek(0)
            value = output.read(min(max_pack_bytes, 1024 * 1024) + 1)
            if len(value) > min(max_pack_bytes, 1024 * 1024):
                raise PermissionError('Output limit exceeded')
            return value
    finally:
        if lease is not None:
            lease.close()


def _transport(bare, url, host, address, **limits):
    address = f'[{address}]' if ':' in address else address
    _run(bare, ['-c', f'http.curloptResolve={host}:443:{address}',
        '-c', 'fetch.fsckObjects=true', '-c', 'transfer.fsckObjects=true',
        'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--no-recurse-submodules',
        '--keep', '--', url, '+refs/heads/*:refs/heads/*'], network=True, origin=(host, address.strip('[]')), **limits)


def _exchange(fd, left, right):
    # Linux renameat2 guarantees readers see either complete remote ref directory.
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as error:
        raise PermissionError('Atomic remote ref exchange unavailable') from error
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(fd, os.fsencode(left), fd, os.fsencode(right), 2):
        raise OSError(ctypes.get_errno(), 'Atomic remote ref exchange failed')


def _validate_ref(name):
    if (len(name) > 512 or not name.startswith('refs/heads/') or name.endswith('.')
            or '..' in name or '@{' in name or '\\' in name
            or any(ord(c) < 33 or ord(c) > 126 or c in '~^:?*[' for c in name)):
        raise PermissionError('Invalid reference')
    components = name.split('/')[2:]
    if not components or any(not c or c.startswith('.') or c.endswith('.lock') for c in components):
        raise PermissionError('Invalid reference path')
    return components


def _check_tree(fd, *, budget):
    if os.fstat(fd).st_mode & 0o700 != 0o700:
        raise PermissionError('Remote refs must permit owner traversal and cleanup')
    for name in os.listdir(fd):
        budget[0] -= 1
        if budget[0] < 0:
            raise PermissionError('Too many metadata entries')
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
            raise PermissionError('Unsafe remote metadata')
        if stat.S_ISDIR(info.st_mode):
            child = _directory(parent=fd, name=name)
            try:
                _check_tree(child, budget=budget)
            finally:
                os.close(child)
        elif not stat.S_ISREG(info.st_mode):
            raise PermissionError('Unsafe remote metadata')


def _publish(packfd, remotesfd, remote, bare, refs, max_pack_bytes):
    files = []
    total = 0
    for path in sorted((bare / 'objects/pack').iterdir()):
        if path.suffix in {'.keep', '.bitmap', '.rev'}:
            continue
        if not _PACK.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            raise PermissionError('Unexpected pack metadata')
        total += path.stat().st_size
        if total > max_pack_bytes:
            raise PermissionError('Pack byte limit exceeded')
        data = path.read_bytes()
        files.append((path.name, data))
    if {n[:-5] for n, _ in files if n.endswith('.pack')} != {n[:-4] for n, _ in files if n.endswith('.idx')}:
        raise PermissionError('Unpaired pack/index')
    stage = '.fetch-' + os.urandom(16).hex()
    os.mkdir(stage, mode=0o700, dir_fd=remotesfd)
    stagefd = _directory(parent=remotesfd, name=stage)
    created = []
    try:
        for name, oid in refs:
            parts = _validate_ref(name)
            with ExitStack() as stack:
                current = stagefd
                for component in parts[:-1]:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    current = _directory(parent=current, name=component)
                    stack.callback(os.close, current)
                out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=current)
                with os.fdopen(out, 'wb') as stream:
                    stream.write(oid.encode('ascii') + b'\n')
                    stream.flush()
                    os.fsync(stream.fileno())
        for name, data in files:
            try:
                existing = _read(packfd, name, max_pack_bytes)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing != data:
                    raise PermissionError('Conflicting existing pack')
                continue
            temporary = '.fetch-' + os.urandom(16).hex()
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=packfd)
            try:
                with os.fdopen(out, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(temporary, name, src_dir_fd=packfd, dst_dir_fd=packfd, follow_symlinks=False)
                created.append(name)
            finally:
                os.unlink(temporary, dir_fd=packfd)
        try:
            previous = _directory(parent=remotesfd, name=remote)
        except FileNotFoundError:
            os.rename(stage, remote, src_dir_fd=remotesfd, dst_dir_fd=remotesfd)
        else:
            try:
                _check_tree(previous, budget=[10000])
            finally:
                os.close(previous)
            _exchange(remotesfd, stage, remote)
        return total
    except BaseException:
        for name in created:
            os.unlink(name, dir_fd=packfd)
        raise
    finally:
        os.close(stagefd)
        # The descriptor-relative rmtree implementation never follows symlinks.
        if stage in os.listdir(remotesfd):
            shutil.rmtree(stage, dir_fd=remotesfd)


def fetch_repository(workspace_root, remote='origin', *, state_dir, resources=None,
                     timeout_seconds=60, max_pack_bytes=128 * 1024 * 1024, max_refs=4096):
    """Return bounded, URL-free status; never expose transport errors or credentials."""
    if (not isinstance(remote, str) or not _NAME.fullmatch(remote)
            or type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 300
            or type(max_pack_bytes) is not int or not 1024 <= max_pack_bytes <= 512 * 1024**2
            or type(max_refs) is not int or not 1 <= max_refs <= 10000):
        return {'status': 'denied'}
    try:
        state = Path(state_dir)
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with ExitStack() as stack:
            statefd = _directory(state); stack.callback(os.close, statefd)
            if os.fstat(statefd).st_mode & 0o077:
                raise PermissionError('Private fetch state required')
            rootfd = _directory(workspace_root); stack.callback(os.close, rootfd)
            gitfd = _directory(parent=rootfd, name='.git'); stack.callback(os.close, gitfd)
            objects = _directory(parent=gitfd, name='objects'); stack.callback(os.close, objects)
            packfd = _directory(parent=objects, name='pack'); stack.callback(os.close, packfd)
            refsfd = _directory(parent=gitfd, name='refs'); stack.callback(os.close, refsfd)
            # Create this only after all network/validation work succeeds.
            url, host = _url(_read(gitfd, 'config', 65536), remote)
            addresses = _resolve_public_addresses(host)
            address = addresses[0][4][0]
            repo_id = hashlib.sha256(f'{os.fstat(gitfd).st_dev}:{os.fstat(gitfd).st_ino}'.encode()).hexdigest()[:24]
            lockfd = os.open(repo_id + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=statefd)
            stack.callback(os.close, lockfd)
            lockinfo = os.fstat(lockfd)
            if not stat.S_ISREG(lockinfo.st_mode) or lockinfo.st_uid != os.getuid() or lockinfo.st_mode & 0o077:
                raise PermissionError('Unsafe lease')
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with tempfile.TemporaryDirectory(prefix='git-fetch-', dir=state) as directory:
                bare = Path(directory)
                (bare / 'objects/pack').mkdir(parents=True)
                (bare / 'refs/heads').mkdir(parents=True)
                (bare / 'HEAD').write_text('ref: refs/heads/main\n')
                (bare / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n')
                limits = dict(timeout_seconds=timeout_seconds, max_pack_bytes=max_pack_bytes, resources=resources)
                _transport(bare, url, host, address, **limits)
                if sum(p.stat().st_size for p in (bare / 'objects/pack').iterdir()) > max_pack_bytes:
                    raise PermissionError('Pack byte limit exceeded')
                _run(bare, ['fsck', '--strict', '--no-reflogs', '--no-dangling'], **limits)
                output = _run(bare, ['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads/'], **limits)
                refs = []
                for line in output.decode('ascii').splitlines():
                    name, oid = line.split(' ')
                    _validate_ref(name)
                    if not re.fullmatch('[0-9a-f]{40}', oid) or len(refs) >= max_refs:
                        raise PermissionError('Invalid or excessive refs')
                    refs.append((name, oid))
                created_remotes = False
                try:
                    remotesfd = _directory(parent=refsfd, name='remotes')
                except FileNotFoundError:
                    os.mkdir('remotes', mode=0o700, dir_fd=refsfd)
                    created_remotes = True
                    remotesfd = _directory(parent=refsfd, name='remotes')
                stack.callback(os.close, remotesfd)
                try:
                    size = _publish(packfd, remotesfd, remote, bare, refs, max_pack_bytes)
                except BaseException:
                    if created_remotes:
                        os.rmdir('remotes', dir_fd=refsfd)
                    raise
                return {'status': 'ok', 'repository_id': repo_id, 'refs': len(refs), 'pack_bytes': size}
    except AuthenticationUnavailable:
        return {'status': 'authunavailable'}
    except (TimeoutError, subprocess.TimeoutExpired):
        return {'status': 'timeout'}
    except (OSError, ValueError, PermissionError, configparser.Error, UnicodeError, RecursionError):
        return {'status': 'denied'}
