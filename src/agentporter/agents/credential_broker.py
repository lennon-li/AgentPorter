"""Owner-side native authentication custody for isolated BCC workers.

Canonical auth stays in its native account. BCC uses access-only issuance:
workers never receive refresh tokens or write authentication back. Renewal is
requested from the already-running native daemon. Exclusive lease support is
opt-in and requires enrollment of every native launcher. The broker socket is
never mounted into a child. Credentials and account IDs are never logged.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import threading
import time
import uuid

from agentporter.agents.credential_lease import CredentialLease, _read, _document

_LIMIT = 2 * 1024 * 1024
# Pinned Codex 0.167.2 renews managed access credentials five minutes early.
# Cover a full worker job plus that window, with time for launch preparation.
_MAX_JOB_SECONDS = 900
_NATIVE_RENEWAL_WINDOW = 300
_MIN_ACCESS_LIFETIME = _MAX_JOB_SECONDS + _NATIVE_RENEWAL_WINDOW
_ISSUE_ACCESS_LIFETIME = _MIN_ACCESS_LIFETIME + 60
_ACCOUNT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate protocol field')
        result[key] = value
    return result


def _receive(channel):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = channel.recv(size-len(data))
            if not part:
                raise EOFError('Credential channel disconnected; recovery required')
            data.extend(part)
        return bytes(data)
    size, = struct.unpack('>I', exact(4))
    if not 0 < size <= _LIMIT:
        raise ValueError('Credential frame exceeds its bound')
    value = json.loads(exact(size), object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite field')))
    if not isinstance(value, dict):
        raise ValueError('Credential frame must be an object')
    return value


def _send(channel, data):
    raw = json.dumps(data, allow_nan=False, separators=(',', ':')).encode()
    if not 0 < len(raw) <= _LIMIT:
        raise ValueError('Credential frame exceeds its bound')
    channel.sendall(struct.pack('>I', len(raw))+raw)


def _peer_uid(channel):
    return struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _oauth_document(raw, expected=None):
    data = _document(raw)
    if (data.get('auth_mode') not in (None, 'chatgpt') or data.get('OPENAI_API_KEY')
            or not isinstance(data.get('tokens'), dict)
            or not isinstance(data['tokens'].get('account_id'), str)
            or not data['tokens']['account_id']):
        raise PermissionError('Canonical broker requires an existing identified ChatGPT OAuth account')
    if expected is not None and data['tokens']['account_id'] != expected:
        raise PermissionError('Canonical account binding changed; owner enrollment required')
    return data


def _access_expiry(data):
    try:
        encoded = data['tokens']['access_token'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
        expiry = claims['exp']
        if type(expiry) not in (int, float) or not 0 < expiry < 1e12:
            raise ValueError()
        return expiry
    except (KeyError, IndexError, TypeError, ValueError):
        raise PermissionError('Native access credential has no bounded expiry') from None


def _read_native(source, expected):
    _owner_directory(source.parent)
    parent = os.open(source.parent, _DIR)
    try:
        return _oauth_document(_read(parent, source.name), expected)
    finally:
        os.close(parent)


def _read_private_document(source, *, jsonc=False):
    source=Path(source)
    _owner_directory(source.parent)
    parent=os.open(source.parent,_DIR)
    try:
        raw=_read(parent,source.name)
    finally:
        os.close(parent)
    if jsonc:
        text='\n'.join(line for line in raw.decode().splitlines() if not line.lstrip().startswith('//'))
        raw=re.sub(r',\s*([}\]])',r'\1',text).encode()
    return _document(raw)


def _copilot_access_document(data, expected=None):
    """Validate Copilot account aliases and return one bounded auth document."""
    def aliases(names):
        return [(name, data[name]) for name in names if name in data]

    def identity(value):
        if not isinstance(value, dict):
            raise PermissionError('Malformed Copilot account identity')
        login, host = value.get('login'), value.get('host')
        if (not isinstance(login, str) or not login or len(login) > 256
                or not isinstance(host, str) or host not in {'github.com', 'https://github.com'}):
            raise PermissionError('Malformed Copilot account identity')
        return {'login': login, 'host': host}

    def same_identity(left, right):
        return (left['login'].casefold() == right['login'].casefold()
                and left['host'].removeprefix('https://').casefold()
                == right['host'].removeprefix('https://').casefold())

    last_values = aliases(('lastLoggedInUser', 'last_logged_in_user'))
    list_values = aliases(('loggedInUsers', 'logged_in_users'))
    if not last_values and not list_values:
        raise PermissionError('Copilot account identity is unavailable')
    canonical_identity = None
    for _, value in last_values:
        current = identity(value)
        if canonical_identity and not same_identity(current, canonical_identity):
            raise PermissionError('Conflicting Copilot account aliases')
        canonical_identity = canonical_identity or current
    for _, value in list_values:
        if not isinstance(value, list) or len(value) != 1:
            raise PermissionError('Copilot account list must contain one selected account')
        current = identity(value[0])
        if canonical_identity and not same_identity(current, canonical_identity):
            raise PermissionError('Conflicting Copilot account aliases')
        canonical_identity = canonical_identity or current
    if expected is not None and canonical_identity['login'].casefold() != expected.casefold():
        raise PermissionError('Native Copilot account binding changed')

    result = {'lastLoggedInUser': canonical_identity,
              'loggedInUsers': [canonical_identity]}
    for names, output in ((('authTokens', 'auth_tokens'), 'authTokens'),
                          (('copilotTokens', 'copilot_tokens'), 'copilotTokens')):
        values = aliases(names)
        canonical_map = None
        emitted_map = None
        for _, value in values:
            if not isinstance(value, dict) or len(value) > 1:
                raise PermissionError('Copilot token map must contain at most one entry')
            checked = {}
            emitted = {}
            for key, token in value.items():
                if not isinstance(key, str):
                    raise PermissionError('Malformed or foreign Copilot token entry')
                owner_key = None
                prefix = 'https://github.com:'
                suffix = ':github' if output == 'authTokens' else ''
                if key.startswith(prefix) and (not suffix or key.endswith(suffix)):
                    owner_key = key[len(prefix):len(key)-len(suffix) if suffix else None]
                if owner_key is not None:
                    if owner_key.casefold() != canonical_identity['login'].casefold():
                        raise PermissionError('Malformed or foreign Copilot token entry')
                    normalized_key = 'selected-account'
                elif key in {'github.com', 'https://github.com'}:
                    normalized_key = 'selected-account'
                elif key.casefold() == canonical_identity['login'].casefold():
                    normalized_key = 'selected-account'
                else:
                    raise PermissionError('Malformed or foreign Copilot token entry')
                if output == 'authTokens' and isinstance(token, dict):
                    if set(token) != {'token'}:
                        raise PermissionError('Malformed Copilot auth-token record')
                    token_value = token.get('token')
                    emitted_token = {'token': token_value}
                else:
                    token_value = token
                    emitted_token = token
                if not isinstance(token_value, str) or not token_value or len(token_value) > 65536:
                    raise PermissionError('Malformed or foreign Copilot token entry')
                checked[normalized_key] = token_value
                emitted[key] = emitted_token
            if canonical_map is not None and checked != canonical_map:
                raise PermissionError('Conflicting Copilot token aliases')
            canonical_map = checked
            if emitted_map is None:
                emitted_map = emitted
        if canonical_map is not None:
            result[output] = emitted_map
    return result


def _provider_access_document(spec):
    """Fresh native provider auth, without settings, hooks or Claude refresh."""
    provider=spec['provider']
    if provider=='claude':
        identity=_read_private_document(spec['identity_file']).get('oauthAccount',{})
        if identity.get('accountUuid')!=spec['account_id']:
            raise PermissionError('Native Claude account binding changed')
        data=_read_private_document(spec['auth_file'])
        token=data.get('claudeAiOauth')
        if (not isinstance(token,dict) or not isinstance(token.get('accessToken'),str)
                or not token['accessToken'] or type(token.get('expiresAt')) not in (int,float)
                or not time.time()+_ISSUE_ACCESS_LIFETIME<=token['expiresAt']/1000<1e12):
            raise PermissionError('Native Claude access renewal required')
        if _read_private_document(spec['identity_file']).get('oauthAccount',{}).get('accountUuid')!=spec['account_id']:
            raise PermissionError('Native Claude account changed during inspection')
        allowed={'accessToken','expiresAt','scopes','subscriptionType','subscriptionTypeSource','rateLimitTier'}
        return {'claudeAiOauth':{k:v for k,v in token.items() if k in allowed}}
    if provider=='copilot':
        data=_read_private_document(spec['auth_file'],jsonc=True)
        return _copilot_access_document(data, spec['account_id'])
    raise PermissionError('Unknown native credential provider')


def _native_refresh(spec):
    """Ask the existing native authority to renew; never create a second one."""
    path = Path(spec['native_socket']).resolve(strict=True)
    _owner_directory(path.parent)
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise PermissionError('Native account daemon is unavailable')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(20)
        channel.connect(str(path))
        if _peer_uid(channel) != os.getuid():
            raise PermissionError('Native account daemon owner differs')
        from agentporter.agents.native_codex_auth import read_native_account
        read_native_account(channel, refresh=True)


@contextmanager
def _native_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) or libc.prctl(36, 1, 0, 0, 0):
        raise PermissionError('Cannot supervise native authentication descendants')
    try:
        yield
    finally:
        if libc.prctl(36, previous.value, 0, 0, 0):
            raise PermissionError('Cannot restore native process supervision')


def _children():
    result = set()
    for task in Path('/proc/self/task').iterdir():
        try:
            result.update(int(pid) for pid in (task/'children').read_text().split())
        except FileNotFoundError:
            pass
    return result


def _native_stopped(before):
    deadline = time.monotonic()+3
    while True:
        remaining = set()
        for pid in _children()-before:
            try:
                state = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0]
            except FileNotFoundError:
                continue
            if state == 'Z':
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
            else:
                remaining.add(pid)
        if not remaining:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)


def _immutable_executable(path):
    path = Path(path)
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        kind = stat.S_ISREG(info.st_mode) if component == path else stat.S_ISDIR(info.st_mode)
        if not kind or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Native executable requires immutable root custody')
    if not os.access(path, os.X_OK):
        raise PermissionError('Native executable is not executable')


def _owner_directory(path, *, private=False):
    descriptor = os.open('/', _DIR)
    try:
        for part in Path(path).parts[1:]:
            child = os.open(part, _DIR, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022 and not sticky_root:
                raise PermissionError('Broker directory ancestry is not trusted')
        info = os.fstat(descriptor)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise PermissionError('Broker state must be owner private')
    finally:
        os.close(descriptor)


def _private_write(path, raw, *, create=False):
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_CREAT | os.O_EXCL if create else 0
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise PermissionError('Credential snapshot lost private custody')
        os.ftruncate(fd, 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def load_policy(path):
    """Read an immutable operator policy, never authority supplied by a job."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise PermissionError('Noncanonical credential policy path')
    parent = os.open('/', _DIR)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, _DIR, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Credential policy ancestry requires root custody')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 65536):
                raise PermissionError('Credential policy requires immutable root custody')
            raw = os.read(fd, 65537)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    data = json.loads(raw, object_pairs_hook=_unique)
    fields = {'version', 'owner_uid', 'worker_uid', 'socket_path', 'state_dir', 'accounts', 'forbidden_roots', 'mode'}
    if (not isinstance(data, dict) or set(data) != fields or type(data['version']) is not int
            or data['version'] != 1 or type(data['owner_uid']) is not int
            or data['owner_uid'] <= 0 or type(data['worker_uid']) is not int
            or data['worker_uid'] <= 0 or data['worker_uid'] == data['owner_uid']
            or data['mode'] not in {'access_only', 'exclusive_native'}
            or not isinstance(data['accounts'], dict) or not 1 <= len(data['accounts']) <= 32
            or not isinstance(data['forbidden_roots'], list) or not data['forbidden_roots']):
        raise PermissionError('Invalid credential broker policy')
    protected = [data['socket_path'], data['state_dir']]
    stores = set()
    for name, account in data['accounts'].items():
        account_fields = {'auth_file', 'native_socket', 'account_id'} if data['mode'] == 'access_only' else {'auth_file', 'native_executable', 'account_id'}
        provider=account.get('provider') if isinstance(account,dict) else None
        if provider is not None:
            if data['mode']!='access_only' or provider not in {'claude','copilot'}:
                raise PermissionError('Provider files require access-only custody')
            account_fields={'provider','auth_file','account_id'}|({'identity_file'} if provider=='claude' else set())
        if (not _ACCOUNT.fullmatch(name) or not isinstance(account, dict)
                or set(account) != account_fields
                or not isinstance(account['account_id'], str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', account['account_id'])):
            raise PermissionError('Invalid canonical credential account')
        protected.extend(account[key] for key in account_fields-{'account_id','provider'})
        source = Path(account['auth_file'])
        if source.name != {'claude':'.credentials.json','copilot':'config.json'}.get(provider,'auth.json'):
            raise PermissionError('Canonical Codex auth must be named auth.json')
        # Aliases of one intended account use one exact path and one lease.
        stores.add(str(source))
    for value in [*protected, *data['forbidden_roots']]:
        if (not isinstance(value, str) or not Path(value).is_absolute()
                or value != str(Path(value)) or '..' in Path(value).parts):
            raise PermissionError('Broker policy paths must be canonical and absolute')
    for value in protected:
        resolved = Path(value).resolve(strict=False)
        if any(resolved == Path(root).resolve() or resolved.is_relative_to(Path(root).resolve())
               for root in data['forbidden_roots']):
            raise PermissionError('Credential authority overlaps a workspace')
    if data['mode'] == 'exclusive_native':
        for account in data['accounts'].values():
            _immutable_executable(account['native_executable'])
    if len(data['socket_path'].encode()) > 100:
        raise PermissionError('Credential socket path is too long')
    return data


class CredentialBroker:
    def __init__(self, policy):
        self.policy = policy
        self.slots = threading.BoundedSemaphore(8)
        self.account_locks = {spec['auth_file']: threading.Lock() for spec in policy['accounts'].values()}

    def issue_access(self, account, channel):
        spec = self.policy['accounts'][account]
        source = Path(spec['auth_file'])
        with self.account_locks[str(source)]:
            if spec.get('provider') in {'claude','copilot'}:
                issued=_provider_access_document(spec)
                label='lease-'+uuid.uuid4().hex
                self.audit('access_issued',account,label)
                _send(channel,{'status':'issued','lease_id':label,
                    'auth_b64':base64.b64encode(json.dumps(issued).encode()).decode()})
                return
            data = _read_native(source, spec['account_id'])
            if _access_expiry(data) < time.time()+_ISSUE_ACCESS_LIFETIME:
                self.audit('native_renewal_requested', account)
                _native_refresh(spec)
                data = _read_native(source, spec['account_id'])
            if _access_expiry(data) < time.time()+_ISSUE_ACCESS_LIFETIME:
                raise PermissionError('Native account renewal required')
            tokens = data['tokens']
            # Only a bounded access credential crosses the UID boundary.
            # Empty refresh_token satisfies native Codex's managed-auth schema
            # but cannot renew or alter the authoritative native credential.
            issued = {'auth_mode': 'chatgpt', 'OPENAI_API_KEY': None,
                'tokens': {key: tokens[key] for key in ('access_token', 'id_token', 'account_id')},
                'last_refresh': datetime.now(timezone.utc).isoformat()}
            issued['tokens']['refresh_token'] = ''
            label = 'lease-'+uuid.uuid4().hex
            self.audit('access_issued', account, label)
            _send(channel, {'status': 'issued', 'lease_id': label,
                'auth_b64': base64.b64encode(json.dumps(issued).encode()).decode()})

    def audit(self, event, account, lease_id=None):
        # Profile and opaque lease labels only. Never record authentication
        # contents, account IDs, token hashes, caller payloads or exception text.
        _owner_directory(self.policy['state_dir'], private=True)
        path = Path(self.policy['state_dir'])/'events.jsonl'
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise PermissionError('Broker audit file lost private custody')
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = json.dumps({'event': event, 'account': account, 'lease_id': lease_id,
                              'timestamp': time.time()}, separators=(',', ':')).encode()+b'\n'
            while raw:
                count = os.write(fd, raw)
                if count <= 0:
                    raise OSError('Broker audit write failed')
                raw = raw[count:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def handle(self, channel):
        """One socket connection, one exact account; disconnects retain recovery."""
        lease = None
        directory = None
        try:
            if _peer_uid(channel) != self.policy['worker_uid']:
                raise PermissionError('Credential client UID is not admitted')
            channel.settimeout(10)
            request = _receive(channel)
            if (set(request) != {'version', 'op', 'account'} or request['version'] != 1
                    or type(request['version']) is not int or request['op'] != 'begin'
                    or not isinstance(request['account'], str)
                    or request['account'] not in self.policy['accounts']):
                raise PermissionError('Credential account is not admitted')
            source = Path(self.policy['accounts'][request['account']]['auth_file'])
            if self.policy.get('mode') == 'access_only':
                self.issue_access(request['account'], channel)
                return
            _owner_directory(self.policy['state_dir'], private=True)
            directory = Path(self.policy['state_dir']) / ('lease-'+uuid.uuid4().hex)
            directory.mkdir(mode=0o700)
            snapshot = directory/'auth.json'
            lease = CredentialLease(source, snapshot)
            _oauth_document(lease.before, self.policy['accounts'][request['account']]['account_id'])
            self.audit('worker_lease', request['account'], directory.name)
            _send(channel, {'status': 'leased', 'lease_id': directory.name,
                            'auth_b64': base64.b64encode(lease.before).decode()})
            # The provider runtime caps jobs at 900 seconds. The owner retains
            # the pending guard on disconnect; no automatic account fallback.
            channel.settimeout(930)
            result = _receive(channel)
            if (set(result) != {'version', 'op', 'auth_b64'} or type(result['version']) is not int
                    or result['version'] != 1 or result['op'] != 'finish'
                    or not isinstance(result['auth_b64'], str)):
                raise PermissionError('Invalid credential completion')
            raw = base64.b64decode(result['auth_b64'], validate=True)
            if not 0 < len(raw) <= 1024*1024:
                raise PermissionError('Credential completion exceeds its bound')
            _oauth_document(raw)
            _private_write(snapshot, raw)
            lease.finish()
            snapshot.unlink()
            directory.rmdir()
            self.audit('worker_completion', request['account'], directory.name)
            _send(channel, {'status': 'committed'})
        except (OSError, ValueError, EOFError, PermissionError, KeyError, TypeError):
            # Never serialize exception contents, native auth or filesystem data.
            try:
                reason = ('native_account_unavailable_or_renewal_required' if self.policy.get('mode') == 'access_only'
                          else 'credential_account_unavailable_or_recovery_required')
                _send(channel, {'status': 'denied', 'reason': reason})
            except OSError:
                pass
        finally:
            if lease is not None and not lease.closed:
                lease.close()

    def serve(self):
        if os.getuid() != self.policy['owner_uid'] or os.getuid() == 0:
            raise PermissionError('Credential broker must run as its native account owner')
        state = Path(self.policy['state_dir'])
        _owner_directory(state, private=True)
        info = state.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError('Credential broker state must be owner private')
        path = Path(self.policy['socket_path'])
        _owner_directory(path.parent)
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or parent.st_mode & 0o027 or path.exists() or path.is_symlink()):
            raise PermissionError('Credential socket requires an owner-controlled free path')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            old_umask = os.umask(0o117)
            try:
                listener.bind(str(path))
            finally:
                os.umask(old_umask)
            os.chmod(path, 0o660)
            # The systemd service receives the worker group solely to label
            # this socket. Workers cannot enter the owner-private state dir.
            os.chown(path, -1, parent.st_gid)
            identity = path.lstat()
            listener.listen(8)
            try:
                while True:
                    channel, _ = listener.accept()
                    if not self.slots.acquire(blocking=False):
                        channel.close()
                        continue
                    def serve_one(connection):
                        try:
                            with connection:
                                self.handle(connection)
                        finally:
                            self.slots.release()
                    threading.Thread(target=serve_one, args=(channel,), daemon=True).start()
            finally:
                if path.lstat().st_ino == identity.st_ino:
                    path.unlink()


class BrokerCredentialLease:
    """Worker-parent client. This socket and protocol never enter Bubblewrap."""
    def __init__(self, config, target):
        self.channel = None
        self.access_only = False
        self.target = Path(target)
        self.target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = Path(config['socket_path'])
        parent, info = path.parent.lstat(), path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != config['owner_uid']
                or parent.st_mode & 0o027 or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != config['owner_uid'] or info.st_mode & 0o007):
            raise PermissionError('Untrusted canonical credential socket')
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(30)
            channel.connect(str(path))
            if _peer_uid(channel) != config['owner_uid']:
                raise PermissionError('Credential broker owner UID differs')
            _send(channel, {'version': 1, 'op': 'begin', 'account': config['account']})
            response = _receive(channel)
            if (set(response) != {'status', 'lease_id', 'auth_b64'} or response['status'] not in {'leased', 'issued'}
                    or not re.fullmatch('lease-[0-9a-f]{32}', response['lease_id'])):
                raise PermissionError('Canonical credential account unavailable; no copied-token fallback')
            raw = base64.b64decode(response['auth_b64'], validate=True)
            provider=config.get('provider','codex')
            if provider=='codex':
                data = _oauth_document(raw)
            elif provider in {'claude','copilot'} and response['status']=='issued':
                data=_document(raw)
                if provider=='claude':
                    token=data.get('claudeAiOauth',{})
                    allowed={'accessToken','expiresAt','scopes','subscriptionType','subscriptionTypeSource','rateLimitTier'}
                    if (set(data)!={'claudeAiOauth'} or not isinstance(token,dict) or set(token)-allowed
                            or not isinstance(token.get('accessToken'),str) or not token['accessToken']
                            or type(token.get('expiresAt')) not in (int,float)
                            or token['expiresAt']/1000<time.time()+_MIN_ACCESS_LIFETIME):
                        raise PermissionError('Claude access credential is unbounded or contains renewal authority')
                else:
                    allowed={'authTokens','copilotTokens','loggedInUsers','lastLoggedInUser',
                             'auth_tokens','copilot_tokens','logged_in_users','last_logged_in_user'}
                    if set(data)-allowed:
                        raise PermissionError('Copilot credential contains non-authentication settings')
                    data = _copilot_access_document(data)
                    raw = json.dumps(data, separators=(',', ':'), allow_nan=False).encode()
            else:
                raise PermissionError('Unknown credential provider')
            if response['status'] == 'issued':
                if provider=='codex' and (data['tokens'].get('refresh_token') != '' or _access_expiry(data) < time.time()+_MIN_ACCESS_LIFETIME):
                    raise PermissionError('Access-only credential is unbounded or contains renewal authority')
                self.access_only = True
            _private_write(self.target, raw, create=True)
            self.channel = channel
            if self.access_only:
                channel.close()
                self.channel = None
        except BaseException:
            channel.close()
            raise

    def finish(self):
        if self.access_only:
            return
        if self.channel is None:
            raise PermissionError('Canonical credential lease is no longer held')
        try:
            parent = os.open(self.target.parent, _DIR)
            try:
                raw = _read(parent, self.target.name)
            finally:
                os.close(parent)
            self.channel.settimeout(15)
            _send(self.channel, {'version': 1, 'op': 'finish', 'auth_b64': base64.b64encode(raw).decode()})
            if _receive(self.channel) != {'status': 'committed'}:
                raise PermissionError('Canonical credential completion needs owner recovery')
        finally:
            self.channel.close()
            self.channel = None


def native_run(policy, account, arguments):
    """Enroll native launches in the same account lock without changing routing."""
    if policy.get('mode', 'exclusive_native') != 'exclusive_native':
        raise PermissionError('Access-only issuance uses the existing native daemon')
    if os.getuid() != policy['owner_uid'] or account not in policy['accounts']:
        raise PermissionError('Native credential account is not admitted')
    spec = policy['accounts'][account]
    _immutable_executable(spec['native_executable'])
    _owner_directory(policy['state_dir'], private=True)
    with _native_subreaper():
        before = _children()
        directory = Path(policy['state_dir']) / ('native-'+uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        snapshot = directory/'auth.json'
        lease = CredentialLease(Path(spec['auth_file']), snapshot)
        process = None
        try:
            _oauth_document(lease.before, spec['account_id'])
            CredentialBroker(policy).audit('native_lease', account, directory.name)
            environment = dict(os.environ, CODEX_HOME=str(Path(spec['auth_file']).parent))
            process = subprocess.Popen([spec['native_executable'], *arguments], env=environment)
            return process.wait()
        finally:
            if not _native_stopped(before):
                lease.close()
                CredentialBroker(policy).audit('native_recovery_required', account, directory.name)
                raise PermissionError('Native authentication descendants remain; account requires owner recovery')
            try:
                parent = os.open(Path(spec['auth_file']).parent, _DIR)
                try:
                    current = _read(parent, 'auth.json')
                finally:
                    os.close(parent)
                _oauth_document(current, spec['account_id'])
                # Native CLI used canonical auth directly. The unchanged
                # inspection snapshot never overwrites its native rotation.
                lease.finish()
            except BaseException:
                if not lease.closed:
                    lease.close()
                raise
            snapshot.unlink()
            directory.rmdir()
            CredentialBroker(policy).audit('native_completion', account, directory.name)


def native_account(policy):
    """Resolve an enrolled native profile without changing its CODEX_HOME."""
    profile = Path(os.environ.get('CODEX_HOME', str(Path.home()/'.codex'))).resolve()
    matches = sorted(name for name, spec in policy['accounts'].items()
                     if Path(spec['auth_file']).parent.resolve() == profile)
    if not matches:
        raise PermissionError('Native profile is not enrolled; no account fallback')
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    subparsers = parser.add_subparsers(dest='operation', required=True)
    subparsers.add_parser('serve')
    native = subparsers.add_parser('native')
    native.add_argument('account')
    native.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    policy = load_policy(args.policy)
    if args.operation == 'serve':
        CredentialBroker(policy).serve()
    else:
        arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
        account = native_account(policy) if args.account == 'auto' else args.account
        raise SystemExit(native_run(policy, account, arguments))


if __name__ == '__main__':
    main()
