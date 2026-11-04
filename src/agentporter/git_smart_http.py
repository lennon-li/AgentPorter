"""Bounded smart-HTTP wire transport, not an approval or publication backend.

Only protected backend code may construct these dependencies. No MCP/REST tool
uses this module yet. Callers must separately enforce signatures, local/remote
state, ancestry, admission, durable outcome guards, and scoped ref application.
"""
import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import time
from types import MappingProxyType
from urllib.parse import urlsplit

from agentporter.resources import ResourceCleanupError
from agentporter.scoped_https import _PinnedPublicHTTPS, ScopedPublicHTTPSPolicy

_SERVICES = {'git-upload-pack', 'git-receive-pack'}
_MAX_BYTES = 64 * 1024 * 1024
_MAX_DISCOVERY = 8 * 1024 * 1024


def _ref(name, *, branch=False):
    if not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024:
        return False
    if branch and not name.startswith('refs/heads/'):
        return False
    if not branch and name == 'HEAD':
        return True
    if not name.startswith('refs/') or '..' in name or '@{' in name:
        return False
    if any(ord(c) <= 32 or ord(c) == 127 or c in '~^:?*[\\' for c in name):
        return False
    return all(part and not part.startswith('.') and not part.endswith(('.', '.lock')) for part in name.split('/'))


def _oid(value):
    return isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value) is not None


def packet(body):
    if not isinstance(body, bytes) or not body or len(body) + 4 > 65520:
        raise ValueError('Invalid Git packet length')
    return f'{len(body) + 4:04x}'.encode('ascii') + body


def _packets(body):
    if not isinstance(body, bytes) or len(body) > _MAX_DISCOVERY:
        raise ValueError('Git protocol response exceeds bound')
    position, lines = 0, []
    while position < len(body):
        header = body[position:position + 4]
        if len(header) != 4 or not re.fullmatch(b'[0-9a-f]{4}', header):
            raise ValueError('Malformed Git packet header')
        length = int(header, 16)
        if length == 0:
            lines.append(None)
            position += 4
        else:
            if not 4 <= length <= 65520 or position + length > len(body):
                raise ValueError('Truncated or unsupported Git packet')
            lines.append(body[position + 4:position + length])
            position += length
        if len(lines) > 50004:
            raise ValueError('Too many Git protocol records')
    return lines


@dataclass(frozen=True)
class Advertisement:
    refs: object
    capabilities: frozenset
    object_format: str


def parse_advertisement(body, service):
    if service not in _SERVICES:
        raise ValueError('Unsupported Git HTTP service')
    lines = _packets(body)
    if (len(lines) < 4 or lines[0] != f'# service={service}\n'.encode()
            or lines[1] is not None or lines[-1] is not None):
        raise ValueError('Wrong smart-HTTP service advertisement')
    refs, capabilities, width = {}, frozenset(), None
    for index, raw in enumerate(lines[2:-1]):
        if raw is None:
            raise ValueError('Unexpected discovery flush')
        raw = raw.removesuffix(b'\n')
        if b'\r' in raw or b'\n' in raw:
            raise ValueError('Ambiguous Git reference record')
        if index == 0:
            parts = raw.split(b'\0')
            if len(parts) != 2 or len(parts[1]) > 4096:
                raise ValueError('Missing or ambiguous Git capabilities')
            raw, encoded = parts
            if any(c < 32 or c > 126 for c in encoded):
                raise ValueError('Invalid Git capability separator')
            tokens = encoded.split()
            if any(any(c < 33 or c > 126 for c in token) for token in tokens) or len(set(tokens)) != len(tokens):
                raise ValueError('Invalid Git capabilities')
            capabilities = frozenset(token.decode('ascii') for token in tokens)
        elif b'\0' in raw:
            raise ValueError('Capabilities appear outside first reference')
        parts = raw.split(b' ')
        if len(parts) != 2:
            raise ValueError('Malformed Git reference')
        oid, name = (part.decode('utf-8') for part in parts)
        if not _oid(oid) or (width is not None and len(oid) != width):
            raise ValueError('Inconsistent Git object identity')
        width = len(oid)
        if name == 'capabilities^{}' and index == 0 and oid == '0' * width:
            continue
        if oid == '0' * width:
            raise ValueError('Zero Git object outside empty advertisement')
        if name == '.have':
            continue
        candidate = name[:-3] if name.endswith('^{}') else name
        if not _ref(candidate) or name in refs:
            raise ValueError('Invalid or duplicate Git reference')
        refs[name] = oid
    algorithm = 'sha256' if width == 64 else 'sha1'
    formats = [cap for cap in capabilities if cap.startswith('object-format=')]
    if formats and formats != ['object-format=' + algorithm]:
        raise ValueError('Git object format does not match discovery')
    if algorithm == 'sha256' and not formats:
        raise ValueError('SHA256 Git requires explicit object-format capability')
    return Advertisement(MappingProxyType(refs), capabilities, algorithm)


@dataclass(frozen=True)
class RefUpdate:
    ref: str
    old_oid: str
    new_oid: str

    def __post_init__(self):
        if (not _ref(self.ref, branch=True) or not _oid(self.old_oid) or not _oid(self.new_oid)
                or len(self.old_oid) != len(self.new_oid) or self.new_oid == '0' * len(self.new_oid)):
            raise ValueError('An exact non-deleting local-branch update is required')


def validate_pack(pack, algorithm):
    if not isinstance(pack, bytes) or not 12 < len(pack) <= _MAX_BYTES or pack[:4] != b'PACK':
        raise ValueError('Invalid or oversized Git pack')
    version, count = struct.unpack('>II', pack[4:12])
    if version not in {2, 3} or count > 100000:
        raise ValueError('Unsupported Git pack version or object count')
    width = 32 if algorithm == 'sha256' else 20
    if algorithm not in {'sha1', 'sha256'} or len(pack) < 12 + width:
        raise ValueError('Unsupported Git pack format')
    if hashlib.new(algorithm, pack[:-width]).digest() != pack[-width:]:
        raise ValueError('Git pack checksum mismatch')


def push_body(update, pack, advertisement):
    algorithm = 'sha256' if len(update.new_oid) == 64 else 'sha1'
    if advertisement.object_format != algorithm or 'report-status' not in advertisement.capabilities:
        raise ValueError('Remote lacks exact-format push status support')
    actual = advertisement.refs.get(update.ref, '0' * len(update.old_oid))
    if actual != update.old_oid:
        raise PermissionError('Remote branch changed before publication')
    validate_pack(pack, algorithm)
    capabilities = 'report-status'
    if 'object-format=' + algorithm in advertisement.capabilities:
        capabilities += ' object-format=' + algorithm
    command = f'{update.old_oid} {update.new_oid} {update.ref}\0 {capabilities}\n'.encode('utf-8')
    return packet(command) + b'0000' + pack


def check_push_result(body, update):
    expected = [b'unpack ok\n', ('ok ' + update.ref + '\n').encode('utf-8'), None]
    if _packets(body) != expected:
        raise ValueError('Remote did not confirm exactly the requested branch update')


@dataclass(frozen=True)
class RemoteRepository:
    url: str

    def __post_init__(self):
        if not isinstance(self.url, str) or len(self.url) > 2048:
            raise ValueError('Invalid owner Git remote URL')
        parts = urlsplit(self.url)
        host = parts.hostname or ''
        path = parts.path
        if (parts.scheme != 'https' or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host)
                or '.' not in host or '..' in host or parts.netloc != host
                or parts.query or parts.fragment or self.url != 'https://' + host + path
                or not re.fullmatch(r'(?:/[A-Za-z0-9._-]+){1,8}\.git', path)
                or any(part in {'.', '..'} for part in path.split('/')[1:])):
            raise ValueError('Remote must be one canonical HTTPS repository without credentials or query')


class ScopedGitHTTP:
    def __init__(self, remote, *, credential_file=None, username='x-access-token', workspace_roots=()):
        if not isinstance(remote, RemoteRepository) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', username):
            raise ValueError('Invalid protected Git transport dependencies')
        self.remote = remote
        self._credential = Path(credential_file).absolute() if credential_file is not None else None
        self._username = username
        if self._credential is not None:
            if '..' in self._credential.parts:
                raise PermissionError('Git credential path must be canonical')
            for root in workspace_roots:
                if self._credential.resolve().is_relative_to(Path(root).resolve()):
                    raise PermissionError('Git credential must be outside exposed workspaces')

    def _authorization(self):
        if self._credential is None:
            return None
        directory = ScopedPublicHTTPSPolicy._open_trusted_directory(self._credential.parent)
        if directory is None:
            raise PermissionError('Protected Git credential directory is missing')
        try:
            descriptor = os.open(self._credential.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_nlink != 1 or info.st_mode & 0o077 or not 1 <= info.st_size <= 4096):
                    raise PermissionError('Untrusted protected Git credential')
                raw = os.read(descriptor, 4097)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        if not raw or len(raw) > 4096 or any(c < 33 or c > 126 for c in raw):
            raise PermissionError('Invalid protected Git credential encoding')
        return 'Basic ' + base64.b64encode(self._username.encode('ascii') + b':' + raw).decode('ascii')

    def _request(self, service, body=None):
        if service not in _SERVICES or (body is not None and (not isinstance(body, bytes) or len(body) > _MAX_BYTES)):
            raise ValueError('Unsupported Git HTTP request')
        origin = urlsplit(self.remote.url)
        method = 'GET' if body is None else 'POST'
        target = origin.path + ('/info/refs?service=' + service if body is None else '/' + service)
        suffix = 'advertisement' if body is None else 'result'
        expected = f'application/x-{service}-{suffix}'
        headers = {'Accept': expected, 'Accept-Encoding': 'identity', 'Connection': 'close',
                   'User-Agent': 'AgentPorter-scoped-git/1', 'Git-Protocol': 'version=0'}
        authorization = self._authorization()
        if authorization is not None:
            headers['Authorization'] = authorization
        if body is not None:
            headers.update({'Content-Type': f'application/x-{service}-request', 'Content-Length': str(len(body))})
        connection, attempted = None, False
        try:
            connection = _PinnedPublicHTTPS(origin.hostname, timeout=20)
            attempted = True
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            response_headers = {}
            for name, value in response.getheaders():
                key = name.lower()
                if key in response_headers and key in {'content-type', 'content-length', 'transfer-encoding', 'content-encoding'}:
                    raise ValueError('Ambiguous Git HTTP framing')
                response_headers[key] = value
            if (response.status != 200 or response_headers.get('content-type', '').split(';')[0].strip().lower() != expected
                    or response_headers.get('content-encoding', 'identity').lower() != 'identity'
                    or ('content-length' in response_headers and 'transfer-encoding' in response_headers)
                    or response_headers.get('transfer-encoding', 'chunked').lower() != 'chunked'):
                raise ValueError('Rejected Git HTTP response')
            limit = _MAX_DISCOVERY if body is None or service == 'git-receive-pack' else _MAX_BYTES
            length = response_headers.get('content-length')
            if length is not None and (not re.fullmatch(r'[0-9]{1,20}', length) or int(length) > limit):
                raise ValueError('Oversized Git HTTP response')
            deadline, output = time.monotonic() + 40, bytearray()
            while True:
                chunk = response.read(min(65536, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit or time.monotonic() >= deadline:
                    raise ValueError('Git HTTP body exceeded resource bound')
            if length is not None and len(output) != int(length):
                raise ValueError('Truncated Git HTTP response')
            return bytes(output)
        except Exception:
            if attempted and method == 'POST' and service == 'git-receive-pack':
                raise ResourceCleanupError('Scoped Git publication outcome is uncertain; owner reconciliation required') from None
            raise PermissionError('Scoped Git HTTPS request failed') from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    if attempted and method == 'POST' and service == 'git-receive-pack':
                        raise ResourceCleanupError('Scoped Git publication cleanup is uncertain; owner reconciliation required') from None
                    raise PermissionError('Scoped Git HTTPS connection cleanup failed') from None

    def discover(self, service):
        try:
            return parse_advertisement(self._request(service), service)
        except ValueError:
            raise PermissionError('Scoped Git remote advertisement was rejected') from None

    def send_push(self, update, pack):
        observed = self.discover('git-receive-pack')
        body = push_body(update, pack, observed)
        response = self._request('git-receive-pack', body)
        try:
            check_push_result(response, update)
        except ValueError:
            raise ResourceCleanupError('Remote publication acknowledgement is uncertain; owner reconciliation required') from None

    def fetch_pack(self, ref, expected_oid):
        if not _ref(ref, branch=True) or not _oid(expected_oid) or expected_oid == '0' * len(expected_oid):
            raise ValueError('An exact advertised branch object is required')
        observed = self.discover('git-upload-pack')
        if observed.refs.get(ref) != expected_oid:
            raise PermissionError('Remote branch changed before object acquisition')
        capabilities = ' ofs-delta' if 'ofs-delta' in observed.capabilities else ''
        if 'object-format=' + observed.object_format in observed.capabilities:
            capabilities += ' object-format=' + observed.object_format
        body = packet(('want ' + expected_oid + capabilities + '\n').encode()) + b'0000' + packet(b'done\n')
        response = self._request('git-upload-pack', body)
        prefix = packet(b'NAK\n')
        if not response.startswith(prefix):
            raise PermissionError('Unexpected Git fetch negotiation response')
        pack = response[len(prefix):]
        try:
            validate_pack(pack, observed.object_format)
        except ValueError:
            raise PermissionError('Scoped Git fetch returned an invalid pack') from None
        return pack
