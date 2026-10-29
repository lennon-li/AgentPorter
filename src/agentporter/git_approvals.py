"""Independent owner signatures for exact, single-use Git requests.

Internal protocol only. No tool is enabled by this module. A privileged backend
must enforce its sealed workspace policy and construct the expected request from
locked current repository state. Its verification key and claim ledger must be
operator-controlled; request data never chooses a key or a ledger.
"""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import time
import uuid
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_REQUEST_DOMAIN = b'AgentPorter BCC Git request v1\0'
_APPROVAL_DOMAIN = b'AgentPorter BCC Git owner approval v1\0'
_AUDIENCE = 'agentporter-bcc-git'
_MAX_LIFETIME = 300


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def _decode(value):
    return json.loads(value, object_pairs_hook=_unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON number')))


def _text(value, maximum):
    return isinstance(value, str) and 0 < len(value) <= maximum and all(ord(c) >= 32 and ord(c) != 127 for c in value)


@dataclass(frozen=True)
class GitApprovalRequest:
    canonical_payload: bytes

    def __post_init__(self):
        if not isinstance(self.canonical_payload, bytes) or len(self.canonical_payload) > 65536:
            raise ValueError('Invalid Git request size')
        data = _decode(self.canonical_payload)
        fields = {'operation', 'workspace_id', 'repository_path', 'repository_device',
                  'repository_inode', 'expected_head', 'expected_tree', 'branch', 'parameters'}
        if not isinstance(data, dict) or set(data) != fields or _canonical(data) != self.canonical_payload:
            raise ValueError('Invalid canonical Git request schema')
        if data['operation'] not in {'commit', 'push', 'fetch', 'pull'}:
            raise ValueError('Unsupported Git approval operation')
        if not _text(data['workspace_id'], 256) or data['workspace_id'] == '*':
            raise ValueError('Git approval requires one workspace')
        path = data['repository_path']
        if (not _text(path, 4096) or not path.startswith('/') or path.startswith('//')
                or path == '/' or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path):
            raise ValueError('Git approval requires one canonical absolute repository path')
        if (type(data['repository_device']) is not int or data['repository_device'] < 0
                or type(data['repository_inode']) is not int or data['repository_inode'] <= 0):
            raise ValueError('Git approval requires repository filesystem identity')
        for name in ('expected_head', 'expected_tree'):
            value = data[name]
            if not (name == 'expected_head' and value is None):
                if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value):
                    raise ValueError('Git approval requires full repository object IDs')
        branch = data['branch']
        if branch is not None and (not _text(branch, 1024) or not branch.startswith('refs/heads/')):
            raise ValueError('Git approval branch must be explicit')
        if not isinstance(data['parameters'], dict):
            raise ValueError('Git approval parameters must be an object')

    @classmethod
    def from_payload(cls, payload):
        return cls(_canonical(payload))

    @property
    def digest(self):
        return hashlib.sha256(_REQUEST_DOMAIN + self.canonical_payload).hexdigest()

    def to_payload(self):
        """Return a new copy; mutations cannot alter the verified request."""
        return _decode(self.canonical_payload)


def issue_git_approval(private_key: Ed25519PrivateKey, request: GitApprovalRequest, *,
                       now=None, lifetime_seconds=300, nonce=None):
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= _MAX_LIFETIME:
        raise ValueError('Git approval lifetime must be 1..300 seconds')
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError('Invalid approval issue time')
    nonce = uuid.uuid4().hex if nonce is None else nonce
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('Invalid approval nonce')
    claims = {'version': 1, 'audience': _AUDIENCE, 'nonce': nonce,
              'issued_at': now, 'expires_at': now + lifetime_seconds,
              'request_sha256': request.digest}
    signature = private_key.sign(_APPROVAL_DOMAIN + _canonical(claims))
    return _canonical({'claims': claims, 'signature': base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}).decode()


@dataclass(frozen=True)
class VerifiedGitApproval:
    request_digest: str
    nonce: str
    expires_at: int


class GitApprovalVerifier:
    def __init__(self, public_key: Ed25519PublicKey, ledger_path, *, existing_only=False):
        self.public_key = public_key
        self.ledger_path = Path(ledger_path).absolute()
        if '..' in self.ledger_path.parts:
            raise PermissionError('Git approval ledger path must be canonical')
        self._check_parent_directories(create=not existing_only)
        parent = self.ledger_path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise PermissionError('Git approval ledger requires a private operator directory')
        self._parent_identity = (parent.st_dev, parent.st_ino)
        flags = os.O_RDONLY if existing_only else os.O_RDWR | os.O_CREAT
        descriptor = os.open(self.ledger_path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise PermissionError('Untrusted Git approval ledger')
            self._ledger_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(descriptor)
        self._check_ledger_identity()
        if existing_only:
            with sqlite3.connect('file:' + quote(str(self.ledger_path)) + '?mode=ro', uri=True) as database:
                database.execute('SELECT nonce,request_sha256,claimed_at,expires_at FROM consumed LIMIT 0')
        else:
            with sqlite3.connect(self.ledger_path) as database:
                database.execute('CREATE TABLE IF NOT EXISTS consumed (nonce TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, claimed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)')

    def assert_consumed(self, nonce, request: GitApprovalRequest):
        """Owner recovery may inspect a spent claim, never restore or reuse it."""
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
            raise PermissionError('Invalid recovery approval nonce')
        self._check_ledger_identity()
        database = sqlite3.connect('file:' + quote(str(self.ledger_path)) + '?mode=ro', uri=True)
        try:
            rows = database.execute('SELECT request_sha256 FROM consumed WHERE nonce=?', (nonce,)).fetchall()
            if len(rows) != 1 or rows[0][0] != request.digest:
                raise PermissionError('Git recovery guard has no matching consumed approval')
        finally:
            database.close()

    def _check_parent_directories(self, *, create=False):
        parent = self.ledger_path.parent
        for directory in [*reversed(parent.parents), parent]:
            try:
                info = directory.lstat()
            except FileNotFoundError:
                if not create:
                    raise PermissionError('Git approval ledger directory disappeared')
                directory.mkdir(mode=0o700)
                info = directory.lstat()
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}
                    or (info.st_mode & 0o022 and not sticky_root)):
                raise PermissionError('Git approval ledger has an untrusted ancestor')

    def _check_ledger_identity(self):
        self._check_parent_directories()
        parent = self.ledger_path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or parent.st_mode & 0o077
                or (parent.st_dev, parent.st_ino) != self._parent_identity):
            raise PermissionError('Git approval ledger private directory changed')
        try:
            info = self.ledger_path.lstat()
        except FileNotFoundError as error:
            raise PermissionError('Git approval ledger disappeared') from error
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != self._ledger_identity):
            raise PermissionError('Git approval ledger identity changed')
        # SQLite opens these paths itself. Never let an existing alias redirect
        # journal I/O or expose a receipt ledger through a public sidecar.
        for suffix in ('-journal', '-wal', '-shm'):
            try:
                sidecar = Path(str(self.ledger_path) + suffix).lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(sidecar.st_mode) or sidecar.st_uid != os.getuid()
                    or sidecar.st_nlink != 1 or sidecar.st_mode & 0o077):
                raise PermissionError('Untrusted Git approval ledger sidecar')

    def verify_and_consume(self, receipt, request: GitApprovalRequest, *, now=None):
        realtime = now is None
        now = int(time.time()) if now is None else now
        if type(now) is not int or now < 0:
            raise PermissionError('Invalid Git approval verification time')
        if not isinstance(receipt, str) or not receipt.isascii() or len(receipt) > 8192:
            raise PermissionError('Invalid Git approval receipt size')
        try:
            envelope = _decode(receipt)
            if not isinstance(envelope, dict) or set(envelope) != {'claims', 'signature'}:
                raise ValueError('Invalid envelope')
            claims, encoded = envelope['claims'], envelope['signature']
            if not isinstance(claims, dict) or set(claims) != {'version', 'audience', 'nonce', 'issued_at', 'expires_at', 'request_sha256'}:
                raise ValueError('Invalid claims')
            if type(claims['version']) is not int or claims['version'] != 1 or claims['audience'] != _AUDIENCE:
                raise ValueError('Invalid approval audience')
            if not isinstance(encoded, str) or not re.fullmatch('[A-Za-z0-9_-]{86}', encoded):
                raise ValueError('Invalid signature encoding')
            signature = base64.urlsafe_b64decode(encoded + '==')
            if base64.urlsafe_b64encode(signature).rstrip(b'=').decode() != encoded:
                raise ValueError('Noncanonical signature encoding')
            self.public_key.verify(signature, _APPROVAL_DOMAIN + _canonical(claims))
            if not isinstance(claims['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', claims['nonce']):
                raise ValueError('Invalid nonce')
            issued, expires = claims['issued_at'], claims['expires_at']
            if (type(issued) is not int or type(expires) is not int or issued < 0
                    or not 1 <= expires - issued <= _MAX_LIFETIME or issued > now or now >= expires):
                raise ValueError('Approval is future-dated, expired, or overlong')
            digest = claims['request_sha256']
            if not isinstance(digest, str) or not hmac.compare_digest(digest, request.digest):
                raise ValueError('Approval does not match the exact Git request')
        except (ValueError, TypeError, KeyError, RecursionError, InvalidSignature) as error:
            raise PermissionError('Git approval receipt rejected') from error
        self._check_ledger_identity()
        database = sqlite3.connect(self.ledger_path, timeout=5)
        try:
            try:
                with database:
                    database.execute('BEGIN IMMEDIATE')
                    # Acquiring the database write lock may have waited. Expiry
                    # is enforced at the actual claim, not only before waiting.
                    claimed_at = int(time.time()) if realtime else now
                    if not issued <= claimed_at < expires:
                        raise PermissionError('Git approval expired before claim')
                    database.execute('INSERT INTO consumed VALUES (?,?,?,?)',
                                     (claims['nonce'], request.digest, claimed_at, expires))
            except sqlite3.IntegrityError as error:
                raise PermissionError('Git approval already consumed') from error
        finally:
            database.close()
        return VerifiedGitApproval(request.digest, claims['nonce'], expires)
