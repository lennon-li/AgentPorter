"""Exclusive, durable custody of a Codex worker's configured auth file.

No login or refresh is performed here. The native client owns token renewal.
The parent reconciles its isolated result only after the client has stopped.
External writers must cooperate with this lock; conflicts fail closed and
retain the pending worker home instead of losing a rotated refresh token.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

_MAX = 1024 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read(parent: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or before.st_size > _MAX):
            raise PermissionError('Credential requires private single-inode custody')
        raw = bytearray()
        while len(raw) <= _MAX:
            chunk = os.read(fd, min(65536, _MAX + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) > _MAX or len(raw) != before.st_size
                or any(getattr(before, f) != getattr(after, f) for f in fields)):
            raise PermissionError('Credential changed during inspection')
        return bytes(raw)
    finally:
        os.close(fd)


def _document(raw: bytes) -> dict:
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('Duplicate authentication field')
            out[key] = value
        return out
    try:
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as exc:
        raise PermissionError('Invalid native authentication document') from exc
    if not isinstance(data, dict) or not data:
        raise PermissionError('Invalid native authentication document')
    return data


def _same_account(before: bytes, after: bytes) -> None:
    old, new = _document(before), _document(after)
    # Do not turn an OAuth renewal into API billing or an account switch.
    for key in ('auth_mode', 'OPENAI_API_KEY'):
        equivalent = (key == 'auth_mode' and old.get(key) in (None, 'chatgpt')
                      and new.get(key) in (None, 'chatgpt'))
        if not equivalent and old.get(key) != new.get(key):
            raise PermissionError('Worker authentication route changed; owner recovery required')
    for data in (old, new):
        if 'tokens' in data and not isinstance(data['tokens'], dict):
            raise PermissionError('Invalid native authentication token object')
    if not old.get('tokens', {}).get('account_id'):
        raise PermissionError('Credential account identity is unavailable; owner recovery required')
    if old.get('tokens', {}).get('account_id') != new.get('tokens', {}).get('account_id'):
        raise PermissionError('Worker authentication account changed; owner recovery required')


class CredentialLease:
    """One configured source, one in-flight native client, no blind writeback."""

    def __init__(self, source: Path, target: Path):
        self.source, self.target = Path(source), Path(target)
        self.parent = self.lock = None
        self.pending = '.' + self.source.name + '.agentporter-pending.json'
        self.staged = False
        self.closed = False
        try:
            # Pin each directory without following an ancestor symlink.
            if not self.source.is_absolute() or '..' in self.source.parts:
                raise PermissionError('Credential source must be canonical')
            self.parent = os.open('/', _DIRECTORY)
            for part in self.source.parent.parts[1:]:
                child = os.open(part, _DIRECTORY, dir_fd=self.parent)
                os.close(self.parent)
                self.parent = child
            info = os.fstat(self.parent)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise PermissionError('Credential directory requires trusted owner custody')
            self.lock = os.open('.' + self.source.name + '.agentporter.lock',
                                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.parent)
            info = os.fstat(self.lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise PermissionError('Invalid credential lease lock')
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PermissionError('Credential account already has an active worker') from exc
            try:
                os.stat(self.pending, dir_fd=self.parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise PermissionError('Credential account has pending owner recovery')
            self.before = _read(self.parent, self.source.name)
            _document(self.before)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(self.before)
                stream.flush()
                os.fsync(stream.fileno())
            # Persist the location before any provider code can run. A crash
            # blocks the next launch until an owner reconciles the retained file.
            fd = os.open(self.pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.parent)
            with os.fdopen(fd, 'w') as stream:
                json.dump({'version': 1, 'worker_auth_path': str(target),
                           'original_sha256': hashlib.sha256(self.before).hexdigest()}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            self.staged = True
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def finish(self) -> None:
        """Called only after the entire native process group is stopped."""
        if self.closed:
            raise PermissionError('Credential lease is no longer held')
        temporary = None
        try:
            # Canonical path must still identify our pinned parent directory.
            now, pinned = self.source.parent.stat(), os.fstat(self.parent)
            if (now.st_dev, now.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise PermissionError('Credential source directory moved; owner recovery required')
            parent = os.open(self.target.parent, _DIRECTORY)
            try:
                result = _read(parent, self.target.name)
            finally:
                os.close(parent)
            current = _read(self.parent, self.source.name)
            if result != self.before:
                _same_account(self.before, result)
                if current not in (self.before, result):
                    raise PermissionError('Credential refresh conflict; owner recovery required')
                if current != result:
                    temporary = '.credential-rotation-' + uuid.uuid4().hex
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self.parent)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(result)
                        stream.flush()
                        os.fsync(stream.fileno())
                    # This CAS protects against a cooperating writer or a
                    # detected external update. Operators must also take the
                    # lease lock; arbitrary same-UID writers are not sandboxed.
                    if _read(self.parent, self.source.name) != current:
                        raise PermissionError('Credential refresh conflict; owner recovery required')
                    os.replace(temporary, self.source.name,
                               src_dir_fd=self.parent, dst_dir_fd=self.parent)
                    temporary = None
                    os.fsync(self.parent)
            os.unlink(self.pending, dir_fd=self.parent)
            os.fsync(self.parent)
            self.staged = False
        finally:
            if temporary is not None:
                os.unlink(temporary, dir_fd=self.parent)
            self.close()

    def close(self) -> None:
        """Release descriptors; a pending journal deliberately survives failure."""
        for key in ('lock', 'parent'):
            descriptor = getattr(self, key, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, key, None)
        self.closed = True
