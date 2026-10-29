"""Offline Ed25519 approvals with exact scope and persistent retry binding.

Only the owner holds a private key. Services receive a public key and a private,
local ledger. Verification is an admission operation, never a polling operation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import unicodedata
import uuid
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_ACTIONS = {"dispatch_agent", "exec_run", "exec_start", "git_commit", "git_push", "destructive"}
_OPERATIONS = {"write", "delete", "commit", "push"}
_FIELDS = {"version", "grant_id", "workspace_id", "workspace_root", "action", "agent",
           "task_sha256", "arguments_sha256", "operations", "issued_at", "expires_at"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class ApprovalError(ValueError):
    """Approval is invalid or cannot safely be admitted."""


def _text(value: Any) -> bool:
    return (type(value) is str and bool(value) and unicodedata.normalize("NFC", value) == value
            and all(not unicodedata.category(c).startswith("C") for c in value))


def _json_value(value: Any) -> None:
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ApprovalError("Ambiguous Unicode")
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ApprovalError("JSON keys must be strings")
            _json_value(key)
            _json_value(item)
        return
    raise ApprovalError("Arguments must contain finite JSON values")


def _canonical(value: Any) -> bytes:
    try:
        _json_value(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise ApprovalError("Invalid canonical JSON") from exc


def clean_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Remove only transport metadata; callers must normalize defaults first."""
    if type(arguments) is not dict:
        raise ApprovalError("Arguments must be an object")
    return {k: v for k, v in arguments.items() if k not in {"approval_token", "request_id"}}


def canonical_arguments(arguments: dict[str, Any]) -> bytes:
    return _canonical(clean_arguments(arguments))


def hash_arguments(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_arguments(arguments)).hexdigest()


def _root(value: Any) -> str:
    if not _text(os.fspath(value)) or not Path(value).is_absolute():
        raise ApprovalError("Workspace root must be absolute")
    return str(Path(value).resolve())


def _task_hash(arguments: dict[str, Any], task: str | None) -> str | None:
    value = arguments.get("task") if task is None else task
    if value is None:
        return None
    if not _text(value):
        raise ApprovalError("Task must be unambiguous text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _claims_valid(claims: Any, max_lifetime: int) -> None:
    if type(claims) is not dict or set(claims) != _FIELDS:
        raise ApprovalError("Invalid grant schema")
    if type(claims["version"]) is not int or claims["version"] != 1:
        raise ApprovalError("Unsupported grant version")
    if type(claims["grant_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", claims["grant_id"]):
        raise ApprovalError("Invalid grant ID")
    if not _text(claims["workspace_id"]) or not _text(claims["action"]) or claims["action"] not in _ACTIONS:
        raise ApprovalError("Invalid workspace or action")
    root = claims["workspace_root"]
    if type(root) is not str or _root(root) != root:
        raise ApprovalError("Workspace root must be canonical")
    agent = claims["agent"]
    if agent is not None and not _text(agent):
        raise ApprovalError("Invalid agent")
    if claims["action"] == "dispatch_agent" and agent is None:
        raise ApprovalError("Dispatch approval requires an exact agent")
    for name in ("arguments_sha256", "task_sha256"):
        value = claims[name]
        if name == "task_sha256" and value is None and claims["action"] != "dispatch_agent":
            continue
        if type(value) is not str or not _HEX.fullmatch(value):
            raise ApprovalError("Invalid argument or task digest")
    ops = claims["operations"]
    if (type(ops) is not list or not ops or any(type(v) is not str or v not in _OPERATIONS for v in ops)
            or len(ops) != len(set(ops))):
        raise ApprovalError("Invalid operations")
    start, end = claims["issued_at"], claims["expires_at"]
    if type(start) is not int or type(end) is not int or start < 0 or not 0 < end - start <= max_lifetime:
        raise ApprovalError("Invalid grant lifetime")


def _lifetime(value: int) -> int:
    if type(value) is not int or not 0 < value <= 86400:
        raise ApprovalError("Maximum lifetime must be at most 24 hours")
    return value


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ApprovalError("Invalid token encoding")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ApprovalError("Invalid token encoding") from exc
    if _encode(decoded) != value:
        raise ApprovalError("Noncanonical token encoding")
    return decoded


def read_private_file(path: str | Path, *, owner_uid: int, limit: int = 1048576) -> bytes:
    """Read a bounded owned 0600 file without following symlinks."""
    path = Path(path)
    try:
        if path.parent.resolve() != path.parent.absolute():
            raise ApprovalError("Private file path must not contain symlinks")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ApprovalError("Private file must be owned and mode 0600")
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ApprovalError("Private file exceeds size limit")
        return raw
    except OSError as exc:
        raise ApprovalError("Cannot safely read private file") from exc


def load_private_key(path: str | Path, *, owner_uid: int = 0) -> Ed25519PrivateKey:
    """Owner-terminal use only; services must never receive this file."""
    raw = read_private_file(path, owner_uid=owner_uid, limit=16384)
    try:
        key = (Ed25519PrivateKey.from_private_bytes(raw) if len(raw) == 32
               else serialization.load_pem_private_key(raw, password=None))
    except (ValueError, TypeError) as exc:
        raise ApprovalError("Invalid private signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApprovalError("Ed25519 signing key required")
    return key


def sign_grant(private_key: Ed25519PrivateKey | bytes, *, workspace_id: str,
               workspace_root: str | Path, action: str, arguments: dict[str, Any],
               operations: list[str], expires_at: int, agent: str | None = None,
               task: str | None = None, issued_at: int | None = None,
               grant_id: str | None = None, max_lifetime_seconds: int = 3600) -> str:
    """Issue offline; private key custody and explicit owner approval are external."""
    if isinstance(private_key, bytes):
        try:
            private_key = (Ed25519PrivateKey.from_private_bytes(private_key) if len(private_key) == 32
                           else serialization.load_pem_private_key(private_key, password=None))
        except (ValueError, TypeError) as exc:
            raise ApprovalError("Invalid signing key") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ApprovalError("Ed25519 signing key required")
    claims = dict(version=1, grant_id=grant_id if grant_id is not None else uuid.uuid4().hex,
                  workspace_id=workspace_id, workspace_root=_root(workspace_root), action=action,
                  agent=agent, task_sha256=_task_hash(arguments, task), arguments_sha256=hash_arguments(arguments),
                  operations=operations, issued_at=int(time.time()) if issued_at is None else issued_at,
                  expires_at=expires_at)
    _claims_valid(claims, _lifetime(max_lifetime_seconds))
    payload = _canonical(claims)
    token = _encode(payload) + "." + _encode(private_key.sign(payload))
    if len(token) > 8192:
        raise ApprovalError("Grant exceeds token limit")
    return token


@dataclass(frozen=True)
class VerifiedGrant:
    claims: dict[str, Any]

    @property
    def grant_id(self) -> str:
        return self.claims["grant_id"]


class ApprovalVerifier:
    def __init__(self, public_key: Ed25519PublicKey | bytes, ledger_path: str | Path, *,
                 clock: Callable[[], float] = time.time, max_lifetime_seconds: int = 3600):
        if isinstance(public_key, bytes):
            try:
                public_key = (Ed25519PublicKey.from_public_bytes(public_key) if len(public_key) == 32
                              else serialization.load_pem_public_key(public_key))
            except (ValueError, TypeError) as exc:
                raise ApprovalError("Invalid verification key") from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise ApprovalError("Ed25519 verification key required")
        self.public_key = public_key
        self.ledger_path = Path(ledger_path)
        self.clock = clock
        self.max_lifetime_seconds = _lifetime(max_lifetime_seconds)

    def verify(self, token: str, *, workspace_id: str, workspace_root: str | Path,
               action: str, arguments: dict[str, Any], request_id: str,
               required_operations: set[str] | list[str], agent: str | None = None,
               task: str | None = None) -> VerifiedGrant:
        try:
            return self._verify(token, workspace_id=workspace_id, workspace_root=workspace_root,
                                action=action, arguments=arguments, request_id=request_id,
                                required_operations=required_operations, agent=agent, task=task)
        except (OSError, sqlite3.Error, TypeError, KeyError, RecursionError, UnicodeError) as exc:
            raise ApprovalError("Approval could not be safely verified") from exc

    def _verify(self, token: str, **scope: Any) -> VerifiedGrant:
        if type(token) is not str or not token.isascii() or len(token) > 8192 or token.count(".") != 1:
            raise ApprovalError("Invalid token")
        payload_part, signature_part = token.split(".")
        payload, signature = _decode(payload_part), _decode(signature_part)
        try:
            self.public_key.verify(signature, payload)
        except InvalidSignature as exc:
            raise ApprovalError("Invalid approval signature") from exc

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ApprovalError("Duplicate grant field")
                result[key] = value
            return result

        try:
            claims = json.loads(payload, object_pairs_hook=unique)
        except (ValueError, UnicodeError) as exc:
            raise ApprovalError("Invalid grant JSON") from exc
        _claims_valid(claims, self.max_lifetime_seconds)
        if payload != _canonical(claims):
            raise ApprovalError("Grant JSON must be canonical")
        if not claims["issued_at"] <= self.clock() < claims["expires_at"]:
            raise ApprovalError("Grant has expired or is not yet valid")
        if not _text(scope["request_id"]):
            raise ApprovalError("Request ID required")
        required = scope["required_operations"]
        if type(required) not in (set, list, frozenset) or any(type(v) is not str or v not in _OPERATIONS for v in required):
            raise ApprovalError("Invalid required operations")
        expected = dict(workspace_id=scope["workspace_id"], workspace_root=_root(scope["workspace_root"]),
                        action=scope["action"], agent=scope["agent"],
                        task_sha256=_task_hash(scope["arguments"], scope["task"]),
                        arguments_sha256=hash_arguments(scope["arguments"]))
        if any(claims[k] != v for k, v in expected.items()) or not set(required).issubset(claims["operations"]):
            raise ApprovalError("Approval scope does not match request")
        self._bind(claims["grant_id"], scope["request_id"], hashlib.sha256(payload).hexdigest())
        return VerifiedGrant(claims)

    def _bind(self, grant_id: str, request_id: str, scope_digest: str) -> None:
        path = self.ledger_path
        parent = path.parent
        if parent.is_symlink() or parent.resolve() != parent.absolute():
            raise ApprovalError("Ledger directory must not contain symlinks")
        info = parent.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ApprovalError("Ledger directory must be private and owned by service")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ApprovalError("Ledger must be an owned private regular file")
        finally:
            os.close(fd)
        with closing(sqlite3.connect(path, timeout=10)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS approvals (grant_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, scope_digest TEXT NOT NULL)")
            row = db.execute("SELECT request_id, scope_digest FROM approvals WHERE grant_id = ?", (grant_id,)).fetchone()
            if row is not None and row != (request_id, scope_digest):
                raise ApprovalError("Approval already bound to another request or scope")
            if row is None:
                db.execute("INSERT INTO approvals VALUES (?, ?, ?)", (grant_id, request_id, scope_digest))
