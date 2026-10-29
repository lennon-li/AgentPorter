"""Fail-closed production-to-isolated-worker delegation relay.

Only seven named agents and registered workspace IDs are admitted. The gateway
accepts a dedicated, private relay key distinct from its general API key.
No generic shell, filesystem, Git, networking or privileged tool is exposed.
"""
from __future__ import annotations

import hmac
import http.client
import json
import os
import re
import stat
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

import yaml

from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.scoped_https import ScopedPublicHTTPSPolicy

JOB_RE = re.compile(r"job_[0-9a-f]{24}\Z")
MAX_TASK = 24_000
MAX_REQUEST = 32_768
MAX_RESPONSE = 524_288
ALLOWED_OPS = frozenset(("list_agents", "workspace_info", "dispatch_agent", "job_status", "job_output", "job_result", "lookup_dispatch"))
RECEIVING_SECURITY_PROFILE = "provider_origin_v1"
DEFAULT_TIMEOUT = 8
INVENTORY_TIMEOUT = 90  # measured healthy inventory responses take 43-46s
# Receiving gateway validates confined inventory before launch; healthy
# admission measured 33-58s. Bounds admission only, not job execution.
DISPATCH_ADMISSION_TIMEOUT = 90
OPERATION_TIMEOUTS = {"list_agents": INVENTORY_TIMEOUT, "dispatch_agent": DISPATCH_ADMISSION_TIMEOUT}


class RelayLedger:
    """Private durable mapping of relay-issued jobs to one relay principal.

    The gateway is single-process and dispatch operations are serialized by
    the ledger lock. Unknown IDs never trigger arbitrary local job lookups.
    """

    def __init__(self, state_dir: Path):
        self.lock = threading.RLock()
        root = Path(state_dir)
        if not root.is_dir():
            raise PermissionError("Relay job state directory missing")
        self.path = root / "delegation-relay-jobs.sqlite"
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                request_id TEXT PRIMARY KEY, remote_id TEXT UNIQUE,
                workspace_id TEXT NOT NULL, agent TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            if "active" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

    @contextmanager
    def _db(self):
        connection = sqlite3.connect(str(self.path), timeout=3)
        try:
            os.chmod(self.path, 0o600)
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def validate_request_id(value):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
            raise PermissionError("Invalid relay idempotency key")
        return value

    def get_request(self, request_id):
        self.validate_request_id(request_id)
        with self.lock, self._db() as db:
            row = db.execute("SELECT remote_id, workspace_id, agent FROM jobs WHERE request_id=?", (request_id,)).fetchone()
        return row

    def get_remote(self, remote_id):
        if not isinstance(remote_id, str) or not JOB_RE.fullmatch(remote_id):
            raise PermissionError("Invalid remote job reference")
        with self.lock, self._db() as db:
            return db.execute("SELECT workspace_id, agent FROM jobs WHERE remote_id=?", (remote_id,)).fetchone()

    def reserve(self, request_id, workspace_id, agent, *, max_active=None):
        """Atomic cross-process reservation; only creator may launch a worker."""
        self.validate_request_id(request_id)
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT remote_id, workspace_id, agent FROM jobs WHERE request_id=?",
                (request_id,)).fetchone()
            if existing:
                if (existing[1], existing[2]) != (workspace_id, agent):
                    raise PermissionError("Relay idempotency request changed scope")
                return existing
            if max_active is not None:
                count = db.execute("SELECT count(*) FROM jobs WHERE active=1").fetchone()[0]
                if count >= max_active:
                    raise PermissionError("Relay concurrency limit reached")
            db.execute(
                "INSERT INTO jobs (request_id, remote_id, workspace_id, agent, active) VALUES (?, NULL, ?, ?, 1)",
                (request_id, workspace_id, agent))
            return None

    def active_jobs(self):
        with self.lock, self._db() as db:
            return db.execute("SELECT remote_id FROM jobs WHERE active=1 AND remote_id IS NOT NULL").fetchall()

    def mark_terminal(self, remote_id):
        with self.lock, self._db() as db:
            db.execute("UPDATE jobs SET active=0 WHERE remote_id=?", (remote_id,))

    def mark_no_launch(self, request_id):
        """Release capacity only after a verified policy/input rejection.

        Do not erase the reservation: the stable idempotency key remains
        spent and can never create a duplicate worker after a retry.
        """
        self.validate_request_id(request_id)
        with self.lock, self._db() as db:
            db.execute(
                "UPDATE jobs SET active=0 WHERE request_id=? AND remote_id IS NULL",
                (request_id,),
            )

    def register(self, request_id, remote_id, workspace_id, agent):
        self.validate_request_id(request_id)
        if not JOB_RE.fullmatch(remote_id):
            raise PermissionError("Invalid backend job ID")
        with self.lock, self._db() as db:
            existing = db.execute("SELECT remote_id, workspace_id, agent FROM jobs WHERE request_id=?", (request_id,)).fetchone()
            if existing:
                if (existing[1], existing[2]) != (workspace_id, agent):
                    raise PermissionError("Relay idempotency collision")
                if existing[0] is None:
                    db.execute("UPDATE jobs SET remote_id=? WHERE request_id=?",
                               (remote_id, request_id))
                elif existing[0] != remote_id:
                    raise PermissionError("Relay idempotency collision")
                return
            db.execute("INSERT INTO jobs (request_id, remote_id, workspace_id, agent, active) VALUES (?, ?, ?, ?, 1)",
                       (request_id, remote_id, workspace_id, agent))


def read_relay_key(config_dir: Path) -> str | None:
    """Operator-installed 0600 token; absence means the relay is disabled."""
    parent = ScopedPublicHTTPSPolicy._open_trusted_directory(
        Path(os.path.abspath(config_dir)))
    if parent is None:
        return None
    try:
        try:
            fd = os.open("delegation-relay.key", os.O_RDONLY | os.O_NOFOLLOW,
                         dir_fd=parent)
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)
    try:
        mode = os.fstat(fd)
        if (not stat.S_ISREG(mode.st_mode) or mode.st_uid not in (os.getuid(), 0)
                or mode.st_mode & 0o077 or mode.st_size > 128):
            raise PermissionError("Delegation relay key must be owner-owned mode 0600")
        token = os.read(fd, 129).decode("ascii")
    finally:
        os.close(fd)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,96}\n?", token):
        raise PermissionError("Delegation relay key is not a valid generated secret")
    return token.strip()


def read_relay_scope(config_dir: Path) -> dict[str, str]:
    """Gateway-side operator allowlist; cannot be expanded by a relay client."""
    parent = ScopedPublicHTTPSPolicy._open_trusted_directory(
        Path(os.path.abspath(config_dir)))
    if parent is None:
        return {}
    try:
        try:
            fd = os.open("delegation-relay-scope.yaml",
                         os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            return {}
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o077 or info.st_size > 4096):
            raise PermissionError("Relay scope must be operator-owned private file")
        from agentporter.action_policy import _UniqueKeysLoader
        doc = yaml.load(os.read(fd, 4097), Loader=_UniqueKeysLoader)
    finally:
        os.close(fd)
    from agentporter.workspace_policy import shared_policy_reference
    policy = shared_policy_reference(doc)
    if policy is not None:
        return {name: row["path"] for name, row in policy.workspaces.items()
                if policy.capabilities(name)["agent_dispatch"]}
    if (not isinstance(doc, dict) or set(doc) != {"version", "workspaces"}
            or type(doc["version"]) is not int or doc["version"] != 1
            or not isinstance(doc["workspaces"], dict)
            or not 1 <= len(doc["workspaces"]) <= 32):
        raise PermissionError("Invalid operator-approved relay scope")
    scopes = doc["workspaces"]
    for name, location in scopes.items():
        if (not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
                or not isinstance(location, str)
                or not location.startswith("/")
                or os.path.normpath(location) != location
                or "\x00" in location):
            raise PermissionError("Invalid relay workspace root")
    return dict(scopes)


def relay_upstream_workspaces(config_dir: Path) -> frozenset[str]:
    parent = ScopedPublicHTTPSPolicy._open_trusted_directory(
        Path(os.path.abspath(config_dir)))
    if parent is None:
        return frozenset()
    try:
        try:
            fd = os.open("delegation-upstream.yaml", os.O_RDONLY | os.O_NOFOLLOW,
                         dir_fd=parent)
        except FileNotFoundError:
            return frozenset()
    finally:
        os.close(parent)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid not in (os.getuid(), 0) or s.st_mode & 0o077:
            raise PermissionError("Relay upstream configuration must be owner-owned mode 0600")
        if s.st_size > 1024:
            raise ValueError("Relay upstream configuration oversized")
        doc = yaml.safe_load(os.read(fd, 1025))
    finally:
        os.close(fd)
    from agentporter.workspace_policy import shared_policy_reference
    policy = shared_policy_reference(doc)
    if policy is not None:
        return frozenset(name for name in policy.workspaces
                         if policy.capabilities(name)["agent_dispatch"])
    if (not isinstance(doc, dict) or set(doc) != {"version", "host", "port", "workspaces"}
            or type(doc["version"]) is not int or doc["version"] != 1
            or doc["host"] != "127.0.0.1" or type(doc["port"]) is not int
            or doc["port"] != 8876):
        raise PermissionError("Relay upstream must name the fixed local isolated gateway")
    workspaces = doc["workspaces"]
    if (not isinstance(workspaces, list) or not 1 <= len(workspaces) <= 32
            or not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", x)
                       for x in workspaces) or len(set(workspaces)) != len(workspaces)):
        raise PermissionError("Relay upstream workspaces must be an explicit unique allowlist")
    return frozenset(workspaces)


def normalize_dispatch(data: dict) -> dict:
    """Canonical defaults shared by the approval issuer and both relay endpoints."""
    return {"purpose": "", "model": None, "reasoning_effort": None,
            "allow_commit": False, "allow_push": False, "read_only": True, **data}


def validate_dispatch(data: dict, workspace_ids: set[str], *, approval_verifier=None,
                      workspace_paths=None) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Relay payload must be an object")
    permitted = {"agent", "task", "workspace_id", "purpose", "model", "reasoning_effort",
                 "allow_commit", "allow_push", "read_only", "request_id", "approval_token"}
    if set(data) - permitted:
        raise PermissionError("Unexpected delegation relay argument")
    data = normalize_dispatch(data)
    agent = data.get("agent")
    workspace = data.get("workspace_id")
    task = data.get("task")
    if agent not in PUBLIC_AGENT_IDS or workspace not in workspace_ids:
        raise PermissionError("Agent/workspace outside delegation relay scope")
    if not isinstance(task, str) or not 1 <= len(task) <= MAX_TASK:
        raise PermissionError("Invalid relay task")
    if "request_id" in data:
        RelayLedger.validate_request_id(data["request_id"])
    if any(type(data[key]) is not bool for key in ("allow_commit", "allow_push", "read_only")):
        raise PermissionError("Relay permission flags must be booleans")
    if data.get("allow_commit") or data.get("allow_push"):
        raise PermissionError("Relay never permits Git publication")
    for key in ("purpose", "model", "reasoning_effort"):
        value = data.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 512):
            raise PermissionError("Invalid relay metadata")
    token = data.get("approval_token")
    if "approval_token" in data and (not isinstance(token, str) or not 1 <= len(token) <= 8192):
        raise PermissionError("Invalid relay approval token")
    if not data["read_only"]:
        if (approval_verifier is None or not token or "request_id" not in data
                or not isinstance(workspace_paths, dict) or workspace not in workspace_paths):
            raise PermissionError("Writable delegation requires an independent task approval")
        approval_verifier.verify(token, workspace_id=workspace,
            workspace_root=workspace_paths[workspace], action="dispatch_agent", arguments=data,
            request_id=data["request_id"], required_operations={"write"}, agent=agent, task=task)
    return {**data, "agent": agent, "workspace_id": workspace, "allow_commit": False,
            "allow_push": False, "read_only": data.get("read_only", True)}


def validate_job_request(data: dict) -> str:
    if set(data) - {"job_id", "cursor", "max_bytes"} or not JOB_RE.fullmatch(data.get("job_id", "")):
        raise PermissionError("Invalid relay job reference")
    if type(data.get("cursor", 0)) is not int or not 0 <= data.get("cursor", 0) <= 100_000_000:
        raise PermissionError("Invalid relay cursor")
    if type(data.get("max_bytes", 65536)) is not int or not 1 <= data.get("max_bytes", 65536) <= 65536:
        raise PermissionError("Invalid relay output size")
    return data["job_id"]


class ProductionDelegationClient:
    """Fixed TCP loopback + purpose-specific credential, no HTTP proxy or redirects."""

    def __init__(self, token: str, workspace_paths: dict[str, str], state_dir: Path, port: int = 8876,
                 *, approval_verifier=None):
        if not token or port != 8876:
            raise PermissionError("Invalid relay configuration")
        self.token = token
        self.approval_verifier = approval_verifier
        self.workspace_paths = dict(workspace_paths)
        self.workspace_ids = frozenset(workspace_paths)
        self.ledger = RelayLedger(state_dir)

    def owns(self, public_id):
        if not isinstance(public_id, str) or not re.fullmatch(r"rjob_[0-9a-f]{32}", public_id):
            return False
        record = self.ledger.get_request(public_id.removeprefix("rjob_"))
        return bool(record)

    def call(self, operation: str, data: dict | None = None) -> dict | list:
        if operation not in ALLOWED_OPS:
            raise PermissionError("Unsupported relay operation")
        data = dict(data or {})
        request_id = None
        if operation == "dispatch_agent":
            data = validate_dispatch(data, set(self.workspace_ids),
                approval_verifier=self.approval_verifier, workspace_paths=self.workspace_paths)
            # A shared ID alone is not authority: verify both gateway
            # registries bind that ID to the SAME absolute workspace root.
            remote = self.call("workspace_info", {"workspace_id": data["workspace_id"]})
            if (not isinstance(remote, dict)
                    or remote.get("workspace_id") != data["workspace_id"]
                    or not remote.get("agent_dispatch")
                    or remote.get("path") != self.workspace_paths[data["workspace_id"]]):
                raise PermissionError("Production/development workspace mapping mismatch")
            if remote.get("security_profile") != RECEIVING_SECURITY_PROFILE:
                raise PermissionError("Receiving gateway lacks reviewed production egress; delegation refused")
            if not data["read_only"] and remote.get("writable") is not True:
                raise PermissionError("Receiving workspace does not permit approved writes")
            request_id = uuid.uuid4().hex if data["read_only"] else data["request_id"]
            data["request_id"] = request_id
            self.ledger.reserve(request_id, data["workspace_id"], data["agent"])
        elif operation == "lookup_dispatch":
            if set(data) != {"request_id"}:
                raise PermissionError("Invalid relay lookup")
            RelayLedger.validate_request_id(data["request_id"])
        elif operation == "workspace_info":
            if set(data) != {"workspace_id"} or data["workspace_id"] not in self.workspace_ids:
                raise PermissionError("Unknown production workspace mapping")
        elif operation in {"job_status", "job_output", "job_result"}:
            public_id = data.get("job_id", "")
            if not self.owns(public_id):
                raise PermissionError("Unknown remote job ID, not issued to production relay")
            request_id = public_id.removeprefix("rjob_")
            row = self.ledger.get_request(request_id)
            if row[0] is None:
                recovery = self.call("lookup_dispatch", {"request_id": request_id})
                recovered = recovery.get("job_id") if isinstance(recovery, dict) else None
                if recovered and JOB_RE.fullmatch(recovered):
                    self.ledger.register(request_id, recovered, row[1], row[2])
                    row = self.ledger.get_request(request_id)
                else:
                    return {"job_id": public_id, "status": "delivery_uncertain",
                            "message": "No confirmed remote job yet; retry status"}
            data["job_id"] = row[0]
            if operation in {"job_output", "job_result"}:
                data["max_bytes"] = min(data.get("max_bytes", 65536), 32768)
            validate_job_request(data)
        raw = json.dumps({"operation": operation, "args": data}, separators=(",", ":")).encode()
        if len(raw) > MAX_REQUEST:
            raise PermissionError("Relay request too large")
        for attempt in range(2 if operation == "dispatch_agent" else 1):
            connection = http.client.HTTPConnection(
                "127.0.0.1", 8876, timeout=OPERATION_TIMEOUTS.get(operation, DEFAULT_TIMEOUT))
            try:
                connection.request(
                    "POST", "/internal/delegation/v1", body=raw,
                    headers={"Authorization": "Bearer " + self.token,
                             "Content-Type": "application/json", "Content-Length": str(len(raw)),
                             "Connection": "close"},
                )
                response = connection.getresponse()
                blob = response.read(MAX_RESPONSE + 1)
                if len(blob) > MAX_RESPONSE:
                    raise ValueError("Relay reply oversized")
                if response.status != 200:
                    raise PermissionError(f"Isolated delegation relay rejected request ({response.status})")
                value = json.loads(blob)
                if not isinstance(value, (list, dict)):
                    raise ValueError("Relay response invalid")
                break
            except (OSError, http.client.HTTPException) as exc:
                if attempt == 0 and operation == "dispatch_agent":
                    continue
                if operation == "dispatch_agent":
                    return {"job_id": "rjob_" + request_id,
                            "dispatch_id": "rjob_" + request_id,
                            "status": "delivery_uncertain",
                            "message": "Transport failed; check status before resubmitting"}
                raise ConnectionError("Isolated relay unreachable") from exc
            finally:
                connection.close()
        if operation == "dispatch_agent":
            job_id = value.get("job_id")
            if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id):
                raise ValueError("Relay did not return a valid job reference")
            self.ledger.register(request_id, job_id, data["workspace_id"], data["agent"])
            value = {**value, "job_id": "rjob_" + request_id, "dispatch_id": "rjob_" + request_id}
        elif operation in {"job_status", "job_output", "job_result"}:
            value["job_id"] = "rjob_" + request_id
        return value
