"""Standalone offline relay security tests; no network, live credentials or services."""
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import ModuleType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
# The offline runner uses the distro Python 3.12 rather than the host's
# Python 3.13 venv. Avoid loading unrelated broker/Pydantic dependencies.
agents_pkg = ModuleType("agentporter.agents")
agents_pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "agentporter" / "agents")]
sys.modules["agentporter.agents"] = agents_pkg
from agentporter.agents.production_relay import (
    RelayLedger, ProductionDelegationClient, validate_dispatch,
    read_relay_key, relay_upstream_workspaces, read_relay_scope,
)


def denies(fn):
    try:
        fn()
    except (PermissionError, ValueError, OSError):
        return
    raise AssertionError("Expected fail-closed denial")


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    config = root / "config"
    config.mkdir(mode=0o700)
    token = "A" * 43
    token_path = config / "delegation-relay.key"
    token_path.write_text(token + "\n")
    token_path.chmod(0o600)
    assert read_relay_key(config) == token
    token_path.chmod(0o644)
    denies(lambda: read_relay_key(config))
    token_path.chmod(0o600)
    print("PASS: narrow relay key mode enforced")

    upstream = config / "delegation-upstream.yaml"
    upstream.write_text("version: 1\nhost: 127.0.0.1\nport: 8876\nworkspaces: [project-a, public-data]\n")
    upstream.chmod(0o600)
    assert relay_upstream_workspaces(config) == {"project-a", "public-data"}
    upstream.write_text("version: 1\nhost: attacker.invalid\nport: 8876\nworkspaces: [project-a]\n")
    denies(lambda: relay_upstream_workspaces(config))
    upstream.unlink()
    assert not relay_upstream_workspaces(config)
    print("PASS: explicit upstream loopback and workspace allowlist")
    scope_file = config / "delegation-relay-scope.yaml"
    scope_file.write_text("version: 1\nworkspaces:\n  project-a: /home/user/repos/project-a\n")
    scope_file.chmod(0o600)
    assert read_relay_scope(config) == {"project-a": "/home/user/repos/project-a"}
    scope_file.chmod(0o644)
    denies(lambda: read_relay_scope(config))
    scope_file.chmod(0o600)
    print("PASS: independent receiving-gateway workspace scope")

    allowed = {"project-a"}
    good = {"agent": "codex_research", "task": "audit", "workspace_id": "project-a", "read_only": True}
    validate_dispatch(good, allowed)
    for changed in (
        {"agent": "root"}, {"workspace_id": "public-data"}, {"allow_commit": True},
        {"allow_push": True}, {"read_only": False}, {"argv": ["/bin/sh"]},
        {"task": ""}, {"request_id": "wrong-key"},
    ):
        denies(lambda changed=changed: validate_dispatch({**good, **changed}, allowed))
    print("PASS: seven-agent identity, workspace, read-only and publication gates")

    ledger = RelayLedger(root)
    req = "a" * 32
    assert ledger.reserve(req, "project-a", "codex_research") is None
    assert ledger.reserve(req, "project-a", "codex_research") == (None, "project-a", "codex_research")
    denies(lambda: ledger.reserve(req, "other", "codex_research"))
    remote_id = "job_" + "b" * 24
    ledger.register(req, remote_id, "project-a", "codex_research")
    ledger.register(req, remote_id, "project-a", "codex_research")
    denies(lambda: ledger.register(req, "job_" + "c" * 24, "project-a", "codex_research"))
    assert RelayLedger(root).get_remote(remote_id) == ("project-a", "codex_research")
    print("PASS: durable relay job ownership and idempotency")

    class Response:
        status = 200
        def __init__(self, data): self.blob = json.dumps(data).encode()
        def read(self, n): return self.blob[:n]

    class FakeHTTP:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 8876, 8)
        def request(self, method, path, body, headers):
            assert method == "POST" and path == "/internal/delegation/v1"
            assert headers["Authorization"] == "Bearer " + token
            self.data = json.loads(body)
        def getresponse(self):
            op = self.data["operation"]
            if op == "workspace_info":
                return Response({"workspace_id": "project-a", "path": "/approved", "agent_dispatch": True, "security_profile": "provider_origin_v1"})
            if op == "dispatch_agent":
                return Response({"job_id": "job_" + "d" * 24, "status": "running"})
            return Response({"job_id": self.data["args"].get("job_id"), "status": "completed"})
        def close(self): pass

    with patch("agentporter.agents.production_relay.http.client.HTTPConnection", FakeHTTP):
        client = ProductionDelegationClient(token, {"project-a": "/approved"}, root)
        denies(lambda: client.call("job_status", {"job_id": "rjob_" + "e" * 32}))
        dispatched = client.call("dispatch_agent", good)
        assert dispatched["job_id"].startswith("rjob_")
        public = dispatched["job_id"]
        assert client.call("job_status", {"job_id": public})["job_id"] == public
        assert ProductionDelegationClient(token, {"project-a": "/approved"}, root).owns(public)
        print("PASS: authenticated, bounded relay protocol and restart-persistent public IDs")
        client.workspace_paths["project-a"] = "/different"
        denies(lambda: client.call("dispatch_agent", good))
        print("PASS: mismatched workspace roots fail closed")
        denies(lambda: client.call("job_cancel", {"job_id": public}))
        print("PASS: unsafe numeric-PID cancellation disabled")
# Real cross-instance SQLite reservation test (no sockets or external services).
with tempfile.TemporaryDirectory() as base:
    from concurrent.futures import ThreadPoolExecutor
    shared = Path(base)
    a, b = RelayLedger(shared), RelayLedger(shared)

    def reserve(item):
        try:
            return item[0].reserve(item[1], "project-a", "codex_research", max_active=1)
        except PermissionError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(reserve, [
            (a, "1" * 32), (b, "2" * 32),
        ]))
    assert outcomes.count(None) == 1 and outcomes.count("refused") == 1, outcomes
print("PASS: SQLite cross-instance concurrency admission is atomic")
# Rejected policy/model dispatch must not consume the three-job capacity.
with tempfile.TemporaryDirectory() as base:
    ledger = RelayLedger(Path(base))
    for count in range(1, 6):
        key = f"{count:032x}"
        assert ledger.reserve(key, "project-a", "codex_research", max_active=3) is None
        ledger.mark_no_launch(key)
        # The spent idempotency key remains reserved, but no longer active.
        assert ledger.reserve(key, "project-a", "codex_research", max_active=3) == (None, "project-a", "codex_research")
    with ledger._db() as db:
        assert db.execute("SELECT count(*) FROM jobs WHERE active=1").fetchone()[0] == 0
print("PASS: five rejected dispatches do not consume relay capacity")


# A dropped first response must retry the exact same idempotency key.
with tempfile.TemporaryDirectory() as base:
    seen = []
    class RetryHTTP(FakeHTTP):
        def request(self, method, path, body, headers):
            super().request(method, path, body, headers)
            if self.data["operation"] == "dispatch_agent":
                seen.append(self.data["args"]["request_id"])
        def getresponse(self):
            if self.data["operation"] == "dispatch_agent" and len(seen) == 1:
                raise ConnectionResetError("lost response")
            return super().getresponse()
    with patch("agentporter.agents.production_relay.http.client.HTTPConnection", RetryHTTP):
        client = ProductionDelegationClient(token, {"project-a": "/approved"}, Path(base))
        issued = client.call("dispatch_agent", good)
        assert issued["job_id"].startswith("rjob_")
        assert len(seen) == 2 and len(set(seen)) == 1, seen
print("PASS: lost reply retries same durable idempotency ID")

print("PASS: production delegation relay offline security tests")
