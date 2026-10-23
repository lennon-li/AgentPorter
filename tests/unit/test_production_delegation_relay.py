"""Production relay must never inherit the general AgentPorter API authority."""
import asyncio
import json
from pathlib import Path

import pytest
from agentporter.agents.production_relay import (
    ProductionDelegationClient, RelayLedger, read_relay_key,
    relay_upstream_workspaces, read_relay_scope, validate_dispatch,
)
from agentporter.middleware import SecurityMiddleware


@pytest.mark.parametrize("changed", [
    {"read_only": False},
    {"allow_commit": True},
    {"allow_push": True},
    {"agent": "codex"},
    {"workspace_id": "not-registered"},
    {"task": ""},
    {"argv": ["sh", "-c", "id"]},
])
def test_relay_rejects_scope_escalation(changed):
    data = {"agent": "prof", "workspace_id": "PAGe", "task": "audit", "read_only": True}
    data.update(changed)
    with pytest.raises(PermissionError):
        validate_dispatch(data, {"PAGe"})


def test_durable_relay_owner_and_pending_block_duplicate(tmp_path):
    ledger = RelayLedger(tmp_path)
    key = "a" * 32
    assert ledger.reserve(key, "PAGe", "prof") is None
    assert ledger.reserve(key, "PAGe", "prof") == (None, "PAGe", "prof")
    with pytest.raises(PermissionError):
        ledger.reserve(key, "m3", "prof")
    job = "job_" + "b" * 24
    ledger.register(key, job, "PAGe", "prof")
    ledger2 = RelayLedger(tmp_path)
    assert ledger2.get_request(key) == (job, "PAGe", "prof")
    assert ledger2.get_remote(job) == ("PAGe", "prof")
    with pytest.raises(PermissionError):
        ledger2.register(key, "job_" + "c" * 24, "PAGe", "prof")


def test_rejected_dispatches_preserve_retry_identity_without_leaking_capacity(tmp_path):
    ledger = RelayLedger(tmp_path)
    for index in range(1, 6):
        key = f"{index:032x}"
        assert ledger.reserve(key, "PAGe", "prof", max_active=3) is None
        ledger.mark_no_launch(key)
        # The idempotency token stays consumed: retries cannot launch again.
        assert ledger.reserve(key, "PAGe", "prof", max_active=3) == (None, "PAGe", "prof")
    with ledger._db() as db:
        assert db.execute("SELECT count(*) FROM jobs WHERE active=1").fetchone()[0] == 0


def test_operator_config_required_private(tmp_path):
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    assert read_relay_key(config) is None
    assert not relay_upstream_workspaces(config)
    token = config / "delegation-relay.key"
    token.write_text("x" * 43 + "\n")
    token.chmod(0o644)
    with pytest.raises(PermissionError):
        read_relay_key(config)
    token.chmod(0o600)
    assert read_relay_key(config) == "x" * 43


def test_gateway_relay_workspace_scope_private(tmp_path):
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    assert read_relay_scope(config) == {}
    path = config / "delegation-relay-scope.yaml"
    path.write_text("version: 1\nworkspaces:\n  PAGe: /home/yeli/repos/PAGe\n")
    path.chmod(0o600)
    assert read_relay_scope(config) == {"PAGe": "/home/yeli/repos/PAGe"}
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        read_relay_scope(config)


def test_relay_key_is_not_general_api_key():
    normal_key = "normal-gateway-token"
    relay_key = "special-relay-token"
    called = []

    async def downstream(scope, receive, send):
        called.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    auth = SecurityMiddleware(
        downstream, api_key=normal_key,
        allowed_hosts=["127.0.0.1", "127.0.0.1:*"],
        delegation_relay_key=relay_key,
    )

    async def request(path, authorization, client_ip="127.0.0.1", method="POST"):
        statuses = []
        scope = {"type": "http", "path": path, "method": method,
                 "client": (client_ip, 54321),
                 "headers": [(b"host", b"127.0.0.1:8876"),
                             (b"authorization", authorization.encode())]}
        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}
        async def send(event):
            if event["type"] == "http.response.start":
                statuses.append(event["status"])
        await auth(scope, receive, send)
        return statuses[0]

    assert asyncio.run(request("/internal/delegation/v1", "Bearer " + normal_key)) == 401
    assert asyncio.run(request("/internal/delegation/v1", "Bearer " + relay_key, "8.8.8.8")) == 401
    assert asyncio.run(request("/internal/delegation/v1", "Bearer " + relay_key)) == 200
    assert asyncio.run(request("/api/v1/workspaces", "Bearer " + relay_key)) == 401
    assert asyncio.run(request("/api/v1/workspaces", "Bearer " + normal_key)) == 200
    assert called == ["/internal/delegation/v1", "/api/v1/workspaces"]
