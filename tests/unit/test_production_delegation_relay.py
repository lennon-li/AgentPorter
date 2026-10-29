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


def test_production_relay_refuses_legacy_unscoped_client_policy(temp_config, monkeypatch):
    """Enabling a relay must not turn legacy broad client access into production delegation."""
    import agentporter.server as server
    monkeypatch.setattr(server, "relay_upstream_workspaces", lambda _: frozenset({"PAGe"}))
    with pytest.raises(PermissionError, match="requires an explicit public-client policy"):
        server.build_mcp_server(temp_config)


def test_explicit_empty_client_policy_does_not_bypass_relay_key(temp_config, monkeypatch):
    import agentporter.server as server
    policy = temp_config.config_dir / "public-client-policy.yaml"
    policy.write_text("version: 1\nworkspaces: {}\n")
    policy.chmod(0o600)
    monkeypatch.setattr(server, "relay_upstream_workspaces", lambda _: frozenset({"PAGe"}))
    monkeypatch.setattr(server, "read_relay_key", lambda _: None)
    with pytest.raises(PermissionError, match="without dedicated relay key"):
        server.build_mcp_server(temp_config)


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


def test_relay_writes_require_explicit_separate_grant():
    data = {"agent": "prof", "workspace_id": "PAGe", "task": "edit", "read_only": False}
    with pytest.raises(PermissionError):
        validate_dispatch(data, {"PAGe"})
    assert validate_dispatch(data, {"PAGe"}, write_workspace_ids=frozenset({"PAGe"}))["read_only"] is False
    for bad in (0, None, "false"):
        with pytest.raises(PermissionError):
            validate_dispatch({**data, "read_only": bad}, {"PAGe"}, write_workspace_ids=frozenset({"PAGe"}))
    with pytest.raises(PermissionError):
        validate_dispatch({**data, "allow_push": True}, {"PAGe"}, write_workspace_ids=frozenset({"PAGe"}))


def test_write_scope_is_separate_private_file(tmp_path):
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    assert read_relay_scope(config, writable=True) == {}
    path = config / "delegation-relay-write-scope.yaml"
    path.write_text("version: 1\nworkspaces:\n  PAGe: /home/yeli/repos/PAGe\n")
    path.chmod(0o600)
    assert read_relay_scope(config, writable=True) == {"PAGe": "/home/yeli/repos/PAGe"}
    assert read_relay_scope(config) == {}
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        read_relay_scope(config, writable=True)


def test_writable_relay_requires_matching_scope_and_worker_handshake(tmp_path, monkeypatch):
    from agentporter.agents import production_relay as relay
    with pytest.raises(PermissionError):
        ProductionDelegationClient("token", {"PAGe": "/approved"}, tmp_path,
                                   write_workspace_paths={"PAGe": "/different"})

    observed = []
    handshake = {"workspace_id": "PAGe", "path": "/approved", "agent_dispatch": True,
                 "security_profile": relay.RECEIVING_SECURITY_PROFILE}

    class Response:
        status = 200
        def __init__(self, value): self.value = value
        def read(self, size): return json.dumps(self.value).encode()

    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, method, path, body, headers): self.message = json.loads(body)
        def getresponse(self):
            observed.append(self.message["operation"])
            if self.message["operation"] == "workspace_info":
                return Response(handshake)
            return Response({"job_id": "job_" + "d" * 24, "status": "running"})
        def close(self): pass

    monkeypatch.setattr(relay.http.client, "HTTPConnection", Connection)
    client = ProductionDelegationClient("token", {"PAGe": "/approved"}, tmp_path,
                                        write_workspace_paths={"PAGe": "/approved"})
    request = {"agent": "phil", "workspace_id": "PAGe", "task": "edit", "read_only": False}
    with pytest.raises(PermissionError, match="transactional writable"):
        client.call("dispatch_agent", request)
    assert observed == ["workspace_info"]
    handshake["writable_transactions"] = True
    result = client.call("dispatch_agent", request)
    assert result["job_id"].startswith("rjob_")
    assert observed == ["workspace_info", "workspace_info", "dispatch_agent"]


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
