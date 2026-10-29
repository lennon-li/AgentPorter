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
    path.write_text("version: 1\nworkspaces:\n  PAGe: /home/operator/repos/PAGe\n")
    path.chmod(0o600)
    assert read_relay_scope(config) == {"PAGe": "/home/operator/repos/PAGe"}
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


class _FakeConnection:
    timeouts = []
    operations = []

    def __init__(self, host, port, timeout=None):
        self.timeouts.append(timeout)

    def request(self, method, path, body=None, headers=None):
        self.operations.append(json.loads(body)["operation"])

    def getresponse(self):
        operation = self.operations[-1]
        payload = {"list_agents": [], "workspace_info": {"workspace_id": "PAGe", "path": "/w/PAGe",
                                                           "agent_dispatch": True,
                                                           "security_profile": "provider_origin_v1"},
                   "dispatch_agent": {"job_id": "job_" + "b" * 24}}.get(operation, {"status": "running"})

        class Response:
            status = 200

            @staticmethod
            def read(_limit):
                return json.dumps(payload).encode()
        return Response()

    def close(self):
        pass


def _client(tmp_path, monkeypatch):
    import agentporter.agents.production_relay as relay
    _FakeConnection.timeouts, _FakeConnection.operations = [], []
    monkeypatch.setattr(relay.http.client, "HTTPConnection", _FakeConnection)
    return ProductionDelegationClient("t" * 40, {"PAGe": "/w/PAGe"}, tmp_path)


def test_inventory_uses_bounded_ninety_second_timeout(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.call("list_agents") == []
    assert _FakeConnection.timeouts == [90]


def test_job_and_workspace_operations_keep_eight_second_timeout(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.call("workspace_info", {"workspace_id": "PAGe"})
    result = client.call("dispatch_agent", {"agent": "prof", "workspace_id": "PAGe", "task": "audit", "read_only": True})
    client.call("job_status", {"job_id": result["job_id"]})
    assert _FakeConnection.operations == ["workspace_info", "workspace_info", "dispatch_agent", "job_status"]
    assert _FakeConnection.timeouts == [8, 8, 90, 8]


class _SlowGateway:
    """Simulated gateway: a call times out when its latency exceeds the client's socket timeout."""
    latency = {}
    attempts = []

    def __init__(self, host, port, timeout=None):
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        self.operation = json.loads(body)["operation"]
        self.attempts.append(self.operation)

    def getresponse(self):
        if self.latency.get(self.operation, 0) > self.timeout:
            raise TimeoutError("simulated socket timeout")
        return _FakeConnection.getresponse(self)

    def close(self):
        pass


def _slow_client(tmp_path, monkeypatch, latency):
    import agentporter.agents.production_relay as relay
    _SlowGateway.latency, _SlowGateway.attempts = latency, []
    _SlowGateway.operations = _SlowGateway.attempts
    monkeypatch.setattr(relay.http.client, "HTTPConnection", _SlowGateway)
    return ProductionDelegationClient("t" * 40, {"PAGe": "/w/PAGe"}, tmp_path)


DISPATCH = {"agent": "prof", "workspace_id": "PAGe", "task": "audit", "read_only": True}


def test_delayed_admission_beyond_eight_seconds_succeeds_with_single_delivery(tmp_path, monkeypatch):
    client = _slow_client(tmp_path, monkeypatch, {"dispatch_agent": 58})
    result = client.call("dispatch_agent", dict(DISPATCH))
    assert result.get("status") != "delivery_uncertain"
    assert result["job_id"] == result["dispatch_id"] and result["job_id"].startswith("rjob_")
    assert _SlowGateway.attempts.count("dispatch_agent") == 1
    assert client.owns(result["job_id"])
    assert client.call("job_status", {"job_id": result["job_id"]})["job_id"] == result["job_id"]


def test_admission_slower_than_budget_stays_uncertain_with_one_retry_same_token(tmp_path, monkeypatch):
    client = _slow_client(tmp_path, monkeypatch, {"dispatch_agent": 120})
    sent = []
    original = _SlowGateway.request

    def capture(self, method, path, body=None, headers=None):
        sent.append(json.loads(body)["args"].get("request_id"))
        original(self, method, path, body, headers)
    monkeypatch.setattr(_SlowGateway, "request", capture)
    result = client.call("dispatch_agent", dict(DISPATCH))
    assert result["status"] == "delivery_uncertain"
    assert _SlowGateway.attempts.count("dispatch_agent") == 2
    dispatch_ids = [i for i in sent if i]
    assert len(dispatch_ids) == 2 and len(set(dispatch_ids)) == 1
    assert result["job_id"] == "rjob_" + dispatch_ids[0]


def test_slow_job_and_workspace_reads_still_use_fast_budget(tmp_path, monkeypatch):
    client = _slow_client(tmp_path, monkeypatch, {"workspace_info": 40})
    with pytest.raises(ConnectionError):
        client.call("workspace_info", {"workspace_id": "PAGe"})
    with pytest.raises(ConnectionError):
        client.call("dispatch_agent", dict(DISPATCH))
    assert "dispatch_agent" not in _SlowGateway.attempts
