"""Central relay inventory and independently approved writable delegation."""
from types import SimpleNamespace
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter.agents import production_relay as relay
from agentporter import scoped_approvals as approvals


def dispatch(**changes):
    return {"agent": "prof", "workspace_id": "PAGe", "task": "audit", **changes}


@pytest.fixture
def approved(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    key = Ed25519PrivateKey.generate()
    verifier = approvals.ApprovalVerifier(key.public_key(), tmp_path / "grants.sqlite", clock=lambda: 1100)
    data = relay.normalize_dispatch(dispatch(read_only=False, request_id=uuid.uuid4().hex))
    token = approvals.sign_grant(key, workspace_id="PAGe", workspace_root=root,
        action="dispatch_agent", arguments=data, operations=["write"], agent="prof",
        task="audit", issued_at=1000, expires_at=1500)
    return {**data, "approval_token": token}, verifier, {"PAGe": str(root)}


def test_read_only_needs_no_grant():
    assert relay.validate_dispatch(dispatch(), {"PAGe"})["read_only"] is True


def test_approved_write_and_identical_retry(approved):
    data, verifier, paths = approved
    for _ in range(2):
        result = relay.validate_dispatch(data, set(paths), approval_verifier=verifier, workspace_paths=paths)
        assert result["read_only"] is False
        assert result["request_id"] == data["request_id"]


@pytest.mark.parametrize("change", [
    {"task": "delete"}, {"workspace_id": "other"}, {"agent": "liz"},
    {"approval_token": ""}, {"request_id": "bad"},
    {"allow_commit": True}, {"allow_push": True},
    {"read_only": 0}, {"allow_commit": 0}, {"allow_push": "false"},
])
def test_invalid_or_mismatched_writable_request_denied(approved, change):
    data, verifier, paths = approved
    with pytest.raises((PermissionError, approvals.ApprovalError)):
        relay.validate_dispatch({**data, **change}, {"PAGe", "other"}, approval_verifier=verifier,
            workspace_paths={**paths, "other": paths["PAGe"]})


def test_missing_approval_or_root_denied(approved):
    data, verifier, paths = approved
    for kwargs in ({}, {"approval_verifier": verifier}, {"workspace_paths": paths}):
        with pytest.raises(PermissionError):
            relay.validate_dispatch(data, set(paths), **kwargs)
    with pytest.raises(PermissionError):
        relay.validate_dispatch(dispatch(read_only=False), set(paths), approval_verifier=verifier, workspace_paths=paths)


def test_expiry_root_and_replay_denied(approved):
    data, verifier, paths = approved
    with pytest.raises(approvals.ApprovalError):
        relay.validate_dispatch(data, set(paths), approval_verifier=verifier,
            workspace_paths={"PAGe": "/different"})
    relay.validate_dispatch(data, set(paths), approval_verifier=verifier, workspace_paths=paths)
    with pytest.raises(approvals.ApprovalError):
        relay.validate_dispatch({**data, "request_id": uuid.uuid4().hex}, set(paths),
            approval_verifier=verifier, workspace_paths=paths)
    verifier.clock = lambda: 1500
    with pytest.raises(approvals.ApprovalError):
        relay.validate_dispatch(data, set(paths), approval_verifier=verifier, workspace_paths=paths)


def test_both_roles_resolve_same_central_inventory(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    reference = "version: 2\npolicy_file: /etc/agentporter/production-workspace-policy.yaml\n"
    for name in ("delegation-upstream.yaml", "delegation-relay-scope.yaml"):
        path = tmp_path / name
        path.write_text(reference)
        path.chmod(0o600)
    paths = {f"workspace-{i}": {"path": f"/registered/{i}"} for i in range(11)}
    policy = SimpleNamespace(workspaces=paths, capabilities=lambda name: {"agent_dispatch": True})
    calls = []
    def resolve(document):
        calls.append(document)
        assert document == {"version": 2, "policy_file": "/etc/agentporter/production-workspace-policy.yaml"}
        return policy
    monkeypatch.setattr("agentporter.workspace_policy.shared_policy_reference", resolve)
    assert relay.relay_upstream_workspaces(tmp_path) == frozenset(paths)
    assert relay.read_relay_scope(tmp_path) == {name: row["path"] for name, row in paths.items()}
    assert len(calls) == 2


def test_legacy_inventory_unchanged(tmp_path):
    tmp_path.chmod(0o700)
    for filename, content in {
        "delegation-upstream.yaml": "version: 1\nhost: 127.0.0.1\nport: 8876\nworkspaces: [PAGe]\n",
        "delegation-relay-scope.yaml": "version: 1\nworkspaces:\n  PAGe: /registered/PAGe\n",
    }.items():
        file = tmp_path / filename
        file.write_text(content)
        file.chmod(0o600)
    assert relay.relay_upstream_workspaces(tmp_path) == frozenset({"PAGe"})
    assert relay.read_relay_scope(tmp_path) == {"PAGe": "/registered/PAGe"}


@pytest.mark.parametrize("writable", [True, False, None])
def test_client_preserves_approved_request_and_checks_receiving_write_policy(approved, tmp_path, monkeypatch, writable):
    data, verifier, paths = approved
    (tmp_path / "client").mkdir(mode=0o700)
    sent = []
    timeouts = []
    class Connection:
        def __init__(self, *args, timeout):
            timeouts.append(timeout)
        def request(self, method, url, *, body, headers):
            self.payload = json.loads(body)
            sent.append(self.payload)
        def getresponse(self):
            if self.payload["operation"] == "workspace_info":
                value = {"workspace_id": "PAGe", "path": paths["PAGe"], "agent_dispatch": True,
                    "security_profile": relay.RECEIVING_SECURITY_PROFILE, "writable": writable}
            else:
                value = {"job_id": "job_" + "a" * 24, "status": "queued"}
            return SimpleNamespace(status=200, read=lambda limit: json.dumps(value).encode())
        def close(self):
            pass
    monkeypatch.setattr(relay.http.client, "HTTPConnection", Connection)
    client = relay.ProductionDelegationClient("key", paths, tmp_path / "client", approval_verifier=verifier)
    if writable is not True:
        with pytest.raises(PermissionError):
            client.call("dispatch_agent", data)
        assert client.ledger.get_request(data["request_id"]) is None
        assert [row["operation"] for row in sent] == ["workspace_info"]
        return
    for _ in range(2):
        result = client.call("dispatch_agent", data)
        assert result["job_id"] == "rjob_" + data["request_id"]
    dispatched = [row["args"] for row in sent if row["operation"] == "dispatch_agent"]
    assert len(dispatched) == 2
    assert all(row["request_id"] == data["request_id"] for row in dispatched)
    assert timeouts == [8, 90, 8, 90]


def test_capability_alone_does_not_authorize_client_write(tmp_path, monkeypatch):
    (tmp_path / "client").mkdir(mode=0o700)
    client = relay.ProductionDelegationClient("key", {"PAGe": "/registered/PAGe"}, tmp_path / "client")
    def unexpected(*args, **kwargs):
        pytest.fail("unapproved request reached network")
    monkeypatch.setattr(relay.http.client, "HTTPConnection", unexpected)
    with pytest.raises(PermissionError):
        client.call("dispatch_agent", dispatch(read_only=False, request_id=uuid.uuid4().hex))


def test_receiving_http_route_preserves_approved_identity_and_does_not_relaunch(
        approved, temp_config, monkeypatch):
    import asyncio
    import httpx
    from mcp.server.mcpserver import MCPServer
    from agentporter import server
    from agentporter.task_authorization import TaskAuthorization, ACTIVE_GRANT
    from agentporter.workspaces.registry import WorkspaceRegistry

    data, verifier, paths = approved
    registry = WorkspaceRegistry({'PAGe': {'path': paths['PAGe'], 'allow_agent_dispatch': True}})
    authority = TaskAuthorization(registry, verifier)
    launched = []
    job_id = 'job_' + 'b' * 24

    def launch(**arguments):
        assert ACTIVE_GRANT.get() is not None
        launched.append(arguments)
        return {'job_id': job_id, 'status': 'queued'}

    context = {
        'registry': registry,
        'task_authorization': authority,
        'client_policy': SimpleNamespace(scopes=None, internal_key=None),
        'agent_broker': SimpleNamespace(development_runtime=SimpleNamespace(
            require_production_egress=lambda *args: {'prof'})),
        'delegation_relay_client': None,
        'job_manager': SimpleNamespace(get_status=lambda _: {'status': 'completed'}),
        'tools': {
            'dispatch_agent': server._monitored_tool('dispatch_agent', authorization=authority)(launch),
            'job_status': lambda **kw: {'job_id': kw['job_id'], 'status': 'completed'},
        },
    }
    monkeypatch.setattr(server, 'build_mcp_server', lambda _: (MCPServer('test-relay'), context))
    monkeypatch.setattr(server, 'read_relay_key', lambda _: 'relay-only-test-key')
    monkeypatch.setattr(server, 'read_relay_scope', lambda _: paths)
    app = server.create_asgi_app(temp_config)

    async def exercise():
        transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1',
                                   headers={'Authorization': 'Bearer relay-only-test-key'}) as client:
            async def submit(arguments):
                return await client.post('/internal/delegation/v1',
                                         json={'operation': 'dispatch_agent', 'args': arguments})
            missing = {k: v for k, v in data.items() if k != 'approval_token'}
            assert (await submit(missing)).status_code == 403
            assert not launched
            for _ in range(2):
                response = await submit(data)
                assert response.status_code == 200, response.text
                assert response.json()['job_id'] == job_id
    asyncio.run(exercise())
    assert len(launched) == 1
    assert launched[0]['request_id'] == data['request_id']
