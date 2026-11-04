"""Public policy catalog must cover every deployed MCP operation, no silent grants."""

from pathlib import Path
import re

from agentporter.rest.schemas import AgentInfo
from agentporter.agents.roster import PUBLIC_AGENT_ROSTER, public_agent_inventory
from agentporter.action_policy import DEFAULT_ACTION_MODES
from agentporter.server import create_asgi_app


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "docs" / "agent-roster-action-policy.md"
SERVER = ROOT / "src" / "agentporter" / "server.py"


def _policy_rows():
    return re.findall(
        r"^\| `([a-z_]+)` \| \*\*(ALLOW|SCOPE|APPROVAL|LOCKED)\*\* \|",
        CATALOG.read_text(),
        re.M,
    )


def test_policy_has_exactly_one_explicit_entry_per_registered_mcp_operation():
    registered = re.findall(
        r'@monitored_tool\("([^"]+)"\)', SERVER.read_text(),
    )
    rows = _policy_rows()
    names = [name for name, _ in rows]
    assert len(registered) == len(DEFAULT_ACTION_MODES)
    assert len(registered) == len(set(registered))
    assert len(rows) == len(set(names))
    assert set(registered) == set(names), {
        "unclassified": sorted(set(registered) - set(names)),
        "orphaned": sorted(set(names) - set(registered)),
    }


def test_publication_operations_are_locked_by_policy():
    matrix = dict(_policy_rows())
    assert matrix["git_commit"] == "SCOPE"
    assert matrix["git_push"] == "LOCKED"
    assert matrix["local_http_request"] == "APPROVAL"
    assert matrix["list_agents"] == "ALLOW"
    assert matrix["dispatch_agent"] == "SCOPE"



# These are outside the owner-overridable action matrix. A privileged
# operation must not become a public endpoint merely because it is LOCKED.
_HARD_EXCLUDED_HOST_ACTIONS = {
    "sudo", "systemctl", "host_shell", "host_exec", "ssh_exec",
    "service_restart", "system_restart", "os_package_install",
    "manage_users", "credential_export", "agentporter_deploy",
    "agentporter_activate", "git_force_push", "forge_approval",
}


def test_strictly_prohibited_host_operations_are_not_public_mcp_or_rest(temp_config):
    """No MCP/REST registration of host administrative capabilities."""

    mcp_names = set(re.findall(
        r'@monitored_tool\("([^"]+)"\)', SERVER.read_text()
    ))
    saved = create_asgi_app(temp_config).app.openapi()
    rest_names = {
        operation["operationId"]
        for path_item in saved["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict) and "operationId" in operation
    }
    assert mcp_names, "MCP registry not discovered; hard exclusion check invalid"
    assert rest_names, "REST actions not discovered; hard exclusion check invalid"
    assert not (_HARD_EXCLUDED_HOST_ACTIONS & (mcp_names | rest_names))
    forbidden_path_fragments = (
        "/admin/", "/host/", "/sudo", "/systemctl", "/service/restart",
        "/deploy/activate",
    )
    assert all(
        not any(fragment in path for fragment in forbidden_path_fragments)
        for path in saved["paths"]
    )


def test_matrix_distinguishes_operator_overrides_from_permanent_exclusions():
    """The policy catalog documents configurable defaults, not a runtime bypass."""
    policy = CATALOG.read_text()
    assert "Operator-overridable matrix" in policy
    assert f"all {len(DEFAULT_ACTION_MODES)} public actions" in policy.lower()
    assert "action-policy.yaml" in policy
    assert "scoped_modes" in policy
    assert dict(_policy_rows()) == DEFAULT_ACTION_MODES
    assert "Permanently excluded capabilities" in policy
    assert "not MCP/REST actions" in policy


def test_pydantic_rest_serialization_preserves_identity_mismatch():
    rows = public_agent_inventory([
        {"agent": "claude_agent", "worker_cli": "opencode", "available": True}
    ])
    obj = next(r for r in rows if r["agent"] == "claude_agent")
    assert obj["available"] is False
    parsed = AgentInfo.model_validate(obj).model_dump(exclude_none=True)
    assert "runtime mismatch" in parsed["routing_error"]
    assert parsed["registered"] is True
    assert len(rows) == len(PUBLIC_AGENT_ROSTER)


def test_openapi_imports_workspace_git_without_receipts_and_excludes_push(temp_config):
    doc = create_asgi_app(temp_config).app.openapi()
    for action in ("commit", "pull"):
        path = f"/api/v1/workspaces/{{workspace_id}}/git/{action}"
        responses = doc["paths"][path]["post"]["responses"]
        assert "403" in responses
        assert any(word in responses["403"]["description"].lower() for word in ("scope", "policy"))
    assert '/api/v1/workspaces/{workspace_id}/git/push' not in doc['paths']
    fields=doc['components']['schemas']['GitPullRequest']['properties']
    assert {'job_id','request_sha256'} <= fields.keys()
    assert 'approval_receipt' not in doc['components']['schemas']['GitPullRequest'].get('required', [])
    assert fields['approval_receipt']['default'] == ''
    assert 'repository' in fields
    operations=[operation for path in doc['paths'].values() for operation in path.values()
                if isinstance(operation,dict) and 'operationId' in operation]
    assert len(operations)<=30

def test_rest_schema_exposes_distinct_worker_availability_and_delegation(temp_config):
    from agentporter.rest.schemas import AgentInfo
    fields = AgentInfo.model_fields
    assert {"agent", "available", "delegatable", "confinement_status"} <= set(fields)
    openapi = create_asgi_app(temp_config).app.openapi()
    props = openapi["components"]["schemas"]["AgentInfo"]["properties"]
    assert {"available", "delegatable", "confinement_status"} <= set(props)


def test_openapi_denies_delegation_without_confinement(temp_config):
    doc = create_asgi_app(temp_config).app.openapi()
    path = "/api/v1/workspaces/{workspace_id}/agents/dispatch"
    assert "403" in doc["paths"][path]["post"]["responses"]
