"""Public policy catalog must cover every deployed MCP operation, no silent grants."""

from pathlib import Path
import re

from agentporter.rest.schemas import AgentInfo
from agentporter.agents.roster import PUBLIC_AGENT_ROSTER, public_agent_inventory


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
    assert len(registered) == 55
    assert len(registered) == len(set(registered))
    assert len(rows) == len(set(names))
    assert set(registered) == set(names), {
        "unclassified": sorted(set(registered) - set(names)),
        "orphaned": sorted(set(names) - set(registered)),
    }


def test_publication_operations_are_locked_by_policy():
    matrix = dict(_policy_rows())
    assert matrix["git_commit"] == matrix["git_push"] == matrix["qman_consult"] == "LOCKED"
    assert matrix["scinet_inference_provision"] == "APPROVAL"
    assert matrix["list_agents"] == "ALLOW"
    assert matrix["dispatch_agent"] == "SCOPE"



# These are outside the owner-overridable 55-action matrix. A privileged
# operation must not become a public endpoint merely because it is LOCKED.
_HARD_EXCLUDED_HOST_ACTIONS = {
    "sudo", "systemctl", "host_shell", "host_exec", "ssh_exec",
    "service_restart", "system_restart", "os_package_install",
    "manage_users", "credential_export", "agentporter_deploy",
    "agentporter_activate", "git_force_push", "forge_approval",
}


def test_strictly_prohibited_host_operations_are_not_public_mcp_or_rest():
    """No MCP/REST registration of host administrative capabilities."""
    import json

    mcp_names = set(re.findall(
        r'@monitored_tool\("([^"]+)"\)', SERVER.read_text()
    ))
    saved = json.loads((ROOT / "docs" / "agent7-asgard-actions.openapi.json").read_text())
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
    assert "all 55 public actions" in policy.lower()
    assert "not yet implemented" in policy
    assert "Permanently excluded capabilities" in policy
    assert "not MCP/REST actions" in policy


def test_pydantic_rest_serialization_preserves_identity_mismatch():
    rows = public_agent_inventory([
        {"agent": "ming", "worker_cli": "opencode", "available": True}
    ])
    obj = next(r for r in rows if r["agent"] == "ming")
    assert obj["available"] is False
    parsed = AgentInfo.model_validate(obj).model_dump(exclude_none=True)
    assert "runtime mismatch" in parsed["routing_error"]
    assert parsed["registered"] is True
    assert len(rows) == len(PUBLIC_AGENT_ROSTER)


def test_saved_openapi_documents_locked_publication_response():
    import json

    doc = json.loads(
        (ROOT / "docs" / "agent7-asgard-actions.openapi.json").read_text()
    )
    for action in ("commit", "push"):
        path = f"/api/v1/workspaces/{{workspace_id}}/git/{action}"
        responses = doc["paths"][path]["post"]["responses"]
        assert "403" in responses
        assert "approval" in responses["403"]["description"].lower()

def test_rest_schema_exposes_distinct_worker_availability_and_delegation():
    from agentporter.rest.schemas import AgentInfo
    fields = AgentInfo.model_fields
    assert {"agent", "available", "delegatable", "confinement_status"} <= set(fields)
    import json
    openapi = json.loads(
        (ROOT / "docs" / "agent7-asgard-actions.openapi.json").read_text()
    )
    props = openapi["components"]["schemas"]["AgentInfo"]["properties"]
    assert {"available", "delegatable", "confinement_status"} <= set(props)


def test_saved_openapi_denies_delegation_without_confinement():
    import json
    doc = json.loads(
        (ROOT / "docs" / "agent7-asgard-actions.openapi.json").read_text()
    )
    path = "/api/v1/workspaces/{workspace_id}/agents/dispatch"
    assert "403" in doc["paths"][path]["post"]["responses"]
