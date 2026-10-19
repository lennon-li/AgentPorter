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
    assert len(registered) == 53
    assert len(registered) == len(set(registered))
    assert len(rows) == len(set(names))
    assert set(registered) == set(names), {
        "unclassified": sorted(set(registered) - set(names)),
        "orphaned": sorted(set(names) - set(registered)),
    }


def test_publication_operations_are_locked_by_policy():
    matrix = dict(_policy_rows())
    assert matrix["git_commit"] == matrix["git_push"] == "LOCKED"
    assert matrix["scinet_inference_provision"] == "APPROVAL"
    assert matrix["list_agents"] == "ALLOW"
    assert matrix["dispatch_agent"] == "SCOPE"


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
