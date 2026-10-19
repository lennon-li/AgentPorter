"""Public seven-agent delegation interface must not expose generic runtime IDs."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.roster import (
    PUBLIC_AGENT_IDS,
    PUBLIC_AGENT_ROSTER,
    public_agent_inventory,
)
from agentporter.tools.agents import create_agent_tools


def _discovered():
    return [
        {"agent": key, "alias": alias, "worker_cli": runtime,
         "available": key != "wei", "configured_model": "example-model",
         "supports_read_only": key in {"jax", "liz", "prof"}}
        for key, alias, runtime in PUBLIC_AGENT_ROSTER
    ] + [
        {"agent": name, "alias": name, "worker_cli": name, "available": True}
        for name in ("codex", "claude", "opencode", "agy")
    ]


def test_exact_public_named_roster_and_order():
    assert [x[0] for x in PUBLIC_AGENT_ROSTER] == [
        "jax", "liz", "prof", "phil", "wei", "ming", "argie"
    ]
    assert len(PUBLIC_AGENT_IDS) == 7
    assert "tracker" not in PUBLIC_AGENT_IDS


def test_public_list_excludes_runtimes_and_preserves_wei_unavailable():
    fake = SimpleNamespace(list_agents=_discovered)
    list_agents, _ = create_agent_tools(fake)
    rows = list_agents()
    assert [r["agent"] for r in rows] == [
        "jax", "liz", "prof", "phil", "wei", "ming", "argie"
    ]
    assert all(r["registered"] is True for r in rows)
    assert next(r for r in rows if r["agent"] == "wei")["available"] is False


def test_absent_identity_shown_unavailable_and_not_borrowed_from_runtime():
    discovered = [r for r in _discovered() if r["agent"] != "ming"]
    rows = public_agent_inventory(discovered)
    missing = next(r for r in rows if r["agent"] == "ming")
    assert missing["registered"] is False
    assert missing["available"] is False
    assert missing["worker_cli"] == "claude"


@pytest.mark.parametrize("identity", ["codex", "claude", "opencode", "agy", "tracker", "other"])
def test_public_dispatch_rejects_unapproved_ids(identity):
    fake = Mock()
    _, dispatch = create_agent_tools(fake)
    with pytest.raises(PermissionError, match="Unapproved public agent identity"):
        dispatch(agent=identity, task="No launch", workspace_id="demo")
    fake.dispatch_agent.assert_not_called()


@pytest.mark.parametrize("identity", ["jax", "liz", "prof", "phil", "wei", "ming", "argie"])
def test_named_dispatch_remains_routable(identity):
    fake = Mock()
    fake.list_agents.return_value = [dict(x, available=True) for x in _discovered()]
    fake.dispatch_agent.return_value = {"job_id": "example"}
    _, dispatch = create_agent_tools(fake)
    result = dispatch(agent=identity, task="Inspect", workspace_id="demo")
    assert result["job_id"] == "example"
    assert fake.dispatch_agent.call_args.kwargs["agent"] == identity
    assert fake.dispatch_agent.call_args.kwargs["read_only"] is True


def test_unavailable_wei_not_replaced_with_generic_opencode():
    fake = Mock()
    fake.list_agents.return_value = _discovered()
    _, dispatch = create_agent_tools(fake)
    with pytest.raises(PermissionError, match="unavailable"):
        dispatch(agent="wei", task="Do not launch", workspace_id="demo")
    fake.dispatch_agent.assert_not_called()


def test_runtime_mismatch_is_not_exposed_as_available():
    discovered = _discovered()
    ming = next(x for x in discovered if x["agent"] == "ming")
    ming["worker_cli"] = "opencode"
    rows = public_agent_inventory(discovered)
    ming = next(x for x in rows if x["agent"] == "ming")
    assert ming["registered"] is True
    assert ming["available"] is False
    assert "runtime mismatch" in ming["routing_error"]
    fake = Mock()
    fake.list_agents.return_value = discovered
    _, dispatch = create_agent_tools(fake)
    with pytest.raises(PermissionError, match="misrouted"):
        dispatch(agent="ming", task="Do not launch", workspace_id="demo")
    fake.dispatch_agent.assert_not_called()

def test_public_tool_rejects_explicit_non_delegatable_worker():
    fake = Mock()
    fake.list_agents.return_value = [
        {"agent": "jax", "worker_cli": "codex", "available": True,
         "delegatable": False, "confinement_status": "blocked_pending_os_confinement"}
    ]
    _, dispatch = create_agent_tools(fake)
    with pytest.raises(PermissionError, match="delegation blocked"):
        dispatch(agent="jax", task="must not launch", workspace_id="demo")
    fake.dispatch_agent.assert_not_called()
