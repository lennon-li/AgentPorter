"""Every policy-declared action must be a registered, published MCP tool."""
from agentporter.action_policy import DEFAULT_ACTION_MODES
from agentporter.server import build_mcp_server


def test_declared_actions_are_published(temp_config):
    mcp, context = build_mcp_server(temp_config)
    published = {tool.name for tool in mcp._tool_manager.list_tools()}
    caps = context["tools"]["get_capabilities"]()
    assert set(caps["supported_tools"]) == published
    assert {row["action"] for row in caps["action_matrix"]} == set(DEFAULT_ACTION_MODES)
    assert caps["unpublished_actions"] == sorted(set(DEFAULT_ACTION_MODES) - published)
    assert caps["unpublished_actions"] == []
