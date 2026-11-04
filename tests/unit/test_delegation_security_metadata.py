"""Schema and approval metadata regressions for AgentPorter delegated operations."""

import json
from pathlib import Path

from agentporter.config import Config
from agentporter.server import build_mcp_server, create_asgi_app

_MUTATING = {
    "dispatch_agent", "exec_run", "exec_start", "write_file",
    "apply_patch", "mkdir", "move_path", "trash_path", "job_cancel",
    "local_http_request", "git_fetch", "git_pull", "git_push",
    "git_commit", "git_add", "git_checkout",
}
_ACTION_READ_ONLY = {
    "list_workspaces", "workspace_info", "list_files", "search_text",
    "read_file", "git_status", "git_diff", "git_log", "git_show",
    "list_agents", "job_status", "job_output", "job_result",
}


def _config(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_API_KEY", "unit-test-only-key")
    config = Config(config_dir=tmp_path / "private-config", state_dir=tmp_path / "state")
    config.workspaces = {"test": {"path": str(tmp_path / "workspace"), "allow_agent_dispatch": True}}
    return config


def test_mcp_tools_explicitly_mark_dangerous_actions(tmp_path, monkeypatch):
    mcp, _ = build_mcp_server(_config(tmp_path, monkeypatch))
    tools = {tool.name: tool for tool in mcp._tool_manager.list_tools()}
    for name in _MUTATING:
        assert name in tools
        ann = tools[name].annotations
        assert ann is not None, name
        assert ann.read_only_hint is False, name
        assert ann.destructive_hint is True, name
    dispatch = tools["dispatch_agent"]
    assert dispatch.parameters["properties"]["read_only"]["default"] is True


def test_runtime_and_served_actions_schema_are_aligned(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    config = _config(tmp_path, monkeypatch)
    application = create_asgi_app(config)
    current = application.app.openapi()
    with TestClient(application) as client:
        response = client.get('/openapi.json', headers={'X-AgentPorter-Key': config.api_key})
    assert response.status_code == 200
    saved = response.json()
    for name, fields in {
        "DispatchAgentRequest": ("read_only", "allow_commit", "allow_push"),
        "DispatchResponse": ("read_only",),
        "AgentInfo": ("supports_read_only", "supports_model_override", "supports_reasoning_override"),
    }.items():
        for field in fields:
            expected = current["components"]["schemas"][name]["properties"][field]
            assert saved["components"]["schemas"][name]["properties"][field] == expected
    # HTTP serialization must preserve the runtime's paths and schemas.
    assert saved["paths"] == current["paths"]
    assert saved["components"]["schemas"] == current["components"]["schemas"]
    for path_item in current["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict) or "operationId" not in operation:
                continue
            expected = operation["operationId"] not in _ACTION_READ_ONLY
            assert operation["x-openai-isConsequential"] == expected
    for path_item in saved["paths"].values():
        for operation in path_item.values():
            if isinstance(operation, dict) and "operationId" in operation:
                assert operation["x-openai-isConsequential"] == (operation["operationId"] not in _ACTION_READ_ONLY)


def test_rest_discovery_reports_read_only_ability(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    app = create_asgi_app(config).app
    discovered = app.state.tools["list_agents"]()
    assert discovered
    from agentporter.rest.schemas import AgentInfo
    for raw in discovered:
        parsed = AgentInfo.model_validate(raw)
        assert parsed.supports_read_only == raw["supports_read_only"]
