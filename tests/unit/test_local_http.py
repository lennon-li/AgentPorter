"""Unit tests for local_http_request tool."""

import pytest
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.tools.local_http import create_local_http_tool


def test_local_http_invalid_port():
    reg = WorkspaceRegistry({"test": {"path": "/tmp", "writable": True}})
    local_http = create_local_http_tool(reg)

    with pytest.raises(ValueError, match="Invalid port number"):
        local_http("test", port=0)

    with pytest.raises(ValueError, match="Invalid port number"):
        local_http("test", port=70000)


def test_local_http_unknown_workspace():
    reg = WorkspaceRegistry()
    local_http = create_local_http_tool(reg)

    with pytest.raises(KeyError):
        local_http("nonexistent", port=8080)


def test_local_http_connection_refused():
    reg = WorkspaceRegistry({"test": {"path": "/tmp", "writable": True}})
    local_http = create_local_http_tool(reg)

    # Port 59999 should not have a service listening
    res = local_http("test", port=59999)
    assert "error" in res
    assert "Failed to connect to local service on 127.0.0.1:59999" in res["error"]
