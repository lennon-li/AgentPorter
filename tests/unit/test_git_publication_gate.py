"""Unverified callers cannot publish Git changes over MCP or REST."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.tools.git import create_git_tools
from agentporter.rest.routers import git as git_router
from agentporter.rest.schemas import GitCommitRequest, GitPushRequest
from fastapi import HTTPException


@pytest.fixture
def tools():
    ws = SimpleNamespace(path="/unused", writable=True, allow_git=True)
    registry = Mock()
    registry.get.return_value = ws
    sandbox = Mock()
    result = create_git_tools(registry, sandbox)
    return result, registry, sandbox


@pytest.mark.parametrize("operation,kw", [
    ("git_push", {"workspace_id": "test", "remote": "origin", "branch": "main"}),
    ("git_commit", {"workspace_id": "test", "message": "unverified publish"}),
])
def test_direct_publication_denied_without_invoking_sandbox(tools, operation, kw):
    git_tools, _, sandbox = tools
    with pytest.raises(PermissionError, match="server-verified|push is disabled"):
        getattr(git_tools, operation)(**kw)
    sandbox.run.assert_not_called()


@pytest.mark.parametrize("operation,payload", [
    ("git_push", GitPushRequest(remote="origin", branch="main")),
    ("git_commit", GitCommitRequest(message="unverified publish")),
])
def test_rest_returns_403_for_unverified_publication(operation, payload):
    fake_tools = {
        "git_push": Mock(side_effect=PermissionError("approval required")),
        "git_commit": Mock(side_effect=PermissionError("approval required")),
    }
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(tools=fake_tools)))
    with pytest.raises(HTTPException) as err:
        getattr(git_router, operation)("test", payload, request)
    assert err.value.status_code == 403
    assert "approval" in err.value.detail


def test_git_read_operations_remain_routable(tools):
    git_tools, _, sandbox = tools
    sandbox.run.return_value = {"exit_code": 0, "stdout": "## main\n", "stderr": ""}
    assert git_tools.git_status("test") == "## main\n"
