"""Fetching changes repository metadata and must respect workspace writability."""

from types import SimpleNamespace

import pytest

from agentporter.tools.git import create_git_tools


class FakeRegistry:
    def __init__(self, workspace):
        self.workspace = workspace

    def get(self, workspace_id):
        assert workspace_id == "repo"
        return self.workspace


class RecordingSandbox:
    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}


def test_git_fetch_rejected_in_read_only_workspace(tmp_path):
    workspace = SimpleNamespace(path=str(tmp_path), writable=False, allow_git=True)
    sandbox = RecordingSandbox()
    tools = create_git_tools(FakeRegistry(workspace), sandbox)

    with pytest.raises(PermissionError, match="read-only"):
        tools.git_fetch("repo")
    assert sandbox.calls == []


def test_git_fetch_can_run_only_when_workspace_is_writable(tmp_path):
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=True)
    sandbox = RecordingSandbox()
    tools = create_git_tools(FakeRegistry(workspace), sandbox)

    assert tools.git_fetch("repo") == "ok"
    assert len(sandbox.calls) == 1
    assert sandbox.calls[0]["writable"] is True
    assert sandbox.calls[0]["network_access"] is True


def test_git_fetch_requires_git_permission_even_if_writable(tmp_path):
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=False)
    sandbox = RecordingSandbox()
    tools = create_git_tools(FakeRegistry(workspace), sandbox)

    with pytest.raises(PermissionError, match="does not allow Git"):
        tools.git_fetch("repo")
    assert sandbox.calls == []


def test_git_pull_rejects_implicit_merge_commits(tmp_path):
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=True)
    sandbox = RecordingSandbox()
    tools = create_git_tools(FakeRegistry(workspace), sandbox)

    assert tools.git_pull("repo", remote="origin", branch="main") == "ok"
    assert len(sandbox.calls) == 1
    args = sandbox.calls[0]["argv"]
    assert args[-4:] == ["pull", "--ff-only", "origin", "main"]
    assert sandbox.calls[0]["network_access"] is True


def test_git_pull_is_read_only_workspace_denied_before_network(tmp_path):
    workspace = SimpleNamespace(path=str(tmp_path), writable=False, allow_git=True)
    sandbox = RecordingSandbox()
    tools = create_git_tools(FakeRegistry(workspace), sandbox)

    with pytest.raises(PermissionError, match="read-only"):
        tools.git_pull("repo")
    assert sandbox.calls == []
