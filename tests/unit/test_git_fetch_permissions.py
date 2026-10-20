"""Git network operations fail closed until an audited transport is available."""

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


@pytest.mark.parametrize("op", ["git_fetch", "git_pull"])
def test_network_git_denied_in_read_only_workspace(tmp_path, op):
    ws = SimpleNamespace(path=str(tmp_path), writable=False, allow_git=True)
    sandbox = RecordingSandbox()
    git = create_git_tools(FakeRegistry(ws), sandbox)

    with pytest.raises(PermissionError, match="read-only"):
        getattr(git, op)("repo")
    assert sandbox.calls == []


@pytest.mark.parametrize("op", ["git_fetch", "git_pull"])
def test_network_git_locked_even_with_writable_workspace_and_invalid_remote(tmp_path, op):
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=True)
    sandbox = RecordingSandbox()
    git = create_git_tools(FakeRegistry(ws), sandbox)

    for remote in ("origin", "-unsafe"):
        with pytest.raises(PermissionError, match="scoped network-capable Git backend"):
            getattr(git, op)("repo", remote=remote)
    assert sandbox.calls == []


@pytest.mark.parametrize("op", ["git_fetch", "git_pull"])
def test_network_git_requires_git_workspace_permission(tmp_path, op):
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=False)
    sandbox = RecordingSandbox()
    git = create_git_tools(FakeRegistry(ws), sandbox)

    with pytest.raises(PermissionError, match="does not allow Git"):
        getattr(git, op)("repo")
    assert sandbox.calls == []


def test_pull_cannot_merge_or_touch_git_without_network_backend(tmp_path):
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_git=True)
    sandbox = RecordingSandbox()
    git = create_git_tools(FakeRegistry(ws), sandbox)
    with pytest.raises(PermissionError, match="Git pull is locked"):
        git.git_pull("repo", remote="origin", branch="main")
    assert sandbox.calls == []
