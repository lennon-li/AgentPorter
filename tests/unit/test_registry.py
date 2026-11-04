"""Unit tests for WorkspaceRegistry."""

import pytest
from pathlib import Path
from agentporter.workspaces.registry import WorkspaceRegistry


def test_registry_registration_and_get(tmp_path: Path):
    reg = WorkspaceRegistry()
    reg.register(ws_id="app", path=str(tmp_path), writable=True, description="Main app")

    ws = reg.get("app")
    assert ws.id == "app"
    assert ws.writable is True
    assert ws.description == "Main app"


def test_registry_unknown_workspace():
    reg = WorkspaceRegistry()
    with pytest.raises(KeyError, match="Unknown workspace_id: 'unknown'"):
        reg.get("unknown")


def test_registry_list_all(tmp_path: Path):
    reg = WorkspaceRegistry({
        "ws1": {"path": str(tmp_path), "writable": True, "description": "WS 1"},
        "ws2": {"path": str(tmp_path / "nonexistent"), "writable": False},
    })
    all_ws = reg.list_all()
    assert len(all_ws) == 2
    ws1 = next(w for w in all_ws if w["workspace_id"] == "ws1")
    assert ws1["exists"] is True
    ws2 = next(w for w in all_ws if w["workspace_id"] == "ws2")
    assert ws2["exists"] is False
    assert ws2["writable"] is False


def test_registry_get_info_missing_directory(tmp_path: Path):
    missing_dir = tmp_path / "missing_folder"
    reg = WorkspaceRegistry({"missing": {"path": str(missing_dir), "writable": True}})
    info = reg.get_info("missing")
    assert "error" in info
    assert "does not exist on host" in info["error"]
