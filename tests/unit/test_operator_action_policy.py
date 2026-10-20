"""Server-side action mode enforcement and hostile operator-file regression."""

import os
from pathlib import Path

import pytest

from agentporter.action_policy import DEFAULT_ACTION_MODES, OperatorActionPolicy
from agentporter.server import build_mcp_server, create_asgi_app


def _policy_file(config_dir: Path, body: str) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "action-policy.yaml"
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_default_modes_cover_complete_public_catalog():
    assert len(DEFAULT_ACTION_MODES) == 53
    assert DEFAULT_ACTION_MODES["get_capabilities"] == "ALLOW"
    assert DEFAULT_ACTION_MODES["dispatch_agent"] == "SCOPE"
    assert DEFAULT_ACTION_MODES["git_push"] == "LOCKED"
    assert DEFAULT_ACTION_MODES["scinet_submit"] == "APPROVAL"


def test_missing_operator_file_preserves_defaults(tmp_path):
    policy = OperatorActionPolicy(tmp_path)
    assert policy.overrides == {}
    assert policy.check("get_capabilities", {}) == "ALLOW"
    with pytest.raises(PermissionError, match="technically locked"):
        policy.check("git_push", {"workspace_id": "demo"})
    with pytest.raises(PermissionError, match="Unknown public action"):
        policy.check("systemctl", {})


def test_owner_mode_can_tighten_but_not_forge_approval(tmp_path):
    _policy_file(tmp_path, """version: 1
action_modes:
  get_capabilities: LOCKED
  list_files: APPROVAL
  read_file: SCOPE
  git_push: ALLOW
""")
    policy = OperatorActionPolicy(tmp_path)
    with pytest.raises(PermissionError, match="technically locked"):
        policy.check("get_capabilities", {})
    with pytest.raises(PermissionError, match="independent approval"):
        policy.check("list_files", {"workspace_id": "demo"})
    with pytest.raises(PermissionError, match="workspace scope"):
        policy.check("read_file", {})
    assert policy.check("read_file", {"workspace_id": "demo"}) == "SCOPE"
    # Default LOCKED Git publication cannot be bypassed with a permissive file.
    with pytest.raises(PermissionError, match="technically locked"):
        policy.check("git_push", {"workspace_id": "demo"})


@pytest.mark.parametrize("body", [
    "version: 1\naction_modes:\n  sudo: ALLOW\n",
    "version: 1\naction_modes:\n  systemctl: APPROVAL\n",
    "version: 1\naction_modes:\n  read_file: unrestricted\n",
    "version: 1\naction_modes:\n  read_file: ALLOW\n  read_file: LOCKED\n",
    "version: 2\naction_modes: {}\n",
    "version: 1\naction_modes: []\n",
    "version: 1\naction_modes: {}\nextra: ignored\n",
])
def test_invalid_policy_rejected_at_load(tmp_path, body):
    _policy_file(tmp_path, body)
    with pytest.raises(ValueError):
        OperatorActionPolicy(tmp_path)


def test_insecure_policy_permissions_are_rejected(tmp_path):
    policy = _policy_file(tmp_path, "version: 1\naction_modes: {}\n")
    policy.chmod(0o666)
    with pytest.raises(PermissionError, match="owner-owned"):
        OperatorActionPolicy(tmp_path)


def test_policy_symlink_is_rejected(tmp_path):
    real_file = _policy_file(tmp_path / "store", "version: 1\naction_modes: {}\n")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "action-policy.yaml").symlink_to(real_file)
    with pytest.raises(OSError):
        OperatorActionPolicy(config_dir)


def test_policy_cannot_live_under_agent_writable_workspace(tmp_path):
    config_dir = tmp_path / "workspace" / ".config" / "agentporter"
    with pytest.raises(PermissionError, match="agent workspace"):
        OperatorActionPolicy(config_dir, workspace_roots=[tmp_path / "workspace"])


def test_same_operator_guard_applies_to_registered_mcp_and_rest_tools(temp_config):
    # list_workspaces is exposed by both surfaces; neither can bypass LOCKED.
    _policy_file(temp_config.config_dir, """version: 1
action_modes:
  list_workspaces: LOCKED
""")
    _, context = build_mcp_server(temp_config)
    with pytest.raises(PermissionError, match="technically locked"):
        context["tools"]["list_workspaces"]()
    app = create_asgi_app(temp_config).app
    with pytest.raises(PermissionError, match="technically locked"):
        app.state.tools["list_workspaces"]()


def test_default_policy_still_allows_readonly_server_inventory(temp_config):
    _, context = build_mcp_server(temp_config)
    assert isinstance(context["tools"]["list_workspaces"](), list)

def test_authenticated_rest_denials_return_403_not_500(temp_config):
    """Both generic REST actions and direct deploy-info honor owner locks."""
    from fastapi.testclient import TestClient

    _policy_file(temp_config.config_dir, """version: 1
action_modes:
  list_workspaces: LOCKED
  server_deploy_info: LOCKED
""")
    temp_config.security.allowed_hosts.append("testserver")
    app = create_asgi_app(temp_config)
    headers = {"Authorization": f"Bearer {temp_config.api_key}"}
    with TestClient(app, base_url="http://testserver") as client:
        for route in ("/api/v1/workspaces/", "/api/v1/server/deploy-info"):
            response = client.get(route, headers=headers)
            assert response.status_code == 403, (route, response.text)
            assert "technically locked" in response.json()["detail"]


def test_policy_gate_for_deploy_info_shared_between_mcp_and_rest(temp_config):
    _policy_file(temp_config.config_dir, """version: 1
action_modes:
  server_deploy_info: LOCKED
""")
    _, context = build_mcp_server(temp_config)
    with pytest.raises(PermissionError, match="technically locked"):
        context["tools"]["server_deploy_info"]()
