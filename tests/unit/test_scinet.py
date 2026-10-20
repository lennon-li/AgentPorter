"""Security and routing tests for the fixed SciNet diagnostic."""

import shlex
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agentporter.tools.scinet import (
    create_scinet_login_tool,
    create_scinet_tool,
    remote_argv,
    ssh_argv,
    ssh_remote_argv,
)
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.config import ScinetSettings, SandboxSettings, SecuritySettings, ServerSettings
from agentporter.server import create_asgi_app


def registry(*, enabled: bool = True) -> WorkspaceRegistry:
    return WorkspaceRegistry(
        {
            "asgard": {
                "path": "/tmp",
                "allow_execute": True,
                "allow_scinet_diagnostic": enabled,
            }
        }
    )


def host(home: str = "/home/yeli") -> SimpleNamespace:
    return SimpleNamespace(pw_name="yeli", pw_dir=home)


def settings(home: str = "/home/yeli") -> ScinetSettings:
    return ScinetSettings(
        host="trillium-gpu.alliancecan.ca",
        user="yeli",
        control_socket=f"{home}/.ssh/cm-yeli@trillium-gpu.alliancecan.ca:22",
        machine="asgard",
    )


def test_remote_commands_are_fixed_and_read_only():
    assert remote_argv("gpu_partitions") == ["sinfo", "-h", "-o", "%P|%D|%t|%G"]
    assert remote_argv("gpu_nodes") == ["sinfo", "-N", "-h", "-o", "%N|%G|%t"]
    assert remote_argv("gpu_allocations") == ["squeue", "-h", "-o", "%i|%P|%T|%b|%D|%j"]
    assert remote_argv("connection_status") is None
    with pytest.raises(ValueError):
        remote_argv("gpu_nodes; id")


def test_ssh_arguments_pin_socket_identity_and_host():
    argv = ssh_argv(settings(), "/home/yeli", "gpu_nodes")
    assert argv[0] == "/usr/bin/ssh"
    assert "-S" in argv
    assert "/home/yeli/.ssh/cm-yeli@trillium-gpu.alliancecan.ca:22" in argv
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "ForwardAgent=no" in argv
    assert "ClearAllForwardings=yes" in argv
    expected_remote = shlex.join(
        ["/bin/bash", "-lc", "exec /usr/bin/timeout 25s sinfo -N -h -o '%N|%G|%t'"]
    )
    assert argv[-2:] == ["trillium-gpu.alliancecan.ca", expected_remote]


def test_server_generated_ssh_preserves_stdin_only_when_requested():
    remote = ["/bin/bash", "-lc", "cat"]
    without_stdin = ssh_remote_argv(settings(), "/home/yeli", remote)
    with_stdin = ssh_remote_argv(settings(), "/home/yeli", remote, accepts_stdin=True)

    assert "-n" in without_stdin
    assert "-n" not in with_stdin


def test_authorized_workspace_runs_only_the_allowlisted_operation(tmp_path: Path):
    result = {
        "exit_code": 0,
        "stdout": b"gpu|idle\n",
        "stderr": b"",
        "timed_out": False,
        "truncated": False,
    }
    with (
        patch("agentporter.tools.scinet.host_identity", return_value=host(str(tmp_path))),
        patch("agentporter.tools.scinet._socket_available", return_value=True),
        patch("agentporter.tools.scinet.run_host_bytes", return_value=result) as run,
    ):
        response = create_scinet_tool(registry(), settings(str(tmp_path)))("asgard", "gpu_nodes")

    assert response["success"] is True
    assert response["target"] == "scinet"
    assert response["command"] == "gpu_nodes"
    run.assert_called_once()
    called_argv = run.call_args.args[0]
    assert "trillium-gpu.alliancecan.ca" in called_argv
    expected_remote = shlex.join(
        ["/bin/bash", "-lc", "exec /usr/bin/timeout 25s sinfo -N -h -o '%N|%G|%t'"]
    )
    assert called_argv[-1] == expected_remote


def test_scinet_login_uses_broker_and_returns_only_safe_state():
    configured = SimpleNamespace(broker_socket="/run/user/1000/agentporter/scinet.sock")
    with (
        patch("agentporter.tools.scinet.host_identity", return_value=host()),
        patch("agentporter.tools.scinet.broker_socket_available", return_value=True),
        patch(
            "agentporter.tools.scinet.run_scinet_bytes",
            return_value={"state": "push_requested", "success": False},
        ) as run,
    ):
        response = create_scinet_login_tool(registry(), configured)("asgard", "start")

    assert response == {"target": "scinet", "success": False, "state": "push_requested"}
    assert run.call_args.kwargs["operation"] == "login"
    assert run.call_args.kwargs["command"] == "start"
    assert run.call_args.args[2] == []


def test_unauthorized_workspace_is_rejected_before_ssh():
    tool = create_scinet_tool(registry(enabled=False), settings())
    with patch("agentporter.tools.scinet.run_host_bytes") as run:
        with pytest.raises(PermissionError):
            tool("asgard", "gpu_nodes")
    run.assert_not_called()


def test_missing_socket_is_structured_failure():
    with patch("agentporter.tools.scinet.host_identity", return_value=host()), patch(
        "agentporter.tools.scinet._socket_available", return_value=False
    ), patch("agentporter.tools.scinet.run_host_bytes") as run:
        response = create_scinet_tool(registry(), settings())("asgard", "connection_status")
    assert response == {
        "target": "scinet",
        "command": "connection_status",
        "success": False,
        "error": "ssh_control_socket_unavailable",
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "truncated": False,
    }
    run.assert_not_called()


@pytest.mark.parametrize(
    ("exit_code", "timed_out", "truncated", "error"),
    [
        (255, False, False, "ssh_command_failed"),
        (-9, True, False, "ssh_timeout"),
        (0, False, True, "output_truncated"),
    ],
)
def test_master_failure_timeout_and_output_limit_are_reported(
    exit_code: int, timed_out: bool, truncated: bool, error: str
):
    raw = {
        "exit_code": exit_code,
        "stdout": b"",
        "stderr": b"Permission denied (keyboard-interactive,hostbased).",
        "timed_out": timed_out,
        "truncated": truncated,
    }
    with (
        patch("agentporter.tools.scinet.host_identity", return_value=host()),
        patch("agentporter.tools.scinet._socket_available", return_value=True),
        patch("agentporter.tools.scinet.run_host_bytes", return_value=raw),
    ):
        response = create_scinet_tool(registry(), settings())("asgard", "gpu_partitions")
    assert response["success"] is False
    assert response["error"] == error
    assert "password" not in response["stderr"].lower()
    assert "token" not in response["stderr"].lower()


def test_arbitrary_remote_command_cannot_be_substituted():
    with pytest.raises(ValueError):
        remote_argv("$(id)")


def test_expired_master_cannot_fall_back_to_direct_authentication():
    argv = ssh_argv(settings(), "/home/yeli", "gpu_nodes")
    for option in ("ProxyCommand=/bin/false", "ControlMaster=no", "ControlPersist=no",
                   "IdentityAgent=none", "PubkeyAuthentication=no", "PasswordAuthentication=no",
                   "KbdInteractiveAuthentication=no", "HostbasedAuthentication=no"):
        assert option in argv
    assert argv[1:3] == ["-F", "/dev/null"]


def test_failed_ssh_output_cannot_expose_credentials_or_environment():
    raw = {"exit_code": 255, "stdout": b"SYNTHETIC_SECRET=hidden-value",
           "stderr": b"SYNTHETIC_TOKEN=hidden-token", "timed_out": False, "truncated": False}
    with patch("agentporter.tools.scinet.host_identity", return_value=host()), patch(
        "agentporter.tools.scinet._socket_available", return_value=True
    ), patch("agentporter.tools.scinet.run_host_bytes", return_value=raw):
        result = create_scinet_tool(registry(), settings())("asgard", "gpu_nodes")
    assert result["stdout"] == "" and result["stderr"] == ""
    assert "hidden-value" not in str(result) and "hidden-token" not in str(result)


def test_rest_action_is_schema_visible_bounded_and_permission_gated():
    with TemporaryDirectory() as root:
        config = SimpleNamespace(
            state_dir=Path(root),
            config_dir=Path(root).with_name(Path(root).name + "-operator-config"),
            workspaces={"asgard": {"path": root}},
            server=ServerSettings(action_prefix="asgard"),
            sandbox=SandboxSettings(),
            security=SecuritySettings(allowed_hosts=["testserver"]),
            api_key="synthetic-test-key",
        )
        with TestClient(create_asgi_app(config)) as client:
            schema = client.get("/openapi.json").json()
            operation = schema["paths"][
                "/api/v1/workspaces/{workspace_id}/scinet/diagnostic"
            ]["post"]
            assert operation["operationId"] == "asgard_scinet_diagnostic"
            assert len([method for path in schema["paths"].values() for method in path]) <= 30
            login_actions = schema["components"]["schemas"]["ScinetSetupRequest"][
                "properties"]["action"]["enum"]
            assert {"login_start", "login_status"} <= set(login_actions)
            assert client.post(
                "/api/v1/workspaces/asgard/scinet/diagnostic",
                json={"command": "gpu_nodes"},
                headers={"Authorization": "Bearer synthetic-test-key"},
            ).status_code == 403
            assert client.post(
                "/api/v1/workspaces/asgard/scinet/diagnostic",
                json={"command": "uname -a"},
                headers={"Authorization": "Bearer synthetic-test-key"},
            ).status_code == 422
            setup = schema["paths"][
                "/api/v1/workspaces/{workspace_id}/scinet/setup"
            ]["post"]
            assert len(setup["description"]) <= 300
            assert client.post(
                "/api/v1/workspaces/asgard/scinet/setup",
                json={"action": "login_start"},
                headers={"Authorization": "Bearer synthetic-test-key"},
            ).status_code == 403


def test_training_actions_are_schema_visible_but_separate_from_diagnostics():
    with TemporaryDirectory() as root:
        config = SimpleNamespace(
            state_dir=Path(root),
            config_dir=Path(root).with_name(Path(root).name + "-operator-config"),
            workspaces={"asgard": {"path": root}},
            server=ServerSettings(action_prefix="asgard"),
            sandbox=SandboxSettings(),
            security=SecuritySettings(allowed_hosts=["testserver"]),
            api_key="synthetic-test-key",
        )
        with TestClient(create_asgi_app(config)) as client:
            paths = client.get("/openapi.json").json()["paths"]
    expected = {
        "/api/v1/workspaces/{workspace_id}/scinet/stage": "asgard_scinet_stage",
        "/api/v1/workspaces/{workspace_id}/scinet/submit": "asgard_scinet_submit",
        "/api/v1/workspaces/{workspace_id}/scinet/job-status": "asgard_scinet_job_status",
        "/api/v1/workspaces/{workspace_id}/scinet/job-logs": "asgard_scinet_job_logs",
        "/api/v1/workspaces/{workspace_id}/scinet/setup": "asgard_scinet_setup",
    }
    for path, operation_id in expected.items():
        assert paths[path]["post"]["operationId"] == operation_id
