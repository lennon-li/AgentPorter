import threading
import time
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentporter.tools.scinet_broker import (
    ScinetBroker,
    DUO_PUSH_PROMPT,
    _has_duo_push_prompt,
    _login_failure_reason,
    broker_request,
    broker_socket_available,
)


def test_only_expected_duo_choice_prompt_triggers_push_selection():
    assert DUO_PUSH_PROMPT.search(b"Passcode or option (1-1):")
    assert _has_duo_push_prompt(b"Passcode or option (1-1):")
    assert _has_duo_push_prompt(b"\x1b[1mPasscode or option (1-1):\x1b[0m\r")
    assert _has_duo_push_prompt(b"\r\nPasscode  or option (1-1) :  ")
    assert not DUO_PUSH_PROMPT.search(b"Password:")
    assert not _has_duo_push_prompt(b"Password:")
    assert not _has_duo_push_prompt(b"Duo Push? (y/n):")
    assert not DUO_PUSH_PROMPT.search(b"Duo Push? (y/n):")


@pytest.mark.parametrize(
    ("output", "push_requested", "exit_status", "timed_out", "expected"),
    [
        (b"Permission denied (keyboard-interactive,hostbased).", False, 255, False, "authentication_rejected"),
        (b"Host key verification failed.", False, 255, False, "host_key_failed"),
        (b"ssh: Could not resolve hostname host: Name or service not known", False, 255, False, "dns_failed"),
        (b"connect to host port 22: Connection refused", False, 255, False, "connection_refused"),
        (b"", False, 127, False, "ssh_start_failed"),
        (b"", False, 255, True, "no_ssh_prompt"),
        (b"Duo two-factor login", False, 255, True, "duo_prompt_unrecognized"),
        (b"Verification code:", False, 255, True, "authentication_prompt_unrecognized"),
        (b"", True, 255, True, "duo_approval_timeout"),
    ],
)
def test_login_failure_reporting_is_classified_and_redacted(
    output, push_requested, exit_status, timed_out, expected
):
    reason = _login_failure_reason(
        output,
        push_requested=push_requested,
        exit_status=exit_status,
        timed_out=timed_out,
    )
    assert reason == expected
    if output:
        assert output.decode(errors="ignore") not in reason


def _unix_sockets_available() -> bool:
    try:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.close()
        return True
    except OSError:
        return False


UNIX_SOCKETS_AVAILABLE = _unix_sockets_available()


def test_broker_envelope_pins_destination_and_disables_forwarding(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )

    from agentporter.tools.scinet_broker import _ssh_envelope

    argv = _ssh_envelope(
        broker.host,
        broker.user,
        broker.control_socket,
        ["sinfo", "-h", "-o", "%P|%D|%t|%G"],
    )
    assert argv[0] == "/usr/bin/ssh"
    import shlex

    assert shlex.split(argv[-1]) == ["/bin/bash", "-lc", "exec /usr/bin/timeout 120s sinfo -h -o '%P|%D|%t|%G'"]
    assert "-n" not in argv
    assert "-o" in argv and "ForwardAgent=no" in argv
    assert "ProxyCommand=/bin/false" in argv
    assert broker.host in argv
    assert broker.user in argv


def test_broker_remote_shell_preserves_command_and_staging_input(tmp_path):
    import subprocess
    import sys

    from agentporter.tools.scinet_broker import _ssh_envelope

    argv = _ssh_envelope(
        "trillium-gpu.alliancecan.ca",
        "yeli",
        str(tmp_path / "control.sock"),
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
    )
    payload = b"bounded staging payload\n"
    result = subprocess.run(
        ["/bin/sh", "-c", argv[-1]],
        input=payload,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == payload


def test_broker_rejects_ssh_like_remote_tokens(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    with patch("agentporter.tools.scinet_broker._control_socket_available", return_value=True):
        with pytest.raises(PermissionError):
            broker._request(
                {"version": 1, "operation": "training", "remote": ["ssh", "other"]},
                b"",
            )


def test_login_argv_allows_host_public_key_then_duo_with_fixed_target(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    argv = broker._login_argv()
    assert argv[0] == "/usr/bin/ssh"
    assert argv[-2:] == ["yeli", "trillium-gpu.alliancecan.ca"]
    assert "-M" in argv and "-f" in argv
    assert "PreferredAuthentications=publickey,keyboard-interactive" in argv
    assert "PubkeyAuthentication=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "ClearAllForwardings=yes" in argv
    assert "ForwardAgent=no" in argv
    assert "ServerAliveInterval=30" in argv
    assert "ServerAliveCountMax=3" in argv
    assert not any(arg in {"-L", "-R", "-D", "-W"} for arg in argv)
    assert not any(arg.startswith("ProxyCommand=") for arg in argv)


@pytest.mark.parametrize("timeout_probe", [False, True])
def test_master_health_requires_remote_response_not_just_mux_listener(tmp_path, timeout_probe):
    import subprocess

    broker = ScinetBroker(str(tmp_path / "broker.sock"), str(tmp_path / "control.sock"),
                          "trillium-gpu.alliancecan.ca", "yeli")
    probe = subprocess.TimeoutExpired("ssh", 5) if timeout_probe else SimpleNamespace(returncode=255)
    with (
        patch("agentporter.tools.scinet_broker._control_socket_available", return_value=True),
        patch("agentporter.tools.scinet_broker.subprocess.run",
              side_effect=[SimpleNamespace(returncode=0), probe]) as run,
    ):
        assert broker._master_is_running() is False
        argv = run.call_args.args[0]
        assert argv[-1] == "/usr/bin/true"
        assert "ProxyCommand=/bin/false" in argv
        assert "BatchMode=yes" in argv
        assert run.call_args.kwargs["timeout"] == 5


def test_stale_authenticated_status_is_reported_as_connection_failure(tmp_path):
    broker = ScinetBroker(str(tmp_path / "broker.sock"), str(tmp_path / "control.sock"),
                          "trillium-gpu.alliancecan.ca", "yeli")
    broker._login_state = "authenticated"
    with patch.object(broker, "_master_is_running", return_value=False):
        assert broker._login_status() == {
            "state": "failed", "success": False, "reason": "scinet_connection_unresponsive",
        }


def test_login_status_only_reports_verified_master(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    request = {
        "version": 1,
        "operation": "login",
        "command": "status",
        "remote": [],
        "input_length": 0,
    }
    with patch.object(broker, "_master_is_running", return_value=False):
        assert broker._request(request, b"") == {"state": "not_started", "success": False}
    with patch.object(broker, "_master_is_running", return_value=True):
        assert broker._request(request, b"") == {"state": "authenticated", "success": True}


def test_login_rpc_rejects_caller_supplied_remote_command(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    request = {
        "version": 1,
        "operation": "login",
        "command": "start",
        "remote": ["uname", "-a"],
        "input_length": 0,
    }
    with pytest.raises(ValueError, match="invalid SciNet login request"):
        broker._request(request, b"")


def test_first_login_not_cooldown_on_short_host_uptime(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    request = {
        "version": 1,
        "operation": "login",
        "command": "start",
        "remote": [],
        "input_length": 0,
    }
    with (
        patch.object(broker, "_master_is_running", return_value=False),
        patch("agentporter.tools.scinet_broker.os.path.lexists", return_value=False),
        patch("agentporter.tools.scinet_broker.pty.fork", return_value=(123, 456)) as fork,
        patch("agentporter.tools.scinet_broker.threading.Thread.start"),
        patch("agentporter.tools.scinet_broker.time.monotonic", return_value=15.0),
    ):
        assert broker._request(request, b"") == {"state": "starting", "success": False}
        fork.assert_called_once()


def test_login_start_is_single_flight_and_rate_limited(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    request = {
        "version": 1,
        "operation": "login",
        "command": "start",
        "remote": [],
        "input_length": 0,
    }
    with (
        patch.object(broker, "_master_is_running", return_value=False),
        patch("agentporter.tools.scinet_broker.os.path.lexists", return_value=False),
        patch("agentporter.tools.scinet_broker.pty.fork", return_value=(123, 456)) as fork,
        patch("agentporter.tools.scinet_broker.threading.Thread.start"),
    ):
        assert broker._request(request, b"") == {"state": "starting", "success": False}
        assert broker._request(request, b"") == {"state": "starting", "success": False}
        fork.assert_called_once()
        with broker._login_lock:
            broker._login_state = "failed"
        assert broker._request(request, b"") == {
            "state": "cooldown", "success": False, "reason": "retry_cooldown"
        }


@pytest.mark.skipif(not UNIX_SOCKETS_AVAILABLE, reason="sandbox disallows Unix sockets")
def test_broker_round_trip_uses_unix_socket_and_returns_bounded_result(tmp_path):
    socket_path = str(tmp_path / "broker.sock")
    broker = ScinetBroker(
        socket_path,
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    raw = {
        "exit_code": 0,
        "stdout": b"compute|up\n",
        "stderr": b"",
        "timed_out": False,
        "truncated": False,
    }
    with (
        patch("agentporter.tools.scinet_broker._control_socket_available", return_value=True),
        patch("agentporter.tools.scinet_broker.run_host_bytes", return_value=raw),
    ):
        threading.Thread(target=broker.serve, daemon=True).start()
        for _ in range(50):
            if broker_socket_available(socket_path):
                break
            time.sleep(0.01)
        settings = SimpleNamespace(broker_socket=socket_path)
        result = broker_request(
            settings,
            ["sinfo", "-h", "-o", "%P|%D|%t|%G"],
            operation="diagnostic",
            command="gpu_partitions",
        )

    assert result["exit_code"] == 0
    assert result["stdout"] == b"compute|up\n"


def test_broker_does_not_accept_client_supplied_destination(tmp_path):
    broker = ScinetBroker(
        str(tmp_path / "broker.sock"),
        str(tmp_path / "control.sock"),
        "trillium-gpu.alliancecan.ca",
        "yeli",
    )
    with (
        patch("agentporter.tools.scinet_broker._control_socket_available", return_value=True),
        patch("agentporter.tools.scinet_broker.run_host_bytes", return_value={
            "exit_code": 0,
            "stdout": b"",
            "stderr": b"",
            "timed_out": False,
            "truncated": False,
        }) as run,
    ):
        broker._request(
            {"version": 1, "operation": "diagnostic", "command": "connection_status", "remote": ["true"]},
            b"",
        )
    called = run.call_args.args[0]
    assert "trillium-gpu.alliancecan.ca" in called
    assert "other-host" not in called
