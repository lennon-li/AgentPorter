import threading
import time
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentporter.tools.scinet_broker import (
    ScinetBroker,
    broker_request,
    broker_socket_available,
)


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
