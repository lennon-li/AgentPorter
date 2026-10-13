"""Fixed-target, read-only SciNet diagnostics through an existing SSH master."""

import os
import pwd
import shlex
import socket
import stat
from typing import Literal

from agentporter.tools.venkata import run_host_bytes
from agentporter.tools.scinet_broker import broker_request, broker_socket_available

ScinetDiagnostic = Literal[
    "gpu_partitions",
    "gpu_nodes",
    "gpu_allocations",
    "connection_status",
]

MAX_OUTPUT = 65536
TIMEOUT = 30
REMOTE_TIMEOUT = "25s"


def control_socket(settings, home: str) -> str:
    """Resolve the private deployment socket, constrained to the user's SSH dir."""
    raw = str(getattr(settings, "control_socket", ""))
    if raw == "~":
        raw = home
    elif raw.startswith("~/"):
        raw = os.path.join(home, raw[2:])
    configured = os.path.realpath(raw)
    ssh_dir = os.path.realpath(os.path.join(home, ".ssh"))
    if not configured or os.path.commonpath([configured, ssh_dir]) != ssh_dir:
        raise PermissionError("SciNet control socket configuration is invalid")
    return configured


def _socket_available(path: str) -> bool:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022


def remote_argv(command: ScinetDiagnostic) -> list[str] | None:
    """Map the enum to a fixed remote command; never accept shell text."""
    fixed = {
        # Alliance environments expose Slurm through the login environment;
        # do not assume sinfo/squeue live under /usr/bin on every cluster.
        "gpu_partitions": ["sinfo", "-h", "-o", "%P|%D|%t|%G"],
        "gpu_nodes": ["sinfo", "-N", "-h", "-o", "%N|%G|%t"],
        # squeue reports jobs and requested/allocated resources. It is intentionally
        # separate from sinfo so callers cannot mistake installed capacity for free GPUs.
        "gpu_allocations": ["squeue", "-h", "-o", "%i|%P|%T|%b|%D|%j"],
    }
    if command == "connection_status":
        return None
    try:
        return fixed[command]
    except KeyError as exc:
        raise ValueError("SciNet diagnostic command is not allowed") from exc


def ssh_argv(settings, home: str, command: ScinetDiagnostic) -> list[str]:
    """Build fixed SSH arguments with no caller-controlled destination or options."""
    socket_path = control_socket(settings, home)
    remote = remote_argv(command)
    argv = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-S",
        socket_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ProxyCommand=/bin/false",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPersist=no",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "HostbasedAuthentication=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
    ]
    if remote is None:
        argv.extend(["-O", "check"])
    else:
        argv.extend(["-n"])
    argv.extend(["-l", settings.user, settings.host])
    if remote is not None:
        # SSH exec requests do not necessarily source the cluster's login
        # profile. Use a fixed login shell so Slurm's site-provided PATH and
        # module setup are available; every command/token remains server-side
        # allowlisted and shell-quoted.
        command = shlex.join(["exec", "/usr/bin/timeout", REMOTE_TIMEOUT, *remote])
        argv.append(shlex.join(["/bin/bash", "-lc", command]))
    return argv


def ssh_remote_argv(
    settings,
    home: str,
    remote: list[str],
    *,
    timeout_text: str = REMOTE_TIMEOUT,
    accepts_stdin: bool = False,
) -> list[str]:
    """Build the fixed SSH envelope for server-generated remote commands."""
    socket_path = control_socket(settings, home)
    argv = [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-S", socket_path,
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ProxyCommand=/bin/false", "-o", "ControlMaster=no",
        "-o", "ControlPersist=no", "-o", "IdentityAgent=none",
        "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "HostbasedAuthentication=no",
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
    ]
    if not accepts_stdin:
        argv.append("-n")
    argv.extend(["-l", settings.user, settings.host])
    command = shlex.join(["exec", "/usr/bin/timeout", timeout_text, *remote])
    argv.append(shlex.join(["/bin/bash", "-lc", command]))
    return argv


def run_scinet_bytes(
    settings,
    user,
    remote: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: float = 60,
    max_output: int = 256 * 1024,
    operation: str = "training",
    command: str | None = None,
) -> dict:
    """Run through the broker when configured; retain legacy fallback only for deployment migration."""
    broker_socket = str(getattr(settings, "broker_socket", "") or "").strip()
    if broker_socket:
        return broker_request(
            settings,
            remote,
            input_bytes=input_bytes,
            timeout=timeout,
            max_output=max_output,
            operation=operation,
            command=command,
        )
    return run_host_bytes(
        ssh_remote_argv(
            settings,
            user.pw_dir,
            remote,
            timeout_text=f"{max(1, int(timeout))}s",
            accepts_stdin=input_bytes is not None,
        ),
        user.pw_dir,
        input_bytes=input_bytes,
        max_output=max_output,
        timeout=timeout + 5,
    )


def _decode(value: bytes | str) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def _redact(value: str, home: str) -> str:
    # Do not return local paths or values that could be copied from SSH diagnostics.
    return value.replace(home, "<home>")


def _failure(command: ScinetDiagnostic, error: str) -> dict:
    return {
        "target": "scinet",
        "command": command,
        "success": False,
        "error": error,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "truncated": False,
    }


def host_identity(registry, workspace_id: str, settings):
    if not settings or not all(
        getattr(settings, field, "")
        for field in ("host", "user", "machine")
    ):
        raise PermissionError("SciNet endpoint is not configured for this AgentPorter instance")
    if not getattr(settings, "broker_socket", "") and not getattr(settings, "control_socket", ""):
        raise PermissionError("SciNet endpoint transport is not configured")
    ws = registry.get(workspace_id)
    if not ws.allow_execute or not ws.allow_scinet_diagnostic:
        raise PermissionError(
            "SciNet diagnostics require explicit workspace execution and SciNet permission"
        )
    user = pwd.getpwuid(os.getuid())
    if user.pw_name != settings.user or socket.gethostname().split(".")[0] != settings.machine:
        raise PermissionError("SciNet diagnostics require the configured host identity")
    return user


def create_scinet_tool(registry, settings=None):
    def scinet_diagnostic(workspace_id: str, command: ScinetDiagnostic) -> dict:
        user = host_identity(registry, workspace_id, settings)
        if command not in {
            "gpu_partitions",
            "gpu_nodes",
            "gpu_allocations",
            "connection_status",
        }:
            raise ValueError("SciNet diagnostic command is not allowed")

        broker_socket = str(getattr(settings, "broker_socket", "") or "").strip()
        if broker_socket:
            if not broker_socket_available(broker_socket):
                return _failure(command, "scinet_broker_unavailable")
            result = run_scinet_bytes(
                settings,
                user,
                remote_argv(command) or [],
                max_output=MAX_OUTPUT,
                timeout=TIMEOUT,
                operation="diagnostic",
                command=command,
            )
        else:
            socket_path = control_socket(settings, user.pw_dir)
            if not _socket_available(socket_path):
                return _failure(command, "ssh_control_socket_unavailable")
            result = run_host_bytes(
                ssh_argv(settings, user.pw_dir, command),
                user.pw_dir,
                max_output=MAX_OUTPUT,
                timeout=TIMEOUT,
            )

        result["target"] = "scinet"
        result["command"] = command
        result["success"] = (
            result.get("exit_code") == 0
            and not result.get("timed_out", False)
            and not result.get("truncated", False)
        )
        result["stdout"] = (
            "SSH master is available" if command == "connection_status" and result["success"]
            else _redact(_decode(result.get("stdout", b"")), user.pw_dir) if result["success"]
            else ""
        )
        result["stderr"] = ""
        if not result["success"] and result.get("error") is None:
            result["error"] = (
                "ssh_timeout" if result.get("timed_out")
                else "output_truncated" if result.get("truncated")
                else "ssh_command_failed"
            )
        return result

    return scinet_diagnostic
