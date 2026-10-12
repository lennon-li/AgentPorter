"""Opt-in, fixed-target Venkata diagnostics using the gateway's host identity."""

import os
import pwd
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import time
from typing import Literal

Diagnostic = Literal["hostname", "nvidia-smi", "nproc", "free", "df", "cuda_version", "torch_status"]
GPU_FIELDS = frozenset({"index", "name", "uuid", "memory.total", "memory.used",
                        "memory.free", "utilization.gpu", "driver_version", "temperature.gpu"})
MAX_OUTPUT = 65536
TIMEOUT = 30


def access_enabled(home: str) -> bool:
    marker = os.path.join(home, ".config", "agentporter", "venkata-access.enabled")
    try:
        info = os.stat(marker, follow_symlinks=False)
        return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o022)
    except OSError:
        return False


def remote_argv(command: Diagnostic, args: list[str]) -> list[str]:
    if not isinstance(args, list) or len(args) > 3 or any(
        not isinstance(arg, str) or not arg or len(arg) > 256 for arg in args
    ):
        raise ValueError("Invalid diagnostic arguments")
    fixed = {
        "hostname": ["/usr/bin/hostname"], "nproc": ["/usr/bin/nproc"],
        "free": ["/usr/bin/free", "-h"], "df": ["/usr/bin/df", "-h"],
        "cuda_version": ["/usr/local/cuda/bin/nvcc", "--version"],
        "torch_status": ["/usr/bin/python3", "-I", "-c",
                         "import torch; print('torch:', torch.__version__); "
                         "print('cuda:', torch.version.cuda); "
                         "print('available:', torch.cuda.is_available()); "
                         "print('devices:', torch.cuda.device_count())"],
    }
    if command in fixed:
        if args:
            raise ValueError("This diagnostic accepts no arguments")
        return fixed[command]
    if command != "nvidia-smi":
        raise ValueError("Diagnostic is not allowed")
    if not args:
        return ["/usr/bin/nvidia-smi"]
    query = next((arg for arg in args if arg.startswith("--query-gpu=")), None)
    fmt = next((arg for arg in args if arg.startswith("--format=")), None)
    gpu = next((arg for arg in args if arg.startswith("--id=")), None)
    if not query or not fmt or len(args) != 2 + bool(gpu):
        raise ValueError("Only GPU query, CSV format and optional numeric GPU IDs are allowed")
    fields = query.partition("=")[2].split(",")
    if not fields or any(field not in GPU_FIELDS for field in fields) or len(set(fields)) != len(fields):
        raise ValueError("GPU query fields are not allowed")
    if fmt not in {"--format=csv", "--format=csv,noheader", "--format=csv,nounits",
                   "--format=csv,noheader,nounits"}:
        raise ValueError("GPU query format is not allowed")
    if gpu and not re.fullmatch(r"--id=[0-9]{1,2}(,[0-9]{1,2})*", gpu):
        raise ValueError("GPU IDs must be numeric")
    return ["/usr/bin/nvidia-smi", query, fmt, *([gpu] if gpu else [])]


def run_bounded(argv: list[str], home: str) -> dict:
    env = {"HOME": home, "USER": "yeli", "LOGNAME": "yeli",
           "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = truncated = False
    with subprocess.Popen(argv, cwd=home, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
                selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
                deadline = time.monotonic() + TIMEOUT
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        room = MAX_OUTPUT - sum(map(len, output.values()))
                        output[key.data].extend(chunk[:room])
                        if len(chunk) > room:
                            truncated = True
                            break
                    if truncated:
                        break
                if not timed_out and not truncated:
                    try:
                        proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        timed_out = True
        finally:
            if timed_out or truncated or proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
    return {"target": "venkata", "exit_code": proc.returncode,
            "stdout": output["stdout"].decode("utf-8", errors="replace"),
            "stderr": output["stderr"].decode("utf-8", errors="replace"),
            "timed_out": timed_out, "truncated": truncated}


def create_venkata_tool(registry):
    def venkata_diagnostic(workspace_id: str, command: Diagnostic, args: list[str] | None = None) -> dict:
        ws = registry.get(workspace_id)
        if not ws.allow_execute or not ws.allow_venkata_ssh:
            raise PermissionError("Venkata SSH requires explicit workspace opt-in and execution permission")
        user = pwd.getpwuid(os.getuid())
        if user.pw_name != "yeli" or socket.gethostname().split(".")[0] not in {"bcc", "pho-rdpdl-23"}:
            raise PermissionError("Venkata diagnostics require the BCC yeli host identity")
        if not access_enabled(user.pw_dir):
            raise PermissionError("Venkata access is OFF; enable locally with venkata-access on")
        remote = remote_argv(command, [] if args is None else args)
        # SSH invokes a remote shell: quote only server-validated tokens, never caller shell text.
        remote_command = shlex.join(["/usr/bin/timeout", "25s", *remote])
        argv = ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
                "-o", "ClearAllForwardings=yes", "venkata", remote_command]
        return run_bounded(argv, user.pw_dir)
    return venkata_diagnostic
