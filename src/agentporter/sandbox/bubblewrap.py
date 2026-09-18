"""Bubblewrap (bwrap) unprivileged namespace sandbox backend."""

import os
import time
import shutil
import signal
import subprocess
import logging
from pathlib import Path
from agentporter.sandbox.base import SandboxBackend

logger = logging.getLogger("agentporter.sandbox.bwrap")


class BubblewrapSandbox(SandboxBackend):
    """Linux Bubblewrap sandbox providing filesystem, network, and environment isolation."""

    def __init__(
        self,
        state_dir: Path,
        default_timeout_seconds: int = 30,
        max_timeout_seconds: int = 900,
        max_output_bytes: int = 100 * 1024,
    ):
        self.state_dir = state_dir
        self.default_timeout_seconds = max(1, int(default_timeout_seconds))
        self.max_timeout_seconds = max(self.default_timeout_seconds, int(max_timeout_seconds))
        self.max_output_bytes = max(1024, int(max_output_bytes))
        self.etc_dir = state_dir / "etc"
        self.etc_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.etc_dir, 0o700)
        except OSError:
            pass
        self.passwd_file = self.etc_dir / "passwd"
        self.group_file = self.etc_dir / "group"
        self._ensure_synthetic_identity()

    def _ensure_synthetic_identity(self) -> None:
        uid = os.getuid()
        gid = os.getgid()
        if not self.passwd_file.exists():
            self.passwd_file.write_text(
                f"root:x:0:0:root:/tmp:/bin/bash\n"
                f"sandbox:x:{uid}:{gid}:Sandbox User:/tmp:/bin/bash\n"
                "nobody:x:65534:65534:nobody:/tmp:/bin/false\n",
                encoding="utf-8",
            )
        if not self.group_file.exists():
            self.group_file.write_text(
                f"root:x:0:\nsandbox:x:{gid}:\nnobody:x:65534:\n",
                encoding="utf-8",
            )
        for p in (self.passwd_file, self.group_file):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass

    def is_available(self) -> bool:
        return shutil.which("bwrap") is not None

    def build_bwrap_args(self, workspace_path: str, writable: bool = True, sub_cwd: str = "") -> list[str]:
        real_workspace = os.path.realpath(workspace_path)
        if not os.path.isdir(real_workspace):
            raise ValueError(f"Workspace path does not exist: {real_workspace}")

        target_cwd = "/workspace"
        if sub_cwd:
            if os.path.isabs(sub_cwd):
                raise ValueError(f"Invalid sub_cwd: {sub_cwd}")
            rel_sub = os.path.normpath(sub_cwd)
            if rel_sub == ".." or rel_sub.startswith("../"):
                raise ValueError(f"Invalid sub_cwd: {sub_cwd}")
            full_sub = os.path.realpath(os.path.join(real_workspace, rel_sub))
            if not (full_sub == real_workspace or full_sub.startswith(real_workspace + os.sep)):
                raise ValueError(f"sub_cwd escapes workspace: {sub_cwd}")
            target_cwd = os.path.join("/workspace", rel_sub)

        args = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/etc/alternatives", "/etc/alternatives",
            "--ro-bind", str(self.passwd_file), "/etc/passwd",
            "--ro-bind", str(self.group_file), "/etc/group",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
        ]

        for opt_dir in ["/etc/R", "/etc/ssl/certs", "/etc/resolv.conf"]:
            if os.path.exists(opt_dir):
                args.extend(["--ro-bind", opt_dir, opt_dir])

        args.extend([
            "--bind" if writable else "--ro-bind",
            real_workspace,
            "/workspace",
            "--unshare-all",
            "--unshare-net",
            "--clearenv",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "USER", "sandbox",
            "--setenv", "LOGNAME", "sandbox",
            "--setenv", "LC_ALL", "C.UTF-8",
            "--setenv", "LANG", "C.UTF-8",
            "--chdir", target_cwd,
        ])
        return args

    def clamp_timeout(self, timeout_seconds: int | None) -> int:
        requested = self.default_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
        if requested <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return min(requested, self.max_timeout_seconds)

    def run(
        self,
        workspace_path: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int | None = None,
        writable: bool = True,
        max_output_bytes: int | None = None,
    ) -> dict:
        if not argv or not isinstance(argv, list) or not all(isinstance(x, str) and x for x in argv):
            raise ValueError("argv must be a non-empty list of non-empty strings")

        timeout = self.clamp_timeout(timeout_seconds)
        output_limit = min(
            max(1024, int(max_output_bytes or self.max_output_bytes)),
            self.max_output_bytes,
        )
        full_cmd = self.build_bwrap_args(
            workspace_path, writable=writable, sub_cwd=cwd
        ) + ["--"] + argv

        t0 = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                process_group=0,
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
                stdout, stderr = proc.communicate()
            else:
                stdout, stderr = "", ""
            exit_code = 124
        except Exception as e:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Sandbox execution error: {e}",
                "duration": time.time() - t0,
                "truncated": False,
                "timed_out": False,
            }

        truncated = False
        stdout_b = stdout.encode("utf-8")
        stderr_b = stderr.encode("utf-8")
        if len(stdout_b) > output_limit:
            stdout = stdout_b[:output_limit].decode("utf-8", errors="replace") + "\n... [STDOUT TRUNCATED]"
            truncated = True
        if len(stderr_b) > output_limit:
            stderr = stderr_b[:output_limit].decode("utf-8", errors="replace") + "\n... [STDERR TRUNCATED]"
            truncated = True

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration": time.time() - t0,
            "truncated": truncated,
            "timed_out": timed_out,
            "timeout_seconds": timeout,
        }
