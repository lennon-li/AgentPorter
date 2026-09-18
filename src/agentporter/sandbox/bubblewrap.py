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

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.etc_dir = state_dir / "etc"
        self.etc_dir.mkdir(parents=True, exist_ok=True)
        self.passwd_file = self.etc_dir / "passwd"
        self.group_file = self.etc_dir / "group"
        self._ensure_synthetic_identity()

    def _ensure_synthetic_identity(self) -> None:
        """Create synthetic passwd and group files to isolate host identity."""
        if not self.passwd_file.exists():
            with open(self.passwd_file, "w", encoding="utf-8") as f:
                f.write("root:x:0:0:root:/tmp:/bin/bash\n"
                        "sandbox:x:1000:1000:Sandbox User:/tmp:/bin/bash\n"
                        "nobody:x:65534:65534:nobody:/tmp:/bin/false\n")

        if not self.group_file.exists():
            with open(self.group_file, "w", encoding="utf-8") as f:
                f.write("root:x:0:\nsandbox:x:1000:\nnobody:x:65534:\n")

    def is_available(self) -> bool:
        return shutil.which("bwrap") is not None

    def build_bwrap_args(self, workspace_path: str, writable: bool = True, sub_cwd: str = "") -> list[str]:
        real_workspace = os.path.realpath(workspace_path)
        if not os.path.isdir(real_workspace):
            raise ValueError(f"Workspace path does not exist: {real_workspace}")

        target_cwd = "/workspace"
        if sub_cwd:
            rel_sub = os.path.normpath(sub_cwd).lstrip("/")
            if rel_sub.startswith("..") or os.path.isabs(rel_sub):
                raise ValueError(f"Invalid sub_cwd: {sub_cwd}")
            full_sub = os.path.realpath(os.path.join(real_workspace, rel_sub))
            if not (full_sub == real_workspace or full_sub.startswith(real_workspace + os.sep)):
                raise ValueError(f"sub_cwd escapes workspace: {sub_cwd}")
            target_cwd = os.path.join("/workspace", rel_sub)

        args = [
            "bwrap",
            # Read-only standard root paths
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/etc/alternatives", "/etc/alternatives",
            "--ro-bind", str(self.passwd_file), "/etc/passwd",
            "--ro-bind", str(self.group_file), "/etc/group",
            # System essentials
            "--proc", "/proc",
            "--dev", "/dev",
            # Isolated private temporary filesystem
            "--tmpfs", "/tmp",
        ]

        # Optional read-only binds if they exist
        for opt_dir in ["/etc/R", "/etc/ssl/certs", "/etc/resolv.conf"]:
            if os.path.exists(opt_dir):
                args.extend(["--ro-bind", opt_dir, opt_dir])

        # Mount workspace
        if writable:
            args.extend(["--bind", real_workspace, "/workspace"])
        else:
            args.extend(["--ro-bind", real_workspace, "/workspace"])

        # Unshare namespaces and clear environment
        args.extend([
            "--unshare-all",
            "--unshare-net",
            "--clearenv",
            # Synthetic safe minimal environment
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "USER", "sandbox",
            "--setenv", "LOGNAME", "sandbox",
            "--setenv", "LC_ALL", "C.UTF-8",
            "--setenv", "LANG", "C.UTF-8",
            # Chdir into workspace
            "--chdir", target_cwd,
        ])

        return args

    def run(
        self,
        workspace_path: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30,
        writable: bool = True,
        max_output_bytes: int = 100 * 1024,
    ) -> dict:
        if not argv or not isinstance(argv, list):
            raise ValueError("argv must be a non-empty list of strings")

        bwrap_prefix = self.build_bwrap_args(workspace_path, writable=writable, sub_cwd=cwd)
        full_cmd = bwrap_prefix + ["--"] + argv

        t0 = time.time()
        timed_out = False
        proc = None

        try:
            proc = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                process_group=0  # Safe in multi-threaded Python >= 3.11
            )
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            duration = time.time() - t0
            logger.warning("Execution timed out after %ds: %s", timeout_seconds, argv)
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
            duration = time.time() - t0
            logger.error("Sandbox execution failed: %s", e)
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Sandbox execution error: {e}",
                "duration": duration,
                "truncated": False,
                "timed_out": False,
            }

        duration = time.time() - t0
        truncated = False

        if len(stdout.encode("utf-8")) > max_output_bytes:
            stdout = stdout.encode("utf-8")[:max_output_bytes].decode("utf-8", errors="replace") + "\n... [STDOUT TRUNCATED]"
            truncated = True

        if len(stderr.encode("utf-8")) > max_output_bytes:
            stderr = stderr.encode("utf-8")[:max_output_bytes].decode("utf-8", errors="replace") + "\n... [STDERR TRUNCATED]"
            truncated = True

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration": duration,
            "truncated": truncated,
            "timed_out": timed_out,
        }
