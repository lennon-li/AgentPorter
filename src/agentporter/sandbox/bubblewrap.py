"""Bubblewrap (bwrap) unprivileged namespace sandbox backend."""

import os
import selectors
import time
import shutil
import signal
import subprocess
import logging
import tempfile
from pathlib import Path
from agentporter.sandbox.base import SandboxBackend
from agentporter.tooling import add_tooling_mounts
from agentporter.process_handles import open_handle, signal_handle
from agentporter.resources import ResourceCleanupError

logger = logging.getLogger("agentporter.sandbox.bwrap")


class BubblewrapSandbox(SandboxBackend):
    """Linux Bubblewrap sandbox providing filesystem, network, and environment isolation."""

    def __init__(
        self,
        state_dir: Path,
        default_timeout_seconds: int = 30,
        max_timeout_seconds: int = 900,
        max_output_bytes: int = 100 * 1024,
        transactional_writes: bool = False,
    ):
        self.state_dir = state_dir
        self.resources = None
        self.transactional_writes = transactional_writes
        self._unresolved_transactions = []
        if transactional_writes:
            from agentporter.agents.development import DevelopmentRuntime
            self.transaction_executable = DevelopmentRuntime._sandbox_executable(
                {'sandbox_executable': '/opt/agentporter-bcc/bin/bwrap'})
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
        records = {
            self.passwd_file: (
                f"root:x:0:0:root:/tmp:/bin/bash\n"
                f"sandbox:x:{uid}:{gid}:Sandbox User:/tmp:/bin/bash\n"
                "nobody:x:65534:65534:nobody:/tmp:/bin/false\n"
            ),
            self.group_file: f"root:x:0:\nsandbox:x:{gid}:\nnobody:x:65534:\n",
        }
        for path, content in records.items():
            fd, name = tempfile.mkstemp(prefix=".identity-", dir=self.etc_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(content)
                os.replace(name, path)
            finally:
                Path(name).unlink(missing_ok=True)

    def is_available(self) -> bool:
        return shutil.which("bwrap") is not None

    def build_bwrap_args(
        self,
        workspace_path: str,
        writable: bool = True,
        sub_cwd: str = "",
        network_access: bool = False,
        git_metadata_writable: bool = False,
    ) -> list[str]:
        # Until a separate trusted approval issuer and constrained egress broker
        # exist, generic execution is deliberately offline. An API Boolean is
        # not proof of human authorization and must never expose host SSH/GH
        # credentials to arbitrary sandbox code.
        if network_access:
            raise PermissionError(
                "Networked generic execution requires independently verified "
                "approval and scoped egress; unavailable"
            )
        real_workspace = os.path.realpath(workspace_path)
        if not os.path.isdir(real_workspace):
            raise ValueError(f"Workspace path does not exist: {real_workspace}")
        self._ensure_synthetic_identity()

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
            # Kill the sandbox namespace with its launcher so background helpers
            # (dbus, git credential caches) cannot hold output pipes open.
            "--die-with-parent",
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

        for opt_dir in ["/etc/R", "/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts"]:
            if os.path.exists(opt_dir):
                args.extend(["--ro-bind", opt_dir, opt_dir])

        # A generic shell must not inherit host Git configuration (credential
        # helpers, hooks, or privileged includes).
        # Expose the explicitly supported development tools through read-only
        # mounts while keeping the host PATH and home directory isolated.
        add_tooling_mounts(args)

        args.extend([
            # Arbitrary commands never receive a canonical writable bind.
            # Supervised transaction wrapping replaces this read-only mount
            # with its private overlay. Only fixed trusted Git tools may opt
            # into canonical mutation through the separate metadata boundary.
            "--bind" if writable and git_metadata_writable else "--ro-bind",
            real_workspace,
            "/workspace",
            "--unshare-all",
        ])
        # Overmount a Git repository's control directory/file as read-only.
        # This is defense in depth, not an authorization boundary for nested
        # repositories, hardlinks, worker CLI access or external publishers.
        git_metadata = os.path.join(real_workspace, ".git")
        if os.path.islink(git_metadata):
            raise PermissionError("Symlinked .git metadata unsupported in generic execution")
        if os.path.lexists(git_metadata) and not git_metadata_writable:
            args.extend(["--ro-bind", git_metadata, "/workspace/.git"])
        # No host SSH/gh/agent socket mounts under any generic execution mode.
        # Network-dependent operations must use independently approved,
        # purpose-built tools, never host-user credential inheritance.
        args.append("--unshare-net")
        path_env = "/opt/agentporter/bin:/usr/local/bin:/usr/bin:/bin"

        args.extend([
            "--clearenv",
            "--setenv", "PATH", path_env,
            "--setenv", "HOME", "/tmp",
            "--setenv", "USER", "sandbox",
            "--setenv", "LOGNAME", "sandbox",
            "--setenv", "LC_ALL", "C.UTF-8",
            "--setenv", "LANG", "C.UTF-8",
            # The service UID may differ from the repository owner. Trust
            # only this explicitly mounted root, including commands in its
            # subdirectories; nested repositories remain independently gated.
            # Environment config is protected Git configuration, unlike the
            # repository-local config that cannot authorize its own owner.
            "--setenv", "GIT_CONFIG_COUNT", "1",
            "--setenv", "GIT_CONFIG_KEY_0", "safe.directory",
            "--setenv", "GIT_CONFIG_VALUE_0", "/workspace",
        ])
        args.extend(["--chdir", target_cwd])
        return args

    def clamp_timeout(self, timeout_seconds: int | None) -> int:
        requested = self.default_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
        if requested <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return min(requested, self.max_timeout_seconds)

    def run(
        self, workspace_path: str, argv: list[str], cwd: str = "",
        timeout_seconds: int | None = None, writable: bool = True,
        max_output_bytes: int | None = None, network_access: bool = False,
        git_metadata_writable: bool = False,
    ) -> dict:
        options = dict(workspace_path=workspace_path, argv=argv, cwd=cwd,
                       timeout_seconds=timeout_seconds, writable=writable,
                       max_output_bytes=max_output_bytes, network_access=network_access,
                       git_metadata_writable=git_metadata_writable)
        if not self.transactional_writes or git_metadata_writable:
            return self._run_command(**options)
        if self.resources is None:
            raise PermissionError('Transactional writes require a verified resource envelope')
        from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
        from agentporter.sandbox.workspace_delta import UnsafeWorkspaceDelta
        transaction = WorkspaceTransaction(Path(workspace_path), self.state_dir / 'workspace-transactions',
                                           writable=writable, git_sandbox=self)
        retain = False
        try:
            result = self._run_command(**options, workspace_transaction=transaction)
            if result['exit_code'] == 0:
                try:
                    transaction.publish()
                except (UnsafeWorkspaceDelta, OSError) as error:
                    result['exit_code'] = 1
                    result['stderr'] += f'\nWorkspace edit rejected: {error}'
            return result
        except ResourceCleanupError:
            retain = True
            self._unresolved_transactions.append(transaction)
            raise
        finally:
            if not retain:
                try:
                    transaction.close()
                except ResourceCleanupError:
                    self._unresolved_transactions.append(transaction)
                    raise

    def _run_command(
        self,
        workspace_path: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int | None = None,
        writable: bool = True,
        max_output_bytes: int | None = None,
        network_access: bool = False,
        git_metadata_writable: bool = False,
        workspace_transaction=None,
        require_resources: bool = False,
    ) -> dict:
        """Run a bounded command without ever accumulating unbounded pipe output.

        stdout/stderr are drained concurrently, each capped to output_limit.
        When either stream exceeds its budget, terminate the process group
        instead of reading all data and truncating after collection.
        """
        if not argv or not isinstance(argv, list) or not all(isinstance(x, str) and x for x in argv):
            raise ValueError("argv must be a non-empty list of non-empty strings")
        resource_provider = self.resources
        if require_resources and resource_provider is None:
            raise PermissionError('This operation requires a verified resource envelope')

        timeout = self.clamp_timeout(timeout_seconds)
        output_limit = min(
            max(1024, int(max_output_bytes or self.max_output_bytes)),
            self.max_output_bytes,
        )
        full_cmd = self.build_bwrap_args(
            workspace_path, writable=writable, sub_cwd=cwd,
            network_access=network_access,
            git_metadata_writable=git_metadata_writable,
        )
        if workspace_transaction is not None:
            full_cmd = workspace_transaction.wrap_command(full_cmd)
            full_cmd[0] = self.transaction_executable
        full_cmd += ["--"] + (workspace_transaction.wrap_argv(argv) if workspace_transaction is not None else argv)

        t0 = time.time()
        deadline = time.monotonic() + timeout
        proc = None
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        exceeded_stream = None
        timed_out = False
        selector = None
        lease = None
        pidfd = None

        def stop_group() -> None:
            if proc is None:
                return
            try:
                if lease is not None:
                    lease.terminate()
            finally:
                if pidfd is None:
                    raise ResourceCleanupError('Missing owned sandbox process handle')
                try:
                    signal_handle(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                raise ResourceCleanupError('Sandbox leader termination remains unverified') from error

        try:
            if resource_provider is not None:
                lease = resource_provider.create()
                if workspace_transaction is None:
                    full_cmd[0] = os.path.realpath(shutil.which('bwrap', path='/usr/bin:/bin'))
                full_cmd = lease.command(full_cmd)
            proc = subprocess.Popen(
                full_cmd,
                pass_fds=workspace_transaction.launch_fds if workspace_transaction is not None else (),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                process_group=0,
            )
            pidfd = open_handle(proc.pid)
            selector = selectors.DefaultSelector()
            for name in ("stdout", "stderr"):
                pipe = getattr(proc, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)

            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready = selector.select(remaining)
                if not ready:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    continue
                for key, _ in ready:
                    pipe = key.fileobj
                    try:
                        chunk = os.read(pipe.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        continue
                    name = key.data
                    available = output_limit - len(streams[name])
                    streams[name].extend(chunk[:available])
                    if len(chunk) > available:
                        exceeded_stream = name
                        break
                if exceeded_stream is not None:
                    break

            if timed_out or exceeded_stream is not None:
                stop_group()
                exit_code = 124 if timed_out else 125
            else:
                try:
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    stop_group()
                    exit_code = 124

        except Exception as exc:
            stop_group()
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Sandbox execution error: {exc}",
                "duration": time.time() - t0,
                "truncated": False,
                "timed_out": timed_out,
                "timeout_seconds": timeout,
            }
        finally:
            if selector is not None:
                selector.close()
            try:
                if proc is not None:
                    for name in ("stdout", "stderr"):
                        pipe = getattr(proc, name)
                        if pipe is not None and not pipe.closed:
                            pipe.close()
                    if proc.poll() is None:
                        stop_group()
            finally:
                try:
                    if lease is not None:
                        lease.close()
                finally:
                    if pidfd is not None:
                        os.close(pidfd)

        stdout = streams["stdout"].decode("utf-8", errors="replace")
        stderr = streams["stderr"].decode("utf-8", errors="replace")
        if exceeded_stream is not None:
            notice = f"\n... [{exceeded_stream.upper()} TRUNCATED: PROCESS KILLED AT OUTPUT LIMIT]"
            if exceeded_stream == "stdout":
                stdout += notice
            else:
                stderr += notice
        if timed_out:
            stderr += "\n... [TIMEOUT: PROCESS GROUP KILLED]"

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration": time.time() - t0,
            "truncated": exceeded_stream is not None or timed_out,
            "timed_out": timed_out,
            "timeout_seconds": timeout,
        }
