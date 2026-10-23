"""Direct sandboxed execution and asynchronous job starter."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager
from agentporter.admission import synchronous_slot


def create_execution_tools(
    registry: WorkspaceRegistry,
    sandbox: BubblewrapSandbox,
    job_manager: JobManager,
    scoped_https=None,
):
    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_execute:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow direct execution")
        return ws

    def _exec_run(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30,
        network_access: bool = False,
    ) -> dict:
        ws = _workspace(workspace_id)
        if network_access:
            if scoped_https is None:
                raise PermissionError(
                    "Networked generic execution requires independent approval and "
                    "scoped egress; unavailable"
                )
            # The only network route is a fixed GET/HEAD public metadata
            # request processed by the audited host-side HTTPS broker, not
            # a shell or networked Bubblewrap namespace.
            return scoped_https.run_bounded(
                workspace_id=workspace_id, argv=argv, cwd=cwd,
                timeout_seconds=timeout_seconds,
            )
        return sandbox.run(
            workspace_path=ws.path,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            writable=ws.writable,
            network_access=network_access,
        )

    def exec_run(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 30,
                 network_access: bool = False) -> dict:
        _workspace(workspace_id)
        if network_access and scoped_https is None:
            raise PermissionError('Networked generic execution requires independent approval and scoped egress; unavailable')
        with synchronous_slot(job_manager):
            return _exec_run(workspace_id, argv, cwd, timeout_seconds, network_access)

    def exec_start(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 300,
        network_access: bool = False,
    ) -> dict:
        ws = _workspace(workspace_id)
        if network_access:
            if scoped_https is None:
                raise PermissionError(
                    "Networked generic execution requires independent approval and "
                    "scoped egress; unavailable"
                )
            if cwd:
                raise PermissionError("Scoped HTTPS does not permit custom working directory")
            from agentporter.scoped_https import _parse_curl

            method, url = _parse_curl(argv)
            host, target, scope = scoped_https.policy.authorize(
                workspace_id, method, url
            )
            timeout = min(
                sandbox.clamp_timeout(timeout_seconds),
                scope["timeout_seconds"],
            )
            job_id = job_manager.start_scoped_https_job(
                workspace_id=workspace_id, workspace_path=ws.path,
                config_dir=str(scoped_https.policy.config_dir),
                method=method, url=url, timeout_seconds=timeout,
            )
            return {
                "job_id": job_id, "workspace_id": workspace_id,
                "status": "running", "timeout_seconds": timeout,
            }
        timeout = sandbox.clamp_timeout(timeout_seconds)
        bwrap_cmd = sandbox.build_bwrap_args(
            workspace_path=ws.path,
            writable=ws.writable,
            sub_cwd=cwd,
            network_access=network_access,
        ) + ["--"] + argv

        job_id = job_manager.start_raw_job(
            workspace_id=workspace_id,
            workspace_path=ws.path,
            cmd=bwrap_cmd,
            timeout_seconds=timeout,
        )
        return {
            "job_id": job_id,
            "workspace_id": workspace_id,
            "status": "running",
            "timeout_seconds": timeout,
        }

    return exec_run, exec_start
