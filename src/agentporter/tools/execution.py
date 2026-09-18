"""Direct sandboxed execution and asynchronous job starter."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager


def create_execution_tools(
    registry: WorkspaceRegistry,
    sandbox: BubblewrapSandbox,
    job_manager: JobManager,
):
    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_execute:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow direct execution")
        return ws

    def exec_run(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30,
    ) -> dict:
        ws = _workspace(workspace_id)
        return sandbox.run(
            workspace_path=ws.path,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            writable=ws.writable,
        )

    def exec_start(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 300,
    ) -> dict:
        ws = _workspace(workspace_id)
        timeout = sandbox.clamp_timeout(timeout_seconds)
        bwrap_cmd = sandbox.build_bwrap_args(
            workspace_path=ws.path,
            writable=ws.writable,
            sub_cwd=cwd,
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
