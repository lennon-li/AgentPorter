"""Direct sandboxed execution and asynchronous job starter."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager


def create_execution_tools(
    registry: WorkspaceRegistry,
    sandbox: BubblewrapSandbox,
    job_manager: JobManager
):
    def exec_run(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30
    ) -> dict:
        """Execute command synchronously inside the bubblewrap sandbox with network disabled."""
        ws = registry.get(workspace_id)
        return sandbox.run(
            workspace_path=ws.path,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            writable=ws.writable
        )

    def exec_start(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 300
    ) -> dict:
        """Start command asynchronously inside the sandbox, returning a job ID."""
        ws = registry.get(workspace_id)
        bwrap_cmd = sandbox.build_bwrap_args(
            workspace_path=ws.path,
            writable=ws.writable,
            sub_cwd=cwd
        ) + ["--"] + argv

        job_id = job_manager.start_raw_job(
            workspace_id=workspace_id,
            workspace_path=ws.path,
            cmd=bwrap_cmd,
            timeout_seconds=timeout_seconds
        )
        return {
            "job_id": job_id,
            "workspace_id": workspace_id,
            "status": "running"
        }

    return exec_run, exec_start
