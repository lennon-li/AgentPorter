"""Read-only Git inspection tools with hostile Git configuration disabled."""

import os
import subprocess
from agentporter.workspaces.registry import WorkspaceRegistry

MAX_GIT_OUTPUT = 200_000


def create_git_tools(registry: WorkspaceRegistry):
    def _run_git(ws_path: str, args: list[str], timeout: int = 10) -> str:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_EXTERNAL_DIFF": "",
        }
        res = subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                "-c", "diff.external=",
                "-c", "pager.status=false",
                "-c", "pager.diff=false",
                "-c", "pager.log=false",
                "-c", "pager.show=false",
                *args,
            ],
            cwd=ws_path,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if res.returncode != 0:
            msg = res.stderr.strip()[:MAX_GIT_OUTPUT]
            return f"Git error (exit {res.returncode}): {msg}"
        out = res.stdout
        if len(out) > MAX_GIT_OUTPUT:
            out = out[:MAX_GIT_OUTPUT] + "\n... [GIT OUTPUT TRUNCATED]"
        return out

    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_git:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow Git inspection")
        return ws

    def git_status(workspace_id: str) -> str:
        ws = _workspace(workspace_id)
        out = _run_git(ws.path, ["status", "--short", "--branch"])
        return out if out.strip() else "Clean working tree."

    def git_diff(workspace_id: str, staged: bool = False) -> str:
        ws = _workspace(workspace_id)
        args = ["diff", "--staged"] if staged else ["diff"]
        out = _run_git(ws.path, args)
        return out if out.strip() else "No diff."

    def git_log(workspace_id: str, limit: int = 10) -> str:
        ws = _workspace(workspace_id)
        n = max(1, min(int(limit), 50))
        return _run_git(ws.path, ["log", f"-n{n}", "--oneline", "--decorate"])

    def git_show(workspace_id: str, ref: str = "HEAD") -> str:
        ws = _workspace(workspace_id)
        clean_ref = ref.strip()
        if not clean_ref or clean_ref.startswith("-") or len(clean_ref) > 256:
            raise ValueError("Invalid ref")
        return _run_git(ws.path, ["show", "--stat", "-p", clean_ref])

    return git_status, git_diff, git_log, git_show
