"""Read-only Git inspection tools."""

import subprocess
import logging
from agentporter.workspaces.registry import WorkspaceRegistry

logger = logging.getLogger("agentporter.tools.git")


def create_git_tools(registry: WorkspaceRegistry):
    def _run_git(ws_path: str, args: list[str], timeout: int = 10) -> str:
        res = subprocess.run(
            ["git"] + args,
            cwd=ws_path,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if res.returncode != 0:
            return f"Git error (exit {res.returncode}): {res.stderr.strip()}"
        return res.stdout

    def git_status(workspace_id: str) -> str:
        """Show git working tree status in workspace."""
        ws = registry.get(workspace_id)
        out = _run_git(ws.path, ["status", "--short", "--branch"])
        return out if out.strip() else "Clean working tree."

    def git_diff(workspace_id: str, staged: bool = False) -> str:
        """Show git diff in workspace (staged or unstaged)."""
        ws = registry.get(workspace_id)
        args = ["diff", "--staged"] if staged else ["diff"]
        out = _run_git(ws.path, args)
        return out if out.strip() else "No diff."

    def git_log(workspace_id: str, limit: int = 10) -> str:
        """Show recent git commit history in workspace."""
        ws = registry.get(workspace_id)
        n = max(1, min(limit, 50))
        return _run_git(ws.path, ["log", f"-n{n}", "--oneline", "--decorate"])

    def git_show(workspace_id: str, ref: str = "HEAD") -> str:
        """Show commit details or object content in workspace."""
        ws = registry.get(workspace_id)
        clean_ref = ref.strip()
        if clean_ref.startswith("-"):
            raise ValueError("Invalid ref: option flags not permitted")
        return _run_git(ws.path, ["show", "--stat", "-p", clean_ref])

    return git_status, git_diff, git_log, git_show
