"""Git inspection and repository operations executed inside the Bubblewrap sandbox."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox

MAX_GIT_OUTPUT = 200_000


def create_git_tools(registry: WorkspaceRegistry, sandbox: BubblewrapSandbox):
    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_git:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow Git operations")
        return ws

    def _run_git(ws_path: str, args: list[str], timeout: int = 10, writable: bool = False, network_access: bool = False) -> str:
        # Repository-local Git configuration is treated as untrusted input.
        # Run Git inside the sandbox and override common executable helper mechanisms.
        argv = [
            "git",
            "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false",
            "-c", "diff.external=",
            "-c", "pager.status=false",
            "-c", "pager.diff=false",
            "-c", "pager.log=false",
            "-c", "pager.show=false",
            *args,
        ]
        res = sandbox.run(
            workspace_path=ws_path,
            argv=argv,
            timeout_seconds=timeout,
            writable=writable,
            network_access=network_access,
            max_output_bytes=MAX_GIT_OUTPUT,
        )
        if res["exit_code"] != 0:
            msg = res["stderr"].strip()[:MAX_GIT_OUTPUT]
            return f"Git error (exit {res['exit_code']}): {msg}"
        return res["stdout"]

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

    def git_fetch(workspace_id: str, remote: str = "origin") -> str:
        ws = _workspace(workspace_id)
        clean_remote = remote.strip()
        if not clean_remote or clean_remote.startswith("-") or len(clean_remote) > 256:
            raise ValueError("Invalid remote")
        out = _run_git(ws.path, ["fetch", clean_remote], timeout=60, writable=True, network_access=True)
        return out if out.strip() else f"Fetched from {clean_remote} successfully."

    def git_pull(workspace_id: str, remote: str = "origin", branch: str = "") -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        clean_remote = remote.strip()
        if not clean_remote or clean_remote.startswith("-") or len(clean_remote) > 256:
            raise ValueError("Invalid remote")
        args = ["pull", clean_remote]
        if branch.strip():
            clean_branch = branch.strip()
            if clean_branch.startswith("-") or len(clean_branch) > 256:
                raise ValueError("Invalid branch")
            args.append(clean_branch)
        out = _run_git(ws.path, args, timeout=60, writable=True, network_access=True)
        return out if out.strip() else "Pull completed successfully."

    def git_push(workspace_id: str, remote: str = "origin", branch: str = "", set_upstream: bool = False) -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        clean_remote = remote.strip()
        if not clean_remote or clean_remote.startswith("-") or len(clean_remote) > 256:
            raise ValueError("Invalid remote")
        args = ["push"]
        if set_upstream:
            args.append("-u")
        args.append(clean_remote)
        if branch.strip():
            clean_branch = branch.strip()
            if clean_branch.startswith("-") or len(clean_branch) > 256:
                raise ValueError("Invalid branch")
            args.append(clean_branch)
        out = _run_git(ws.path, args, timeout=60, writable=True, network_access=True)
        return out if out.strip() else f"Pushed to {clean_remote} successfully."

    def git_commit(workspace_id: str, message: str, all_files: bool = False) -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        clean_msg = message.strip()
        if not clean_msg:
            raise ValueError("Commit message cannot be empty")
        args = ["commit", "-a", "-m", clean_msg] if all_files else ["commit", "-m", clean_msg]
        out = _run_git(ws.path, args, timeout=30, writable=True)
        return out if out.strip() else "Committed changes successfully."

    def git_add(workspace_id: str, paths: list[str]) -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        if not paths or not isinstance(paths, list):
            raise ValueError("paths must be a non-empty list of strings")
        clean_paths = []
        for p in paths:
            s = p.strip()
            if not s or s.startswith("-"):
                raise ValueError(f"Invalid path: {p}")
            clean_paths.append(s)
        out = _run_git(ws.path, ["add", "--"] + clean_paths, timeout=30, writable=True)
        return out if out.strip() else "Staged files successfully."

    def git_branch(workspace_id: str) -> str:
        ws = _workspace(workspace_id)
        out = _run_git(ws.path, ["branch", "-a"])
        return out if out.strip() else "No branches found."

    def git_checkout(workspace_id: str, branch: str, create: bool = False) -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        clean_branch = branch.strip()
        if not clean_branch or clean_branch.startswith("-") or len(clean_branch) > 256:
            raise ValueError(f"Invalid branch: {branch}")
        args = ["checkout", "-b", clean_branch] if create else ["checkout", clean_branch]
        out = _run_git(ws.path, args, timeout=30, writable=True)
        return out if out.strip() else f"Switched to branch {clean_branch}."

    class GitTools(tuple):
        def __new__(cls, status, diff, log, show, fetch, pull, push, commit, add, branch, checkout):
            return super().__new__(cls, (status, diff, log, show))

        def __init__(self, status, diff, log, show, fetch, pull, push, commit, add, branch, checkout):
            self.git_status = status
            self.git_diff = diff
            self.git_log = log
            self.git_show = show
            self.git_fetch = fetch
            self.git_pull = pull
            self.git_push = push
            self.git_commit = commit
            self.git_add = add
            self.git_branch = branch
            self.git_checkout = checkout

    return GitTools(
        git_status,
        git_diff,
        git_log,
        git_show,
        git_fetch,
        git_pull,
        git_push,
        git_commit,
        git_add,
        git_branch,
        git_checkout,
    )
