"""Git inspection and repository operations executed inside the Bubblewrap sandbox."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox

MAX_GIT_OUTPUT = 200_000


# Executed only inside the existing bounded sandbox. Config inspection does not
# invoke filters; no repository helper may inherit canonical Git write access.
_FILTER_GUARD = r"""import os, subprocess, sys
query = ['git', '-c', 'safe.directory=/workspace', '-c', 'core.fsmonitor=false',
         '-c', 'core.hooksPath=/dev/null', '-c', 'submodule.recurse=false',
         'config', '--includes', '--name-only', '--get-regexp',
         r'^filter\..*\.(clean|smudge|process)$']
process = subprocess.Popen(query, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
output = process.stdout.read(4097)
if output:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)
    sys.stderr.write('Git mutation denied: repository executable filters require a separately approved backend.\n')
    raise SystemExit(78)
status = process.wait(timeout=2)
if status != 1:
    sys.stderr.write('Git mutation denied: repository configuration could not be safely inspected.\n')
    raise SystemExit(78)
os.execvp(sys.argv[1], sys.argv[1:])
"""

def create_git_tools(registry: WorkspaceRegistry, sandbox: BubblewrapSandbox, approved_commits=None, approved_pushes=None, approved_fetches=None):
    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_git:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow Git operations")
        return ws

    def _run_git(ws_path: str, args: list[str], timeout: int = 10, writable: bool = False, network_access: bool = False, writable_git_metadata: bool = False) -> str:
        if writable_git_metadata:
            import os
            from pathlib import Path
            from agentporter.git_commits import _inspect_metadata, _mount_id
            root = os.open(ws_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.path.lexists(Path(ws_path) / '.git'):
                    try:
                        metadata = os.open('.git', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                    except OSError as error:
                        raise PermissionError('Trusted Git mutations require in-project directory metadata') from error
                    try:
                        _inspect_metadata(metadata, _mount_id(root))
                    finally:
                        os.close(metadata)
            finally:
                os.close(root)
        # Repository-local Git configuration is treated as untrusted input.
        # Run Git inside the sandbox and override common executable helper mechanisms.
        argv = [
            "git",
            *(["--git-dir=/workspace/.git", "--work-tree=/workspace"] if writable_git_metadata else []),
            "-c", "safe.directory=/workspace",
            "-c", "core.fsmonitor=false",
            # No hooks from .git/hooks, core.hooksPath, or inherited config.
            # The dedicated Git-metadata writable mode must never run a
            # repository-supplied post-checkout command with ref write rights.
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.untrackedCache=false",
            "-c", "submodule.recurse=false",
            "-c", "diff.external=",
            "-c", "pager.status=false",
            "-c", "pager.diff=false",
            "-c", "pager.log=false",
            "-c", "pager.show=false",
            *args,
        ]
        if writable_git_metadata:
            argv = ['/usr/bin/python3', '-I', '-S', '-c', _FILTER_GUARD, *argv]
        res = sandbox.run(
            workspace_path=ws_path,
            argv=argv,
            timeout_seconds=timeout,
            writable=writable,
            network_access=network_access,
            max_output_bytes=MAX_GIT_OUTPUT,
            git_metadata_writable=writable_git_metadata,
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
        args = ["diff", "--no-ext-diff", "--no-textconv"]
        if staged:
            args.append("--staged")
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
        return _run_git(ws.path, ["show", "--no-ext-diff", "--no-textconv", "--stat", "-p", clean_ref])

    def git_fetch(workspace_id: str, remote: str = "origin", branch: str = "",
                  approval_receipt: str = '', prepare_only: bool = False) -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        if approved_fetches is None:
            raise PermissionError('Git fetch is locked: scoped network-capable Git backend and server-verified owner approval are unavailable')
        if prepare_only:
            import json
            if approval_receipt:
                raise ValueError('Preparation cannot also submit an approval receipt')
            request = approved_fetches.prepare(workspace_id, remote, branch)
            return json.dumps({'request': request.to_payload(), 'request_sha256': request.digest}, sort_keys=True)
        if not approval_receipt:
            raise PermissionError('Git fetch requires a server-verified exact owner approval receipt')
        return approved_fetches.fetch(workspace_id, remote, branch, approval_receipt)

    def git_pull(workspace_id: str, remote: str = "origin", branch: str = "") -> str:
        ws = _workspace(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is read-only")
        raise PermissionError(
            "Git pull is locked: scoped network-capable Git backend and "
            "independently verified approval are unavailable"
        )

    def git_push(workspace_id: str, remote: str = "origin", branch: str = "", set_upstream: bool = False,
                 approval_receipt: str = '', prepare_only: bool = False) -> str:
        raise PermissionError('Agent Git push is disabled by operator policy')

    def git_commit(workspace_id: str, message: str, all_files: bool = False,
                   approval_receipt: str = '', approval_timestamp: int | None = None,
                   prepare_only: bool = False) -> str:
        if approved_commits is not None and getattr(approved_commits, 'requires_receipt', True) is False:
            import time
            if prepare_only or approval_receipt or approval_timestamp is not None:
                raise ValueError('Workspace commits do not use phone proposals or receipts')
            if all_files:
                raise ValueError('Stage explicit paths with git_add before committing')
            return approved_commits.commit(workspace_id, message, int(time.time()), '')
        if approved_commits is not None:
            import json
            import time
            if all_files:
                raise PermissionError('Owner-approved commits require explicitly staged paths')
            if prepare_only:
                if approval_receipt:
                    raise ValueError('Preparation cannot also submit an approval receipt')
                timestamp = int(time.time()) if approval_timestamp is None else approval_timestamp
                request = approved_commits.prepare(workspace_id, message, timestamp)
                return json.dumps({'request': request.to_payload(), 'request_sha256': request.digest}, sort_keys=True)
            if not approval_receipt or approval_timestamp is None:
                raise PermissionError('Git commit requires a server-verified exact owner approval receipt and timestamp')
            return approved_commits.commit(workspace_id, message, approval_timestamp, approval_receipt)
        # Same fail-closed boundary as git_push; no untrusted boolean override.
        raise PermissionError(
            "Git commit is locked until a server-verified, scoped human approval "
            "receipt is implemented"
        )

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
        out = _run_git(ws.path, ["add", "--"] + clean_paths, timeout=30, writable=True, writable_git_metadata=True)
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
        out = _run_git(ws.path, args, timeout=30, writable=True, writable_git_metadata=True)
        return out if out.strip() else f"Switched to branch {clean_branch}."

    if getattr(sandbox, 'transactional_writes', False) is True:
        from agentporter.workspaces.leases import serialized_mutation
        state = sandbox.state_dir / 'workspace-transactions'
        if approved_fetches is None:
            git_fetch = serialized_mutation(registry, state, git_fetch)
        git_pull = serialized_mutation(registry, state, git_pull)
        if approved_pushes is None:
            git_push = serialized_mutation(registry, state, git_push)
        if approved_commits is None:
            git_commit = serialized_mutation(registry, state, git_commit)
        git_add = serialized_mutation(registry, state, git_add)
        git_checkout = serialized_mutation(registry, state, git_checkout)

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
