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

    def _execution_view(workspace_id, ws, read_only):
        shared = getattr(registry, 'workspace_policy', None)
        if shared is None:
            return None, ws.path, ws.writable if read_only is None else ws.writable and not read_only
        if read_only is None or read_only is True:
            return None, ws.path, False
        if type(read_only) is not bool:
            raise PermissionError('read_only must be boolean')
        from pathlib import Path
        from agentporter.scoped_approvals import VerifiedGrant
        from agentporter.task_authorization import ACTIVE_GRANT
        from agentporter.workspace_views import CowWorkspaceTransaction as WorkspaceTransaction
        import uuid
        grant = ACTIVE_GRANT.get()
        if (not isinstance(grant, VerifiedGrant) or grant.claims.get('workspace_root') != ws.path
                or 'write' not in grant.claims.get('operations', []) or not ws.writable):
            raise PermissionError('Writable command requires independently verified task approval')
        root = Path(ws.path)
        protected_roots = list(shared.protected_paths)
        protected_roots.extend(Path(row['path']) for name,row in shared.workspaces.items()
                               if not shared.capabilities(name)['writable'])
        protected = []
        for path in protected_roots:
            path = Path(path)
            if path == root or root.is_relative_to(path):
                raise PermissionError('Workspace is protected against edits')
            if path.is_relative_to(root):
                protected.append(path.relative_to(root).as_posix())
        private = Path(job_manager.state_dir) / 'workspace-transactions'
        private.mkdir(mode=0o700,exist_ok=True)
        transaction = WorkspaceTransaction(ws.path, private, uuid.uuid4().hex,
            allow_delete='delete' in grant.claims.get('operations', []), protected_paths=protected)
        try:
            stage = transaction.prepare()
        except BaseException:
            transaction.cleanup()
            raise
        return transaction, str(stage), True

    def _exec_run(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30,
        network_access: bool = False,
        read_only: bool | None = None,
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
        transaction, execution_path, writable = _execution_view(workspace_id, ws, read_only)
        try:
            result = sandbox.run(
                workspace_path=execution_path, argv=argv, cwd=cwd,
                timeout_seconds=timeout_seconds, writable=writable, network_access=network_access,
                **({'workspace_descriptor': transaction.view_descriptor, 'source_workspace_path': ws.path}
                   if transaction is not None and hasattr(transaction, 'view_descriptor') else {}))
            if (transaction is not None and result.get('exit_code') == 0
                    and not result.get('timed_out') and not result.get('truncated')):
                if getattr(sandbox, 'resources', None) is None:
                    raise PermissionError('Verified resource cleanup required before publication')
                from agentporter.workspace_transactions import WorkspaceTransactionError
                try:
                    result['workspace_changes'] = transaction.apply()
                except WorkspaceTransactionError:
                    raise PermissionError('Command changes rejected by workspace transaction policy') from None
            return result
        finally:
            if transaction is not None:
                transaction.cleanup()

    def exec_run(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 30,
                 network_access: bool = False, read_only: bool | None = None) -> dict:
        _workspace(workspace_id)
        if network_access and scoped_https is None:
            raise PermissionError('Networked generic execution requires independent approval and scoped egress; unavailable')
        with synchronous_slot(job_manager):
            return _exec_run(workspace_id, argv, cwd, timeout_seconds, network_access, read_only)

    def exec_start(
        workspace_id: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 300,
        network_access: bool = False,
        read_only: bool | None = None,
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
        transaction, execution_path, writable = _execution_view(workspace_id, ws, read_only)
        try:
            bwrap_cmd = sandbox.build_bwrap_args(
                workspace_path=execution_path, writable=writable, sub_cwd=cwd,
                network_access=network_access,
                **({'workspace_descriptor': transaction.view_descriptor, 'source_workspace_path': ws.path}
                   if transaction is not None and hasattr(transaction, 'view_descriptor') else {}),
            ) + ["--"] + argv
            callbacks = {}
            if transaction is not None:
                callbacks = {'finalize': lambda success: transaction.apply() if success else None,
                             'cleanup': transaction.cleanup}
                if hasattr(transaction, 'view_descriptor'):
                    callbacks['workspace_descriptor'] = transaction.view_descriptor
            job_id = job_manager.start_raw_job(
                workspace_id=workspace_id, workspace_path=execution_path,
                cmd=bwrap_cmd, timeout_seconds=timeout, **callbacks)
        except BaseException:
            if transaction is not None: transaction.cleanup()
            raise
        return {
            "job_id": job_id,
            "workspace_id": workspace_id,
            "status": "running",
            "timeout_seconds": timeout,
        }

    return exec_run, exec_start
