"""Owner-installed public-client scopes, separate from worker confinement.

All authenticated general API requests are public, including loopback requests.
Internal access requires a distinct private credential and local transport.
The policy applies to the shared decorated REST/MCP tool functions.
"""
from contextvars import ContextVar
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import re
from mcp.server.mcpserver.exceptions import ToolError

from agentporter.scoped_https import _NoAliasOwnerPolicyLoader
from agentporter.workspaces.bounded import read_regular
import yaml

PRINCIPAL = ContextVar('agentporter_principal', default=None)
GLOBAL_READ = {'get_capabilities', 'server_deploy_info', 'list_agents', 'list_workspaces'}
OPERATIONS = {
    **dict.fromkeys(('workspace_info', 'list_files', 'read_file', 'search_text',
                     'list_artifacts', 'read_artifact'), 'read'),
    **dict.fromkeys(('write_file', 'apply_patch', 'mkdir', 'move_path', 'trash_path'), 'write'),
    **dict.fromkeys(('git_status', 'git_diff', 'git_log', 'git_show', 'git_branch'), 'git_read'),
    **dict.fromkeys(('git_add', 'git_checkout'), 'git_write'),
    'dispatch_agent': 'dispatch', 'exec_run': 'exec', 'exec_start': 'exec',
    'https_download': 'https',
}
JOB_READ = {'job_status', 'job_output', 'job_result'}
SCOPES = {'read', 'write', 'exec', 'https', 'git_read', 'git_write', 'dispatch', 'dispatch_write'}


class PublicDispatchDenied(PermissionError, ToolError):
    """A policy denial that remains explicit over both REST and MCP."""


class PublicClientPolicy:
    def __init__(self, config_dir, state_dir, registry, *, required=False):
        self.registry = registry
        self.state_dir = Path(state_dir)
        self.scopes = None
        self.internal_key = None
        path = Path(config_dir) / 'public-client-policy.yaml'
        if not path.exists() and not path.is_symlink():
            if required:
                raise PermissionError('Required public-client policy is absent')
            return  # Legacy profile compatibility; never hardened clearance.
        self._private(path)
        document = yaml.load(read_regular(config_dir, path.name, 65536), Loader=_NoAliasOwnerPolicyLoader)
        if (not isinstance(document, dict) or set(document) != {'version', 'workspaces'}
                or type(document['version']) is not int or document['version'] != 1
                or not isinstance(document['workspaces'], dict)):
            raise ValueError('Invalid public-client policy')
        scopes = {}
        for name, row in document['workspaces'].items():
            if (not isinstance(row, dict) or set(row) != {'path', 'operations'}
                    or not isinstance(row['path'], str) or not isinstance(row['operations'], list)
                    or not all(isinstance(x, str) and x in SCOPES for x in row['operations'])
                    or len(set(row['operations'])) != len(row['operations'])):
                raise ValueError('Invalid public-client workspace scope')
            ws = registry.get(name)
            if not Path(row['path']).is_absolute() or str(Path(row['path']).resolve()) != ws.path:
                raise PermissionError('Public-client workspace root does not match registry')
            for protected in (Path(config_dir).resolve(), self.state_dir.resolve()):
                if protected == Path(ws.path) or protected.is_relative_to(ws.path):
                    raise PermissionError('Public workspace overlaps protected gateway data')
            scopes[name] = frozenset(row['operations'])
        self.scopes = scopes
        key = Path(config_dir) / 'internal-client.key'
        if key.exists() or key.is_symlink():
            self._private(key)
            fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_size > 4096
                        or info.st_uid != os.getuid() or info.st_mode & 0o077):
                    raise ValueError('Invalid internal-client credential file')
                self.internal_key = os.read(fd, 4097).decode().strip()
            finally:
                os.close(fd)
            if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', self.internal_key):
                raise ValueError('Invalid internal-client credential')
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS public_jobs (job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL)')

    @staticmethod
    def _private(path):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError('Public-client control files require private service ownership')
        # Every parent through config must already be outside writable workspaces.

    @contextmanager
    def _db(self):
        path = self.state_dir / 'public-client-jobs.db'
        connection = sqlite3.connect(path, timeout=3)
        try:
            os.chmod(path, 0o600)
            with connection:
                yield connection
        finally:
            connection.close()

    @property
    def public(self):
        return self.scopes is not None and PRINCIPAL.get() != 'internal'

    def check(self, action, args):
        if not self.public:
            return
        if PRINCIPAL.get() != 'public':
            raise PermissionError('Missing authenticated client principal')
        if action in GLOBAL_READ:
            if (action == 'list_agents' and args.get('workspace_id') is not None
                    and args['workspace_id'] not in self.scopes):
                raise PermissionError('Workspace outside public-client scope')
            return
        if action in JOB_READ:
            with self._db() as db:
                row = db.execute('SELECT workspace_id FROM public_jobs WHERE job_id=?', (args.get('job_id'),)).fetchone()
            if row is None or row[0] not in self.scopes:
                raise PermissionError('Job is outside public-client ownership/scope')
            return
        workspace = args.get('workspace_id')
        operation = OPERATIONS.get(action)
        if action in {'exec_run', 'exec_start'} and args.get('network_access') is True:
            operation = 'https'
        if not operation or operation not in self.scopes.get(workspace, ()):
            if action == 'dispatch_agent':
                raise PublicDispatchDenied(
                    'Public agent dispatch is not authorized for this workspace. '
                    'File and offline execution access do not grant delegation. '
                    'Use list_agents(workspace_id=...) to check this scope; '
                    'expansion requires an owner-installed policy change.'
                )
            raise PermissionError('Operation/workspace outside public-client scope')
        if action == 'dispatch_agent':
            if args.get('allow_commit') or args.get('allow_push'):
                raise PublicDispatchDenied('Public delegation cannot commit or publish')
            if args.get('read_only', True) is not True:
                ws = self.registry.get(workspace)
                if (not {'dispatch', 'write', 'dispatch_write'} <= self.scopes.get(workspace, ())
                        or not ws.writable):
                    raise PublicDispatchDenied(
                        'Writable public delegation requires owner-installed dispatch_write '
                        'and write scopes on a writable workspace; read-only dispatch remains available.')

    def result(self, action, args, result):
        if not self.public:
            return result
        if action == 'list_agents':
            scoped = {name for name, scopes in self.scopes.items()
                      if 'dispatch' in scopes
                      and self.registry.get(name).allow_agent_dispatch
                      and self.registry.get(name).allow_execute}
            workspace = args.get('workspace_id')
            rows = []
            for original in result:
                row = dict(original)
                runtime_workspaces = row.pop('runtime_dispatch_workspaces', None)
                if runtime_workspaces is None:
                    # Development readiness must include the launcher's exact
                    # allowlist/protected-root check, not just registry flags.
                    runtime_workspaces = [] if row.get('runtime_profile') == 'development' else scoped
                allowed = sorted(scoped.intersection(runtime_workspaces))
                runtime_writable = row.pop('runtime_writable_dispatch_workspaces', [])
                writable = sorted(name for name in allowed
                                  if name in runtime_writable
                                  and {'write', 'dispatch_write'} <= self.scopes[name]
                                  and self.registry.get(name).writable)
                runtime_ready = (row.get('delegatable') is True
                                 and row.get('available') is True
                                 and row.get('registered') is True)
                authorized = workspace in allowed if workspace is not None else bool(allowed)
                row.update(runtime_delegatable=runtime_ready,
                           public_dispatch_workspaces=allowed,
                           public_writable_dispatch_workspaces=writable,
                           public_dispatch_read_only=(workspace not in writable if workspace is not None else not writable),
                           delegatable=runtime_ready and authorized,
                           readiness_note='Runtime checks do not verify provider quota or '
                           'successful execution; public dispatch requires an admitted workspace.')
                if workspace is not None:
                    row['workspace_dispatch_authorized'] = authorized
                if not authorized:
                    row['availability_reason'] = (
                        str(row.get('availability_reason') or '')
                        + '; public delegation is not authorized for '
                        + ('this workspace' if workspace is not None else 'any workspace')
                    ).lstrip('; ')
                rows.append(row)
            return rows
        if action == 'list_workspaces':
            return [self._workspace_result(row, row['workspace_id'])
                    for row in result if row.get('workspace_id') in self.scopes]
        if action == 'workspace_info' and isinstance(result, dict):
            return self._workspace_result(result, args['workspace_id'])
        if action in {'dispatch_agent', 'exec_start'} and isinstance(result, dict) and result.get('job_id'):
            with self._db() as db:
                db.execute('INSERT INTO public_jobs VALUES (?,?)', (result['job_id'], args['workspace_id']))
        return result

    def _workspace_result(self, row, workspace):
        result = dict(row)
        if isinstance(row.get('permissions'), dict):
            result['permissions'] = dict(row['permissions'])
            result['permissions']['agent_dispatch'] = bool(
                row['permissions'].get('agent_dispatch')
                and 'dispatch' in self.scopes.get(workspace, ()))
        return result
