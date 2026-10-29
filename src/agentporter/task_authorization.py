"""Verified per-task authority shared by public and receiving-worker boundaries."""
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import stat

from agentporter.scoped_approvals import ApprovalVerifier, ApprovalError

ACTIVE_GRANT = ContextVar('agentporter_verified_task_grant', default=None)
PUBLIC_KEY_PATH = Path('/etc/agentporter/approval-issuer.pub')


def normalize_task_arguments(action, arguments, *, workspace_id=None, agent=None):
    args=dict(arguments)
    if workspace_id is not None:
        if args.get('workspace_id',workspace_id) != workspace_id:
            raise PermissionError('Approval workspace does not match request')
        args['workspace_id']=workspace_id
    if agent is not None:
        if args.get('agent',agent) != agent:
            raise PermissionError('Approval agent does not match request')
        args['agent']=agent
    if action=='dispatch_agent':
        from agentporter.agents.production_relay import normalize_dispatch
        return normalize_dispatch(args)
    if action in {'exec_run','exec_start'}:
        args={'cwd':'','timeout_seconds':30 if action=='exec_run' else 300,
              'network_access':False,'read_only':True,**args}
        if args['read_only'] is None: args['read_only']=True
    return args


def load_task_authorization(registry, state_dir):
    if getattr(registry, 'workspace_policy', None) is None:
        return None
    path = PUBLIC_KEY_PATH
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted approval verification key directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022 or info.st_size > 4096):
            raise PermissionError('Untrusted approval verification key')
        public_key = os.read(fd,4097)
    finally:
        os.close(fd)
    directory = Path(state_dir)/'task-approvals'
    directory.mkdir(mode=0o700,exist_ok=True)
    return TaskAuthorization(registry, ApprovalVerifier(public_key,directory/'grants.db'))


class TaskAuthorization:
    def __init__(self,registry,verifier):
        self.registry=registry
        self.verifier=verifier

    def _check_paths(self,action,args):
        shared=getattr(self.registry,'workspace_policy',None)
        name=args.get('workspace_id')
        if shared is None or name is None:
            return
        try:
            ws=self.registry.get(name)
        except KeyError:
            raise PermissionError('Workspace outside authorized scope') from None
        operation='write' if action in {'write_file','apply_patch','mkdir','move_path','trash_path'} else 'read'
        paths=[]
        if action in {'write_file','read_file','read_artifact','list_artifacts','mkdir','trash_path','list_files','search_text'}:
            paths=[args.get('path','.')]
        if action=='move_path':paths=[args.get('source','.'),args.get('destination','.')]
        if action == 'apply_patch':
            from agentporter.workspaces.patching import targets
            paths = [path for path, _, _ in targets(args.get('patch', ''))]
        for path in paths:
            if not isinstance(path,str):
                raise PermissionError('Invalid workspace path')
            shared.check_path(name,Path(ws.path)/path,operation)

    @contextmanager
    def authorize(self,action,arguments):
        args=normalize_task_arguments(action,arguments)
        self._check_paths(action,args)
        grant=None
        needs_write=action=='dispatch_agent' and args.get('read_only',True) is False
        needs_exec=action in {'exec_run','exec_start'} and args.get('read_only',True) is False
        destructive=action in {'trash_path'}
        if action == 'apply_patch':
            from agentporter.workspaces.patching import targets
            destructive = any(delete for _, _, delete in targets(args.get('patch', '')))

        if action in {'dispatch_agent','exec_run','exec_start'} and type(args.get('read_only',True)) is not bool:
            raise PermissionError('read_only must be an explicit boolean')
        if needs_write or needs_exec or destructive:
            workspace=args.get('workspace_id');ws=self.registry.get(workspace)
            if not ws.writable:
                raise PermissionError('Workspace is not authorized for edits')
            token=args.get('approval_token');request_id=args.get('request_id')
            if not isinstance(token,str) or not isinstance(request_id,str):
                raise PermissionError('Task-scoped owner approval and request identity required')
            if needs_write:
                from agentporter.agents.production_relay import normalize_dispatch
                verified_args=normalize_dispatch(args)
                required={'write'}
                grant_action='dispatch_agent'
            elif needs_exec:
                verified_args=args;required={'write'};grant_action=action
            else:
                verified_args={**args,'operation':action};required={'delete'};grant_action='destructive'
            try:
                grant=self.verifier.verify(token,workspace_id=workspace,workspace_root=ws.path,
                    action=grant_action,arguments=verified_args,request_id=request_id,
                    required_operations=required,agent=args.get('agent') if needs_write else None,
                    task=args.get('task') if needs_write else None)
            except ApprovalError:
                raise PermissionError('Task approval is invalid or outside the authorized scope') from None
        reset=ACTIVE_GRANT.set(grant)
        try:
            yield grant
        finally:
            ACTIVE_GRANT.reset(reset)
