"""Owner-only custody bridge for exact non-ref Git recovery entries.

This is not a ref publisher or a public tool. The offline coordinator must hold
maintenance/workspace leases, verify phase provenance and retain both guards.
Generic workspace path validation is unchanged and still refuses `.git`.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re

from agentporter.sandbox import workspace_custody as custody


def _approved_paths(paths):
    if not paths:return ()
    if (not isinstance(paths,tuple) or len(paths)!=2 or not isinstance(paths[0],str)
            or not paths[0].startswith('refs/remotes/') or paths[1]!='logs/'+paths[0]
            or len(paths[0].encode())>1024 or '..' in paths[0] or '@{' in paths[0]
            or any(ord(char)<33 or ord(char)==127 or char in '~^:?*[' or char=='\\' for char in paths[0])
            or any(part in {'','.','..'} or part.startswith('.') or part.endswith(('.', '.lock')) for part in paths[0].split('/'))):
        raise PermissionError('Git custody requires one exact validated tracking ref/log pair')
    return paths


def _path(relative,approved_paths=()):
    if not isinstance(relative,str) or any(part in {'','.','..'} for part in relative.split('/')):
        raise PermissionError('Invalid Git recovery metadata path')
    approved_paths=_approved_paths(approved_paths)
    if approved_paths and relative in {*approved_paths,approved_paths[0]+'.lock'}:return relative
    exact={'HEAD','index','logs/HEAD','logs/refs/stash','index.lock','HEAD.lock',
           'packed-refs.lock','refs/stash.lock','refs/stash'}
    if relative in exact:return relative
    if relative.startswith(('logs/refs/heads/','logs/refs/tags/','refs/heads/','refs/tags/')):
        return relative
    if re.fullmatch(r'\.agentporter-(?:index|head)-[a-f0-9]{32}',relative):return relative
    if re.fullmatch(r'logs/refs/\.agentporter-stash-[a-f0-9]{32}',relative):return relative
    raise PermissionError('Git custody only admits exact non-ref metadata/temporary paths')


@contextmanager
def _view(workspace,relative,operation,identity,parents,approved_paths=()):
    relative=_path(relative,approved_paths)
    canonical=Path(workspace).resolve(strict=True)
    private=Path(operation).resolve()
    if private.is_relative_to(canonical) or canonical.is_relative_to(private):
        raise PermissionError('Git custody storage must be outside the entire workspace')
    if not isinstance(identity,dict) or set(identity)!={'workspace','git'}:
        raise PermissionError('Git custody requires bound workspace and metadata identities')
    if not isinstance(parents,dict):raise PermissionError('Git custody requires bound parent identities')
    root=os.open(workspace,custody._FLAGS);git=None;parent=None
    try:
        if custody._identity(os.fstat(root))!=identity['workspace']:
            raise PermissionError('Git custody workspace identity changed')
        git=os.open('.git',custody._FLAGS,dir_fd=root)
        if custody._identity(os.fstat(git))!=identity['git']:
            raise PermissionError('Git custody metadata root identity changed')
        parent=os.dup(git);prefix=[]
        for component in relative.split('/')[:-1]:
            prefix.append(component)
            child=os.open(component,custody._FLAGS,dir_fd=parent)
            os.close(parent);parent=child
            if parents.get('/'.join(prefix))!=custody._identity(os.fstat(parent)):
                raise PermissionError('Git custody metadata parent differs from bound journal')
        yield f'/proc/self/fd/{git}/.',relative
    finally:
        for descriptor in (parent,git,root):
            if descriptor is not None:os.close(descriptor)


def preflight_git_entry(workspace,relative,operation,*,identity,parents,approved_paths=()):
    with _view(workspace,relative,operation,identity,parents,approved_paths) as (source,path):
        return custody.preflight_workspace_custody(source,path,operation)


def capture_git_entry(workspace,relative,operation,*,identity,parents,expected_record,expected_support,approved_paths=()):
    with _view(workspace,relative,operation,identity,parents,approved_paths) as (source,path):
        return custody.capture_workspace_entry(source,path,operation,expected_record=expected_record,
                                                expected_support=expected_support)


def _bound_intent(operation,path):
    descriptor=os.open(operation,custody._FLAGS)
    try:
        custody._private(descriptor)
        intent=custody._read_record(descriptor,'intent.json')
        if not isinstance(intent,dict) or intent.get('path')!=path:
            raise PermissionError('Git custody intent path differs from requested entry')
    finally:os.close(descriptor)


def inspect_git_entry(workspace,relative,operation,*,identity,parents,approved_paths=()):
    with _view(workspace,relative,operation,identity,parents,approved_paths) as (source,path):
        _bound_intent(operation,path)
        return custody.inspect_custody(source,operation)


def restore_git_entry(workspace,relative,operation,*,identity,parents,approved_paths=()):
    with _view(workspace,relative,operation,identity,parents,approved_paths) as (source,path):
        _bound_intent(operation,path)
        return custody.restore_custody(source,operation)
