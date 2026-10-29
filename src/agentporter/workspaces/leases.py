"""Shared serialization for job finalization and trusted workspace mutations."""
from contextlib import contextmanager
import fcntl
import functools
import hashlib
import os
from pathlib import Path

from agentporter.resources import ResourceCleanupError


def workspace_key(identity):
    return hashlib.sha256(f'{identity.st_dev}:{identity.st_ino}'.encode()).hexdigest()


@contextmanager
def mutation_lease(workspace, state, *, allow_pending=False):
    workspace = Path(workspace).resolve(strict=True)
    state = Path(state).resolve()
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Workspace mutation state must be outside the workspace')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = workspace.stat()
    key = workspace_key(identity)
    descriptor = os.open(state / (key + '.lock'), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PermissionError('Workspace already has an active mutation') from error
        if not allow_pending and any(os.path.lexists(state / (key + suffix))
                for suffix in ('.pending.json', '.git-pending.json')):
            raise ResourceCleanupError('Workspace publication requires owner recovery')
        current = workspace.stat()
        if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
            raise PermissionError('Workspace root changed before mutation')
        yield
    finally:
        os.close(descriptor)


def serialized_mutation(registry, state, function):
    if state is None:
        return function
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        workspace_id = args[0] if args else kwargs['workspace_id']
        workspace = registry.get(workspace_id)
        with mutation_lease(workspace.path, state):
            return function(*args, **kwargs)
    return wrapped
