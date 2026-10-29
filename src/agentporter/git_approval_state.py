"""Locked, sandboxed repository inspection for the future owner Git backend.

No operation is authorized or executed here. Callers must obtain workspace
policy from the protected registry and retain this context through subsequent
verification/execution. A receipt is not a substitute for that execution boundary.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat

from agentporter.git_approvals import GitApprovalRequest
from agentporter.workspaces.leases import mutation_lease


# Only bounded read commands use repository configuration. Index expansion and
# tree construction run in a clean scratch repository, with no original config,
# no lazy fetching, and no canonical index/object writes. This program itself
# runs inside the existing read-only, network-isolated workspace sandbox.
_INSPECT = r'''
import json, os, pathlib, stat, subprocess, tempfile

environment = {
    'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
    'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_LAZY_FETCH': '1',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_ALLOW_PROTOCOL': '',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
}
base = ['/usr/bin/git', '-c', 'safe.directory=/workspace',
        '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
        '-c', 'protocol.allow=never']

def run(args, *, env=environment, statuses=(0,)):
    result = subprocess.run(base + args, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5, check=False)
    if result.returncode not in statuses or len(result.stdout) > 4096:
        raise RuntimeError('Repository state inspection failed')
    return result.returncode, result.stdout.decode('utf-8').strip()

kind = run(['rev-parse', '--show-object-format'])[1]
if kind not in {'sha1', 'sha256'}:
    raise RuntimeError('Unsupported Git object format')
status, branch = run(['symbolic-ref', '--quiet', 'HEAD'], statuses=(0, 1))
branch = branch if status == 0 else None
if branch is not None:
    run(['check-ref-format', branch])
status, head = run(['rev-parse', '--verify', '--quiet', 'HEAD'], statuses=(0, 1))
if status and branch is None:
    raise RuntimeError('Invalid detached HEAD')
head = head if status == 0 else None

index_budget = 64 * 1024 * 1024

def copy_index(source, target, *, optional=False):
    global index_budget
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > index_budget:
            raise RuntimeError('Unsupported Git index')
        with os.fdopen(fd, 'rb', closefd=False) as stream, open(target, 'xb') as output:
            while True:
                data = stream.read(min(65536, index_budget + 1))
                if not data:
                    break
                index_budget -= len(data)
                if index_budget < 0:
                    raise RuntimeError('Git indexes exceed inspection limit')
                output.write(data)
    finally:
        os.close(fd)

with tempfile.TemporaryDirectory(prefix='git-review-', dir='/tmp') as temporary:
    scratch = pathlib.Path(temporary) / 'metadata'
    run(['init', '--quiet', '--bare', '--template=', '--object-format=' + kind, str(scratch)])
    copy_index('/workspace/.git/index', scratch / 'index', optional=True)
    # Split indexes refer to a shared index relative to their Git directory.
    shared_count = 0
    with os.scandir('/workspace/.git') as entries:
        for entry in entries:
            if not entry.name.startswith('sharedindex.'):
                continue
            shared_count += 1
            if shared_count > 128:
                raise RuntimeError('Too many shared indexes')
            copy_index(entry.path, scratch / entry.name)
    clean = dict(environment, GIT_DIR=str(scratch),
                 GIT_ALTERNATE_OBJECT_DIRECTORIES='/workspace/.git/objects')
    if head is not None:
        if (len(head) != (40 if kind == 'sha1' else 64)
                or any(character not in '0123456789abcdef' for character in head)
                or run(['cat-file', '-t', head], env=clean)[1] != 'commit'):
            raise RuntimeError('HEAD does not identify an existing commit')
    tree = run(['write-tree'], env=clean)[1]
    print(json.dumps({'head': head, 'tree': tree, 'branch': branch}))
'''


def _same_identity(path, descriptor):
    try:
        current = path.lstat()
    except OSError as error:
        raise PermissionError('Repository identity changed during approval inspection') from error
    pinned = os.fstat(descriptor)
    if (not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)):
        raise PermissionError('Repository identity changed during approval inspection')


@contextmanager
def locked_git_request(registry, sandbox, workspace_id, operation, parameters):
    """Yield actual repository state while holding the shared mutation lease.

    Only conventional in-project .git directories are supported at present.
    Linked worktrees and external Git directories are explicitly refused.
    This internal API is not registered as an MCP or REST tool.
    """
    workspace = registry.get(workspace_id)
    if not workspace.allow_git or not workspace.writable:
        raise PermissionError('Workspace policy does not allow Git mutation requests')
    root = Path(workspace.path).resolve(strict=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
        root_fd = os.open(root, flags)
        git_fd = None
        try:
            try:
                git_fd = os.open('.git', flags, dir_fd=root_fd)
            except OSError as error:
                raise PermissionError('Approval inspection requires an in-project Git directory') from error
            # The caller already holds the transaction's shared mutation lease.
            # Use the bounded read-only command primitive to avoid recursively
            # acquiring it. Resource supervision and process cleanup still run;
            # this fixed inspector never receives writable metadata or network.
            result = sandbox._run_command(workspace_path=str(root),
                argv=['/usr/bin/python3', '-I', '-S', '-c', _INSPECT],
                writable=False, network_access=False, timeout_seconds=20,
                max_output_bytes=8192, git_metadata_writable=False)
            if result['exit_code'] != 0:
                raise PermissionError('Sandboxed Git approval state inspection failed')
            _same_identity(root, root_fd)
            _same_identity(root / '.git', git_fd)
            try:
                state = json.loads(result['stdout'])
                if not isinstance(state, dict) or set(state) != {'head', 'tree', 'branch'}:
                    raise ValueError('Unexpected repository state schema')
                identity = os.fstat(root_fd)
                request = GitApprovalRequest.from_payload({
                    'operation': operation, 'workspace_id': workspace_id,
                    'repository_path': str(root), 'repository_device': identity.st_dev,
                    'repository_inode': identity.st_ino, 'expected_head': state['head'],
                    'expected_tree': state['tree'], 'branch': state['branch'],
                    'parameters': parameters,
                })
            except (ValueError, TypeError, KeyError) as error:
                raise PermissionError('Invalid sandboxed Git approval state') from error
            yield request
        finally:
            if git_fd is not None:
                os.close(git_fd)
            os.close(root_fd)


@contextmanager
def approved_git_request(registry, sandbox, verifier, workspace_id, operation, parameters, receipt):
    """Consume an exact owner receipt while retaining the repository lease.

    All dependencies here must be supplied by the protected backend, never by
    tool arguments. This authorizes no generic command, and performs no Git
    mutation. Future execution must enforce the approved operation separately.
    """
    with locked_git_request(registry, sandbox, workspace_id, operation, parameters) as request:
        verifier.verify_and_consume(receipt, request)
        yield request
