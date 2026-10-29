"""Private worker Git state with a fixed, offline history import boundary.

Workers never write canonical metadata. Only validated object data, a staged
index tree, and a fast-forward local branch can cross back after job cleanup.
Repository configuration and hooks are never copied back.
"""
import json
import os
from pathlib import Path
import stat

from agentporter.git_approval_state import _INSPECT
from agentporter.git_commits import _MetadataMount, _inspect_metadata, _mount_id
from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import mutation_lease, workspace_key

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMIT = 256 * 1024 * 1024

_EXPORT = r'''
import contextlib, io, json, os, resource, subprocess, sys
baseline = json.loads(sys.argv[1])
ns = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], ns)
head, branch, tree = ns['head'], ns['branch'], ns['tree']
if branch is None or not branch.startswith('refs/heads/'):
    raise RuntimeError('Local commits require a local branch')
env = dict(ns['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace')
base = ns['base']
if baseline['head'] is not None and head != baseline['head']:
    if head is None or subprocess.run(base + ['merge-base', '--is-ancestor', baseline['head'], head],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10).returncode:
        raise RuntimeError('Delegated history must fast-forward the initial HEAD')
resource.setrlimit(resource.RLIMIT_FSIZE, (268435456, 268435456))
revisions = tree + '\n' + (head + '\n' if head else '')
if baseline['head']:
    revisions += '^' + baseline['head'] + '\n'
with open('/exchange/objects.pack', 'xb') as pack:
    subprocess.run(base + ['-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m',
        'pack-objects', '--stdout', '--revs'], input=revisions.encode('ascii'),
        stdout=pack, stderr=subprocess.DEVNULL, env=env, timeout=20, check=True)
    pack.flush()
    os.fsync(pack.fileno())
print(json.dumps({'head': head, 'branch': branch, 'tree': tree}))
'''

_IMPORT = r'''
import contextlib, io, json, os, subprocess, sys
plan = json.loads(sys.argv[1])
ns = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], ns)
if {k: ns[k] for k in ('head', 'branch', 'tree')} != plan['before']:
    raise RuntimeError('Canonical Git state changed during the job')
env = dict(ns['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace')
base = ns['base'] + ['-c', 'core.fsyncObjectFiles=true']
def run(args, **kwargs):
    return subprocess.run(base + args, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=20, check=True, **kwargs).stdout.decode().strip()
after = plan['after']
if after['branch'] != plan['before']['branch']:
    exists = subprocess.run(base + ['show-ref', '--verify', '--quiet', after['branch']],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=5)
    if exists.returncode != 1:
        raise RuntimeError('Delegated branch creation requires a new local branch')
with open('/incoming/objects.pack', 'rb') as pack:
    run(['unpack-objects', '-r', '--strict'], stdin=pack)
# Validate imported identities with Git before any ref/index update.
run(['cat-file', '-e', after['tree'] + '^{tree}'])
if after['head']:
    run(['cat-file', '-e', after['head'] + '^{commit}'])
    if plan['before']['head']:
        run(['merge-base', '--is-ancestor', plan['before']['head'], after['head']])
run(['read-tree', after['tree']])
if after['head']:
    old = (plan['before']['head'] if after['branch'] == plan['before']['branch'] else None)
    run(['update-ref', '--no-deref', '-m', 'AgentPorter workspace commit',
         after['branch'], after['head'], old or '0' * len(after['head'])])
if after['branch'] != plan['before']['branch']:
    run(['symbolic-ref', '-m', 'AgentPorter workspace branch', 'HEAD', after['branch']])
# Persist metadata before the transaction can release its recovery guard.
for root, dirs, files in os.walk('/workspace/.git', followlinks=False):
    for name in files:
        fd = os.open(os.path.join(root, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print('WORKSPACE_GIT_IMPORTED')
'''


def _copy_directory(source_fd, destination, budget):
    destination.mkdir(mode=0o700)
    with os.scandir(source_fd) as entries:
        for entry in entries:
            budget[0] -= 1
            if budget[0] < 0:
                raise PermissionError('Private Git snapshot exceeds entry budget')
            info = entry.stat(follow_symlinks=False)
            target = destination / entry.name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, _FLAGS, dir_fd=source_fd)
                try:
                    _copy_directory(child, target, budget)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=source_fd)
                try:
                    pinned = os.fstat(fd)
                    if not stat.S_ISREG(pinned.st_mode) or pinned.st_nlink != 1:
                        raise PermissionError('Git snapshot inode changed')
                    with open(target, 'xb') as output:
                        while data := os.read(fd, 65536):
                            budget[1] -= len(data)
                            if budget[1] < 0:
                                raise PermissionError('Private Git snapshot exceeds byte budget')
                            output.write(data)
                finally:
                    os.close(fd)
            else:
                raise PermissionError('Private Git snapshots forbid aliases and special files')


class _PrivateMount:
    wrap_argv = staticmethod(_MetadataMount.wrap_argv)

    def __init__(self, history, *, exchange=False):
        self.history, self.exchange = history, exchange
        self.launch_fds = (history.mount.root,)

    def wrap_command(self, command):
        h = self.history
        command = list(command)
        index = command.index(str(h.workspace))
        if command[index - 1] != '--ro-bind' or command[index + 1] != '/workspace':
            raise PermissionError('Private Git phase requires a read-only workspace')
        command[index] = f'/proc/self/fd/{h.mount.root}'
        command += ['--ro-bind', str(h.private), '/workspace/.git',
                    '--ro-bind', str(h.clean_config), '/workspace/.git/config']
        if self.exchange:
            command += ['--bind', str(h.exchange), '/exchange']
        return command


class _ImportMount:
    wrap_argv = staticmethod(_MetadataMount.wrap_argv)

    def __init__(self, history):
        self.history = history
        self.launch_fds = history.mount.launch_fds

    def wrap_command(self, command):
        return self.history.mount.wrap_command(command) + [
            '--ro-bind', str(self.history.exchange), '/incoming']


class WorkspaceGitHistory:
    """One conventional repository, held under the parent workspace lease."""
    def __init__(self, workspace, directory, sandbox, *, nested=False):
        self.workspace = Path(workspace).resolve(strict=True)
        self.sandbox = sandbox
        self.mount = None
        self._lease = None
        self.guard = None
        self.changed = False
        if nested:
            self._lease = mutation_lease(self.workspace, sandbox.state_dir / 'workspace-transactions')
            self._lease.__enter__()
        try:
            result = sandbox._run_command(workspace_path=str(self.workspace),
                argv=['/usr/bin/python3', '-I', '-S', '-c', _INSPECT], writable=False,
                network_access=False, timeout_seconds=20, max_output_bytes=8192,
                require_resources=True)
            if result['exit_code']:
                raise PermissionError('Cannot inspect private Git snapshot baseline')
            self.before = json.loads(result['stdout'])
            identity = self.workspace.stat()
            request = {'repository_path': str(self.workspace),
                'repository_device': identity.st_dev, 'repository_inode': identity.st_ino,
                'expected_tree': self.before['tree']}
            self.mount = _MetadataMount(request)
            directory.mkdir(mode=0o700)
            self.private = directory / 'metadata'
            _copy_directory(self.mount.git, self.private, [1_000_000, _LIMIT])
            self.clean_config = directory / 'clean-config'
            os.lseek(self.mount.config, 0, os.SEEK_SET)
            config = os.read(self.mount.config, 8192)
            self.clean_config.write_bytes(config + b'[user]\nname = AgentPorter\nemail = agents@agentporter.invalid\n')
            (self.private / 'config').write_bytes(self.clean_config.read_bytes())
            self.exchange = directory / 'exchange'
            self.exchange.mkdir(mode=0o700)
        except BaseException:
            self.close()
            raise

    def prepare(self):
        # No worker process may still be running when this method is called.
        fd = os.open(self.private, _FLAGS)
        try:
            _inspect_metadata(fd, _mount_id(fd))
        finally:
            os.close(fd)
        result = self.sandbox._run_command(workspace_path=str(self.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _EXPORT,
                  json.dumps(self.before), _INSPECT], writable=False,
            network_access=False, timeout_seconds=30, max_output_bytes=8192,
            workspace_transaction=_PrivateMount(self, exchange=True), require_resources=True)
        if result['exit_code']:
            raise PermissionError('Private Git history validation failed')
        after = json.loads(result['stdout'])
        self.changed = after != self.before
        self.plan = {'before': self.before, 'after': after}
        if self.changed:
            self.guard = self.sandbox.state_dir / 'workspace-transactions' / (
                workspace_key(os.fstat(self.mount.root)) + '.git-pending.json')

    def guard_publication(self):
        if not self.changed:
            return
        with open(self.guard, 'x', encoding='utf-8') as output:
            os.chmod(self.guard, 0o600)
            json.dump({'version': 3, 'workspace': str(self.workspace),
                       'plan': self.plan, 'exchange': str(self.exchange)}, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        fd = os.open(self.guard.parent, _FLAGS)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def publish(self):
        if not self.changed:
            return
        result = self.sandbox._run_command(workspace_path=str(self.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _IMPORT,
                  json.dumps(self.plan), _INSPECT], writable=False,
            git_metadata_writable=True, network_access=False,
            timeout_seconds=60, max_output_bytes=8192,
            workspace_transaction=_ImportMount(self), require_resources=True)
        if result['exit_code'] or result['stdout'].strip() != 'WORKSPACE_GIT_IMPORTED':
            raise ResourceCleanupError('Local Git import requires owner recovery; guard retained')

    def finish(self):
        if self.changed:
            self.guard.unlink()
            fd = os.open(self.guard.parent, _FLAGS)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def close(self):
        if self.mount is not None:
            self.mount.close()
            self.mount = None
        if self._lease is not None:
            self._lease.__exit__(None, None, None)
            self._lease = None
