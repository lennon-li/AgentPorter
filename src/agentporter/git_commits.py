"""Internal exact-receipt commit backend; not exposed through MCP/REST.

Git receives canonical metadata writes only after signed state verification.
All untrusted repository configuration is hidden behind a sealed clean config.
Failures after launch retain a durable workspace guard for owner inspection.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
import time

from agentporter.git_approval_state import _INSPECT, locked_git_request
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.workspaces.leases import workspace_key

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

_COMMIT = r'''
import contextlib, io, json, os, subprocess, sys
request = json.loads(sys.argv[1])
namespace = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], namespace)
if any(namespace[name] != request[key] for name, key in
       [('head', 'expected_head'), ('tree', 'expected_tree'), ('branch', 'branch')]):
    raise RuntimeError('Repository state changed before approved commit')
parameters = request['parameters']
environment = dict(namespace['environment'], GIT_DIR='/workspace/.git',
                   GIT_WORK_TREE='/workspace',
                   GIT_AUTHOR_NAME=parameters['author_name'],
                   GIT_AUTHOR_EMAIL=parameters['author_email'],
                   GIT_COMMITTER_NAME=parameters['author_name'],
                   GIT_COMMITTER_EMAIL=parameters['author_email'],
                   GIT_AUTHOR_DATE=str(parameters['timestamp']) + ' +0000',
                   GIT_COMMITTER_DATE=str(parameters['timestamp']) + ' +0000')
base = ['/usr/bin/git', '-c', 'safe.directory=/workspace', '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.fsmonitor=false', '-c', 'commit.gpgsign=false',
        '-c', 'core.fsyncObjectFiles=true', '-c', 'protocol.allow=never']
def run(args, data=None):
    result = subprocess.run(base + args, input=data, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5, check=False)
    if result.returncode or len(result.stdout) > 4096:
        raise RuntimeError('Approved Git operation failed')
    return result.stdout.decode('utf-8').strip()
tree = run(['write-tree'])
if tree != request['expected_tree']:
    raise RuntimeError('Index changed before approved commit')
arguments = ['commit-tree', tree]
if request['expected_head'] is not None:
    arguments += ['-p', request['expected_head']]
commit = run(arguments, parameters['message'].encode('utf-8'))
if len(commit) != len(tree) or any(c not in '0123456789abcdef' for c in commit):
    raise RuntimeError('Invalid commit object identity')
if run(['symbolic-ref', '--quiet', 'HEAD']) != request['branch']:
    raise RuntimeError('Branch changed before approved commit')
old = request['expected_head'] or '0' * len(commit)
run(['update-ref', '--no-deref', '-m', 'AgentPorter owner-approved commit',
     request['branch'], commit, old])
# Git 2.34 on BCC supports fsyncObjectFiles, but not newer core.fsync.
# Persist ref/reflog contents and their directory entries explicitly before
# reporting success. Object data was synced by Git; sync loose-object dirs too.
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
def sync_file(relative):
    descriptors = [os.open('/workspace/.git', flags)]
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=descriptors[-1])
        try:
            os.fsync(leaf)
        finally:
            os.close(leaf)
        for descriptor in reversed(descriptors):
            os.fsync(descriptor)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
sync_file(request['branch'])
sync_file('logs/' + request['branch'])
sync_file('logs/HEAD')
objects = os.open('/workspace/.git/objects', flags)
try:
    with os.scandir(objects) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                descriptor = os.open(entry.name, flags, dir_fd=objects)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
    os.fsync(objects)
finally:
    os.close(objects)
print(commit)
'''


def _mount_id(descriptor):
    for line in Path(f'/proc/self/fdinfo/{descriptor}').read_text().splitlines():
        if line.startswith('mnt_id:'):
            return int(line.split()[1])
    raise PermissionError('Cannot identify Git metadata mount')


def _inspect_metadata(descriptor, mount_id, *, allow_locks=False):
    remaining = 1_000_000
    deadline = time.monotonic() + 30
    forbidden = {'commondir', 'reftable', 'objects/info/alternates', 'objects/info/http-alternates'}
    locks = []
    def scan(directory, relative='', depth=0):
        nonlocal remaining
        if depth > 128 or _mount_id(directory) != mount_id:
            raise PermissionError('Git metadata crosses an unsupported directory boundary')
        with os.scandir(directory) as entries:
            for entry in entries:
                remaining -= 1
                if remaining < 0 or time.monotonic() >= deadline:
                    raise PermissionError('Git metadata inspection exceeds its budget')
                path = relative + entry.name
                info = entry.stat(follow_symlinks=False)
                if path in forbidden:
                    raise PermissionError('Unsupported Git metadata layout or active Git lock')
                if entry.name.endswith('.lock'):
                    if not allow_locks:
                        raise PermissionError('Unsupported Git metadata layout or active Git lock')
                    locks.append(path)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, _DIRECTORY, dir_fd=directory)
                    try:
                        scan(child, path + '/', depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    child = os.open(entry.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        pinned = os.fstat(child)
                        if (not stat.S_ISREG(pinned.st_mode) or pinned.st_nlink != 1
                                or (pinned.st_dev, pinned.st_ino) != (info.st_dev, info.st_ino)
                                or _mount_id(child) != mount_id):
                            raise PermissionError('Git metadata changed during inspection')
                    finally:
                        os.close(child)
                else:
                    raise PermissionError('Git metadata aliases and special files are forbidden')
    scan(descriptor)
    return sorted(locks)


class _MetadataMount:
    def __init__(self, request):
        self.workspace = Path(request['repository_path'])
        self._fds = []
        try:
            self.root = os.open(self.workspace, _DIRECTORY)
            self._fds.append(self.root)
            identity = os.fstat(self.root)
            if (identity.st_dev, identity.st_ino) != (request['repository_device'], request['repository_inode']):
                raise PermissionError('Approved repository identity changed')
            self.git = os.open('.git', _DIRECTORY, dir_fd=self.root)
            self._fds.append(self.git)
            _inspect_metadata(self.git, _mount_id(self.root))
            config_info = os.stat('config', dir_fd=self.git, follow_symlinks=False)
            if not stat.S_ISREG(config_info.st_mode) or config_info.st_nlink != 1:
                raise PermissionError('Git configuration must be a regular private-inode file')
            version = 1 if len(request['expected_tree']) == 64 else 0
            config = ('[core]\nrepositoryformatversion = ' + str(version)
                      + '\nbare = false\nlogAllRefUpdates = true\nhooksPath = /dev/null\nfsmonitor = false\n')
            if version:
                config += '[extensions]\nobjectFormat = sha256\n'
            self.config = os.memfd_create('agentporter-approved-git-config', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self._fds.append(self.config)
            os.write(self.config, config.encode('ascii'))
            os.lseek(self.config, 0, os.SEEK_SET)
            fcntl.fcntl(self.config, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        except BaseException:
            self.close()
            raise

    @property
    def launch_fds(self):
        return tuple(self._fds)

    wrap_argv = staticmethod(WorkspaceTransaction.wrap_argv)

    def wrap_command(self, command):
        current = self.workspace.stat()
        pinned = os.fstat(self.root)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise PermissionError('Approved repository root changed before launch')
        command = list(command)
        matches = [i for i in range(len(command) - 2)
                   if command[i:i + 3] == ['--ro-bind', str(self.workspace), '/workspace']]
        if len(matches) != 1 or '--' in command:
            raise PermissionError('Expected one read-only repository mount')
        index = matches[0]
        command[index + 1] = f'/proc/self/fd/{self.root}'
        # Bubblewrap's --ro-bind-data consumes the descriptor offset. A single
        # trusted operation may launch multiple phases with this sealed config.
        os.lseek(self.config, 0, os.SEEK_SET)
        command += ['--bind', f'/proc/self/fd/{self.git}', '/workspace/.git',
                    '--ro-bind-data', str(self.config), '/workspace/.git/config']
        return command

    def close(self):
        while self._fds:
            os.close(self._fds.pop())


def _parameters(message, timestamp, author_name, author_email):
    if (not isinstance(message, str) or not message.strip() or '\0' in message
            or len(message.encode('utf-8')) > 32768 or type(timestamp) is not int
            or not 1 <= timestamp < 2**63):
        raise ValueError('Invalid exact commit message or timestamp')
    return {'message': message, 'timestamp': timestamp,
            'author_name': author_name, 'author_email': author_email}


def _sync(directory):
    descriptor = os.open(directory, _DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _record_success(state, approval, request, commit):
    directory = state / 'git-receipts'
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise ResourceCleanupError('Approved Git receipt storage is untrusted; guard retained')
    parent = os.open(directory, _DIRECTORY)
    try:
        descriptor = os.open(approval.nonce + '.json',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, 'w', closefd=False) as output:
                json.dump({'version': 1, 'request_sha256': request.digest,
                           'approval_nonce': approval.nonce, 'commit': commit,
                           'request': request.to_payload()}, output, sort_keys=True)
                output.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)
    _sync(state)


class ApprovedGitCommits:
    """Dependencies and author identity must come from sealed backend policy."""
    def __init__(self, registry, sandbox, verifier, *, author_name, author_email, job_manager=None):
        if not sandbox.transactional_writes or sandbox.resources is None:
            raise PermissionError('Approved Git requires supervised transaction-enabled runtime')
        for value in (author_name, author_email):
            if (not isinstance(value, str) or not value or len(value) > 256
                    or any(ord(c) < 32 or ord(c) == 127 or c in '<>' for c in value)):
                raise ValueError('Invalid protected Git author identity')
        self.registry, self.sandbox, self.verifier = registry, sandbox, verifier
        self.author_name, self.author_email = author_name, author_email
        self.job_manager = job_manager
        if job_manager is not None:
            if (Path(job_manager.state_dir).resolve() != Path(sandbox.state_dir).resolve()
                    or job_manager.resources is not sandbox.resources):
                raise PermissionError('Approved Git must share gateway state and resource supervision')

    def _authorize_commit(self, receipt, request):
        return self.verifier.verify_and_consume(receipt, request)

    def _require_runtime(self):
        if self.sandbox.transactional_writes is not True or self.sandbox.resources is None:
            raise PermissionError('Approved Git requires supervised transaction-enabled runtime')

    def prepare(self, workspace_id, message, timestamp):
        if self.job_manager is not None:
            from agentporter.admission import synchronous_slot
            with synchronous_slot(self.job_manager):
                return self._prepare(workspace_id, message, timestamp)
        return self._prepare(workspace_id, message, timestamp)

    def _prepare(self, workspace_id, message, timestamp):
        self._require_runtime()
        parameters = _parameters(message, timestamp, self.author_name, self.author_email)
        with locked_git_request(self.registry, self.sandbox, workspace_id, 'commit', parameters) as request:
            if request.to_payload()['branch'] is None:
                raise PermissionError('Approved commits require an explicit local branch')
            return request

    def commit(self, workspace_id, message, timestamp, receipt):
        if self.job_manager is None:
            return self._commit(workspace_id, message, timestamp, receipt)
        from agentporter.admission import execution_slot
        from agentporter.git_admission import resolve
        with execution_slot(self.job_manager) as token:
            try:
                return self._commit(workspace_id, message, timestamp, receipt, admission_token=token)
            except ResourceCleanupError:
                raise
            except BaseException:
                resolve(self.job_manager, token)
                raise

    def _commit(self, workspace_id, message, timestamp, receipt, *, admission_token=None):
        self._require_runtime()
        parameters = _parameters(message, timestamp, self.author_name, self.author_email)
        with locked_git_request(self.registry, self.sandbox, workspace_id, 'commit', parameters) as request:
            payload = request.to_payload()
            if payload['branch'] is None:
                raise PermissionError('Approved commits require an explicit local branch')
            mount = _MetadataMount(payload)
            guarded = False
            try:
                approval = self._authorize_commit(receipt, request)
                state = self.sandbox.state_dir / 'workspace-transactions'
                guard = state / (workspace_key(os.fstat(mount.root)) + '.git-pending.json')
                descriptor = os.open(guard, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                guarded = True
                try:
                    with os.fdopen(descriptor, 'w', closefd=False) as output:
                        journal = {'version': 1, 'request': payload, 'request_sha256': request.digest,
                                   'approval_nonce': approval.nonce}
                        if admission_token is not None:
                            journal.update(version=2, admission_token=admission_token)
                        json.dump(journal, output, sort_keys=True)
                        output.flush()
                        os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _sync(state)
                if admission_token is not None:
                    from agentporter.git_admission import bind
                    bind(self.job_manager, admission_token, request.digest, guard)
                self._require_runtime()
                result = self.sandbox._run_command(workspace_path=str(mount.workspace),
                    argv=['/usr/bin/python3', '-I', '-S', '-c', _COMMIT,
                          request.canonical_payload.decode(), _INSPECT],
                    writable=False, git_metadata_writable=True, network_access=False,
                    timeout_seconds=30, max_output_bytes=8192, workspace_transaction=mount,
                    require_resources=True)
                commit = result['stdout'].strip()
                if (result['exit_code'] != 0 or len(commit) != len(payload['expected_tree'])
                        or any(c not in '0123456789abcdef' for c in commit)):
                    raise ResourceCleanupError('Approved Git outcome requires owner inspection; guard retained')
                _record_success(state, approval, request, commit)
                if admission_token is not None:
                    from agentporter.git_admission import resolve
                    resolve(self.job_manager, admission_token)
                guard.unlink()
                _sync(state)
                return commit
            except BaseException as error:
                if guarded and not isinstance(error, ResourceCleanupError):
                    raise ResourceCleanupError('Approved Git guard requires owner inspection') from error
                raise
            finally:
                mount.close()


class _WorkspaceCommitClaims:
    """Local operation IDs in the existing protected recovery ledger format.

    This is durable execution evidence, not a human signature. Workspace
    membership supplies authorization; recovery still checks the exact digest.
    """
    def __init__(self, state_dir):
        from agentporter.git_approvals import GitApprovalVerifier
        self.ledger = GitApprovalVerifier(None,
            Path(state_dir) / 'workspace-commit-claims' / 'claims.db')

    def claim(self, request):
        import secrets
        import sqlite3
        from types import SimpleNamespace
        self.ledger._check_ledger_identity()
        nonce = secrets.token_hex(16)
        with sqlite3.connect(self.ledger.ledger_path, timeout=5) as database:
            database.execute('PRAGMA synchronous=FULL')
            database.execute('INSERT INTO consumed VALUES (?,?,?,?)',
                             (nonce, request.digest, int(time.time()), 0))
        return SimpleNamespace(nonce=nonce)

    def assert_consumed(self, nonce, request):
        self.ledger.assert_consumed(nonce, request)


class WorkspaceGitCommits(ApprovedGitCommits):
    """Ordinary offline commits authorized by writable workspace membership.

    Reuses bounded inspection, exclusive leases, sealed Git configuration,
    compare-and-swap refs and durable recovery; no phone credential is involved.
    """
    requires_receipt = False

    def __init__(self, registry, sandbox, *, job_manager=None):
        super().__init__(registry, sandbox, _WorkspaceCommitClaims(sandbox.state_dir), author_name='AgentPorter',
                         author_email='agents@agentporter.invalid', job_manager=job_manager)

    def _authorize_commit(self, receipt, request):
        if receipt:
            raise ValueError('Workspace commits do not accept external receipts')
        return self.verifier.claim(request)
