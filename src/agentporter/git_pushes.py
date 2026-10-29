"""Internal single-use owner-approved, fast-forward-only Git publication.

No public API uses this backend yet. The host broker alone sees credentials;
fixed, supervised offline Git generates an immutable pack from read-only
metadata. Any failure after durable intent retains capacity and workspace guard.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from agentporter.admission import execution_slot, synchronous_slot
from agentporter.git_admission import bind, resolve
from agentporter.git_approvals import GitApprovalRequest
from agentporter.git_approval_state import _INSPECT, _same_identity, locked_git_request
from agentporter.git_commits import _MetadataMount, _sync
from agentporter.git_smart_http import RefUpdate, validate_pack
from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import workspace_key

_MAX_PACK = 64 * 1024 * 1024 - 65520
_PACK = r'''
import contextlib, io, json, os, pathlib, resource, subprocess, sys
request = json.loads(sys.argv[1])
old = sys.argv[3]
namespace = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], namespace)
def same():
    if any(namespace[name] != request[key] for name, key in
           [('head', 'expected_head'), ('tree', 'expected_tree'), ('branch', 'branch')]):
        raise RuntimeError('Local state changed before approved publication')
same()
head = request['expected_head']
if head is None or request['branch'] is None:
    raise RuntimeError('Publication requires a committed local branch')
environment = dict(namespace['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace',
                   GIT_GRAFT_FILE='/dev/null')
if os.path.lexists('/workspace/.git/shallow'):
    raise RuntimeError('Publication requires a complete local history')
base = ['/usr/bin/git', '-c', 'safe.directory=/workspace', '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never']
resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
def run(args, data=None, maximum=4096, statuses=(0,)):
    with open('/tmp/git-publication-output', 'w+b') as output:
        result = subprocess.run(base + args, input=data, stdout=output, stderr=subprocess.DEVNULL,
                                env=environment, timeout=20, check=False)
        output.seek(0)
        body = output.read(maximum + 1)
    if result.returncode not in statuses or len(body) > maximum:
        raise RuntimeError('Offline publication graph validation failed')
    return body
if old != '0' * len(head):
    if run(['cat-file', '-t', old]).strip() != b'commit':
        raise RuntimeError('Remote tip must exist locally as a commit')
    run(['merge-base', '--is-ancestor', old, head])
run(['fsck', '--strict', '--no-reflogs', head])
width = len(head)
lines = run(['rev-list', '--objects', '--no-object-names', head], maximum=100000 * (width + 1)).splitlines()
if (not lines or len(lines) > 100000 or any(len(line) != width or
        any(c not in b'0123456789abcdef' for c in line) for line in lines)):
    raise RuntimeError('Publication object graph exceeds bound')
objects = b'\n'.join(sorted(set(lines))) + b'\n'
fd = os.open('/out/pack', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    result = subprocess.run(base + ['pack-objects', '--stdout', '--no-reuse-delta',
        '--no-reuse-object', '--compression=1', '--window=0', '--threads=1'],
        input=objects, stdout=output, stderr=subprocess.DEVNULL,
        env=environment, timeout=20, check=False)
    if result.returncode:
        raise RuntimeError('Publication pack generation failed')
namespace = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], namespace)
same()
print('pack-ready')
'''


class _PackMount(_MetadataMount):
    def __init__(self, request, output):
        super().__init__(request)
        try:
            self.output = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._fds.append(self.output)
        except BaseException:
            self.close()
            raise

    def wrap_command(self, command):
        command = super().wrap_command(command)
        index = command.index(f'/proc/self/fd/{self.git}')
        if command[index - 1] != '--bind':
            raise PermissionError('Unexpected metadata mount')
        command[index - 1] = '--ro-bind'
        return command + ['--bind', f'/proc/self/fd/{self.output}', '/out']


def _read_pack(path, algorithm):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 1 <= info.st_size <= _MAX_PACK):
            raise PermissionError('Invalid private publication pack')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            pack = stream.read(_MAX_PACK + 1)
    finally:
        os.close(descriptor)
    validate_pack(pack, algorithm)
    return pack


def _write_private(path, document):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'w', closefd=False) as stream:
            json.dump(document, stream, sort_keys=True)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync(path.parent)


class ApprovedGitPushes:
    def __init__(self, registry, sandbox, authority, manager):
        self.registry, self.sandbox, self.authority, self.manager = registry, sandbox, authority, manager
        self.verifier = authority.verifier
        self._require_runtime()

    def _require_runtime(self):
        if (self.sandbox.transactional_writes is not True or self.sandbox.resources is None
                or self.manager.resources is not self.sandbox.resources
                or Path(self.manager.state_dir).resolve() != Path(self.sandbox.state_dir).resolve()):
            raise PermissionError('Approved publication requires shared supervised runtime and admission')

    def _capture(self, request, old):
        self._require_runtime()
        payload = request.to_payload()
        algorithm = 'sha256' if len(payload['expected_tree']) == 64 else 'sha1'
        with tempfile.TemporaryDirectory(prefix='git-publication-') as temporary:
            mount = _PackMount(payload, temporary)
            try:
                result = self.sandbox._run_command(workspace_path=payload['repository_path'],
                    argv=['/usr/bin/python3', '-I', '-S', '-c', _PACK,
                          request.canonical_payload.decode(), _INSPECT, old],
                    writable=False, git_metadata_writable=True, network_access=False,
                    workspace_transaction=mount, require_resources=True,
                    timeout_seconds=120, max_output_bytes=8192)
                if result['exit_code'] != 0 or result['stdout'].strip() != 'pack-ready':
                    raise PermissionError('Offline publication graph/pack validation failed')
                _same_identity(mount.workspace, mount.root)
                _same_identity(mount.workspace / '.git', mount.git)
                return _read_pack(Path(temporary) / 'pack', algorithm)
            finally:
                mount.close()

    def _proposal(self, request, grant, broker, remote_id):
        payload = request.to_payload()
        if payload['expected_head'] is None or payload['branch'] is None:
            raise PermissionError('Publication requires a committed local branch')
        advertisement = broker.discover('git-receive-pack')
        width = len(payload['expected_head'])
        if advertisement.object_format != ('sha256' if width == 64 else 'sha1'):
            raise PermissionError('Remote and local Git object formats differ')
        old = advertisement.refs.get(grant.ref, '0' * width)
        update = RefUpdate(grant.ref, old, payload['expected_head'])
        if update.old_oid == update.new_oid:
            raise PermissionError('Remote already has the requested commit')
        pack = self._capture(request, old)
        parameters = {'remote_id': remote_id, 'remote_url': grant.repository.url,
            'remote_ref': grant.ref, 'old_oid': old, 'new_oid': payload['expected_head'],
            'pack_sha256': hashlib.sha256(pack).hexdigest(), 'pack_size': len(pack),
            'policy_sha256': self.authority.policy_sha256}
        return GitApprovalRequest.from_payload({**payload, 'parameters': parameters}), update, pack

    def prepare(self, workspace_id, remote_id, ref):
        self._require_runtime()
        with synchronous_slot(self.manager):
            grant, broker = self.authority.authorize(workspace_id, remote_id, ref, 'push')
            with locked_git_request(self.registry, self.sandbox, workspace_id, 'push', {}) as state:
                return self._proposal(state, grant, broker, remote_id)[0]

    def push(self, workspace_id, remote_id, ref, receipt):
        self._require_runtime()
        with execution_slot(self.manager) as token:
            guarded = False
            try:
                grant, broker = self.authority.authorize(workspace_id, remote_id, ref, 'push')
                with locked_git_request(self.registry, self.sandbox, workspace_id, 'push', {}) as state:
                    request, update, pack = self._proposal(state, grant, broker, remote_id)
                    payload = request.to_payload()
                    transactions = Path(self.sandbox.state_dir) / 'workspace-transactions'
                    identity = Path(payload['repository_path']).stat()
                    if (identity.st_dev, identity.st_ino) != (payload['repository_device'], payload['repository_inode']):
                        raise PermissionError('Publication repository identity changed before approval')
                    approval = self.verifier.verify_and_consume(receipt, request)
                    guard = transactions / (workspace_key(identity) + '.git-pending.json')
                    # Set before creation: even a partial durable intent needs
                    # owner inspection and must never release publication capacity.
                    guarded = True
                    _write_private(guard, {'version': 2, 'request': payload,
                        'request_sha256': request.digest, 'approval_nonce': approval.nonce,
                        'admission_token': token})
                    bind(self.manager, token, request.digest, guard)
                    self._require_runtime()
                    # Revalidate eligibility immediately before credential use.
                    _, broker = self.authority.authorize(workspace_id, remote_id, ref, 'push')
                    broker.send_push(update, pack)
                    receipts = transactions / 'git-push-receipts'
                    receipts.mkdir(mode=0o700, exist_ok=True)
                    from agentporter.sandbox.workspace_recovery import _directory
                    _directory(receipts, private=True)
                    _write_private(receipts / (approval.nonce + '.json'), {
                        'version': 1, 'request': payload, 'request_sha256': request.digest,
                        'approval_nonce': approval.nonce, 'remote_acknowledged': True})
                    _sync(transactions)
                    resolve(self.manager, token)
                    guard.unlink()
                    _sync(transactions)
                    return update.new_oid
            except BaseException as error:
                if guarded:
                    raise ResourceCleanupError('Approved publication requires owner reconciliation; guard retained') from None
                if not isinstance(error, ResourceCleanupError):
                    resolve(self.manager, token)
                raise
