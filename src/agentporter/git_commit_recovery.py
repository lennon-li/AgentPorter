"""Offline owner reconciliation of guarded approved-commit outcomes.

Never creates or retries a commit, rewrites history, or restores a spent nonce.
No MCP/REST entry point exists. Guard clearance requires a reviewed plan hash.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
import subprocess
import tempfile
import time
from types import SimpleNamespace
import uuid
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_approval_state import _INSPECT, _same_identity
from agentporter.git_approvals import GitApprovalRequest, GitApprovalVerifier, _decode
from agentporter.git_commits import _parameters, _sync, _inspect_metadata, _mount_id
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_recovery import _maintenance, _directory
from agentporter.workspaces.leases import mutation_lease, workspace_key
from agentporter.workspaces.registry import WorkspaceRegistry

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OBSERVE = r'''
import contextlib, io, json, os, pathlib, subprocess, sys, tempfile
request = json.loads(sys.argv[1])
namespace = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], namespace)
parameters = request['parameters']
with tempfile.TemporaryDirectory(prefix='git-reconcile-', dir='/tmp') as temporary:
    scratch = pathlib.Path(temporary) / 'metadata'
    kind = 'sha256' if len(request['expected_tree']) == 64 else 'sha1'
    namespace['run'](['init', '--quiet', '--bare', '--template=', '--object-format=' + kind, str(scratch)])
    environment = dict(namespace['environment'], GIT_DIR=str(scratch),
        GIT_AUTHOR_NAME=parameters['author_name'], GIT_AUTHOR_EMAIL=parameters['author_email'],
        GIT_COMMITTER_NAME=parameters['author_name'], GIT_COMMITTER_EMAIL=parameters['author_email'],
        GIT_AUTHOR_DATE=str(parameters['timestamp']) + ' +0000',
        GIT_COMMITTER_DATE=str(parameters['timestamp']) + ' +0000')
    author = namespace['run'](['var', 'GIT_AUTHOR_IDENT'], env=environment)[1]
    committer = namespace['run'](['var', 'GIT_COMMITTER_IDENT'], env=environment)[1]
    headers = ['tree ' + request['expected_tree']]
    if request['expected_head'] is not None:
        headers.append('parent ' + request['expected_head'])
    headers += ['author ' + author, 'committer ' + committer]
    message = parameters['message'].encode('utf-8')
    body = ('\n'.join(headers) + '\n\n').encode('utf-8') + message
    result = subprocess.run(namespace['base'] + ['hash-object', '-t', 'commit', '--stdin'],
        input=body, env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=5, check=False)
    if result.returncode or len(result.stdout) > 128:
        raise RuntimeError('Cannot derive approved commit identity')
    expected = result.stdout.decode('ascii').strip()
    content_matches = None
    if namespace['head'] == expected:
        # A ref filename alone is insufficient evidence: compare the actual
        # decompressed commit bytes with the exact approved object body.
        readable = dict(environment, GIT_ALTERNATE_OBJECT_DIRECTORIES='/workspace/.git/objects')
        process = subprocess.Popen(namespace['base'] + ['cat-file', 'commit', expected],
            env=readable, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
        try:
            actual = process.stdout.read(len(body) + 1)
            if len(actual) > len(body):
                process.kill()
            status = process.wait(timeout=5)
            content_matches = status == 0 and actual == body
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
print(json.dumps({'head': namespace['head'], 'tree': namespace['tree'],
                  'branch': namespace['branch'], 'expected_commit': expected,
                  'commit_content_matches': content_matches}))
'''


def _read_guard(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077
                or before.st_size > 131072):
            raise PermissionError('Untrusted approved Git recovery guard')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(131073)
        after = os.fstat(descriptor)
        if (len(raw) > 131072 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise PermissionError('Approved Git recovery guard changed while reading')
    finally:
        os.close(descriptor)
    data = _decode(raw)
    fields = {'version', 'request', 'request_sha256', 'approval_nonce'}
    if (not isinstance(data, dict) or type(data.get('version')) is not int
            or data['version'] not in {1, 2}
            or set(data) != (fields | {'admission_token'} if data['version'] == 2 else fields)):
        raise PermissionError('Unsupported approved Git recovery guard')
    if data['version'] == 2 and (not isinstance(data['admission_token'], str)
            or not re.fullmatch('[0-9a-f]{32}', data['admission_token'])):
        raise PermissionError('Invalid approved Git admission token')
    request = GitApprovalRequest.from_payload(data['request'])
    payload = request.to_payload()
    parameters = payload['parameters']
    if (payload['operation'] != 'commit' or payload['branch'] is None
            or data['request_sha256'] != request.digest
            or set(parameters) != {'message', 'timestamp', 'author_name', 'author_email'}):
        raise PermissionError('Invalid approved Git recovery scope')
    for name in ('author_name', 'author_email'):
        value = parameters[name]
        if (not isinstance(value, str) or not value or len(value) > 256
                or any(ord(c) < 32 or ord(c) == 127 or c in '<>' for c in value)):
            raise PermissionError('Invalid recovery author identity')
    _parameters(parameters['message'], parameters['timestamp'],
                parameters['author_name'], parameters['author_email'])
    return data, request, hashlib.sha256(raw).hexdigest()


def _sync_observed_commit(metadata, branch):
    """Persist observed ref/reflog state without changing repository content."""
    parts = branch.split('/')
    if (not branch.startswith('refs/heads/') or any(part in {'', '.', '..'} for part in parts)):
        raise PermissionError('Invalid recovery branch path')
    deadline = time.monotonic() + 15
    for relative in (branch, 'logs/' + branch, 'logs/HEAD'):
        descriptors = [os.dup(metadata)]
        try:
            components = relative.split('/')
            for part in components[:-1]:
                descriptors.append(os.open(part, _DIRECTORY, dir_fd=descriptors[-1]))
            descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=descriptors[-1])
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise PermissionError('Untrusted observed Git outcome file')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            for descriptor in reversed(descriptors):
                if time.monotonic() >= deadline:
                    raise PermissionError('Git recovery durability check exceeded its budget')
                os.fsync(descriptor)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
    objects = os.open('objects', _DIRECTORY, dir_fd=metadata)
    try:
        # Only loose-object fanout directories can have been created by the
        # approved commit. At most 256 directories require persistence.
        for first in '0123456789abcdef':
            for second in '0123456789abcdef':
                if time.monotonic() >= deadline:
                    raise PermissionError('Git recovery durability check exceeded its budget')
                try:
                    descriptor = os.open(first + second, _DIRECTORY, dir_fd=objects)
                except FileNotFoundError:
                    continue
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        os.fsync(objects)
        os.fsync(metadata)
    finally:
        os.close(objects)


def recover_git(service, workspace_id, *, apply=False, expected_plan_sha256=None):
    """Inspect or acknowledge an exact guarded outcome; never publish Git data."""
    state = Path(service.sandbox.state_dir).resolve(strict=True)
    workspace = Path(service.registry.get(workspace_id).path).resolve(strict=True)
    transactions = state / 'workspace-transactions'
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Git recovery state must be outside the workspace')
    with _maintenance(state), mutation_lease(workspace, transactions, allow_pending=True):
        _directory(transactions, private=True)
        root = os.open(workspace, _DIRECTORY)
        metadata = None
        try:
            metadata = os.open('.git', _DIRECTORY, dir_fd=root)
            locks = _inspect_metadata(metadata, _mount_id(root), allow_locks=True)
            identity = os.fstat(root)
            guard = transactions / (workspace_key(identity) + '.git-pending.json')
            data, request, guard_hash = _read_guard(guard)
            payload = request.to_payload()
            if (payload['workspace_id'] != workspace_id or payload['repository_path'] != str(workspace)
                    or (payload['repository_device'], payload['repository_inode'])
                    != (identity.st_dev, identity.st_ino)):
                raise PermissionError('Git guard repository identity does not match')
            service.verifier.assert_consumed(data['approval_nonce'], request)
            admission = None
            token = data.get('admission_token')
            if token is not None:
                from agentporter.git_admission import inspect_recovery
                admission = inspect_recovery(state, token, request.digest, guard)
            result = service.sandbox._run_command(workspace_path=str(workspace),
                argv=['/usr/bin/python3', '-I', '-S', '-c', _OBSERVE,
                      request.canonical_payload.decode(), _INSPECT],
                writable=False, git_metadata_writable=False, network_access=False,
                timeout_seconds=30, max_output_bytes=8192)
            if result['exit_code'] != 0:
                raise PermissionError('Read-only Git outcome inspection failed')
            _same_identity(workspace, root)
            _same_identity(workspace / '.git', metadata)
            observed = _decode(result['stdout'])
            if (not isinstance(observed, dict) or set(observed) != {'head', 'tree', 'branch', 'expected_commit', 'commit_content_matches'}
                    or not isinstance(observed['expected_commit'], str)
                    or len(observed['expected_commit']) != len(payload['expected_tree'])
                    or any(c not in '0123456789abcdef' for c in observed['expected_commit'])):
                raise PermissionError('Invalid Git recovery observation')
            status = 'conflict'
            if not locks and observed['branch'] == payload['branch']:
                if observed['head'] == observed['expected_commit'] and observed['commit_content_matches'] is True:
                    status = 'approved_commit_at_head'
                elif observed['head'] == payload['expected_head']:
                    status = 'original_head'
            plan = {'workspace_id': workspace_id, 'repository_path': str(workspace),
                    'request_sha256': request.digest, 'approval_nonce': data['approval_nonce'],
                    'guard_sha256': guard_hash, 'observed_state': status, **observed}
            plan['metadata_locks'] = locks
            plan.update(admission_token=token, admission_status=admission)
            plan_hash = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            report = {**plan, 'plan_sha256': plan_hash}
            if not apply:
                return report
            if expected_plan_sha256 != plan_hash or status == 'conflict':
                raise PermissionError('Git recovery plan changed or owner history conflicts')
            if _read_guard(guard)[2] != guard_hash:
                raise PermissionError('Git recovery guard changed after inspection')
            if status == 'approved_commit_at_head':
                _sync_observed_commit(metadata, payload['branch'])
            # The receipt records current observation, not whether an operation
            # ever ran before an owner reset. The consumed nonce stays spent.
            directory = state / 'git-recovery-receipts'
            directory.mkdir(mode=0o700, exist_ok=True)
            _directory(directory, private=True)
            receipt = directory / (uuid.uuid4().hex + '.json')
            descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                with os.fdopen(descriptor, 'w', closefd=False) as output:
                    json.dump({**report, 'status': 'recovered'}, output, sort_keys=True)
                    output.flush()
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _sync(directory)
            _sync(state)
            if token is not None:
                from agentporter.git_admission import resolve_recovery
                resolve_recovery(state, token, request.digest, guard)
            guard.unlink()
            _sync(transactions)
            return {**report, 'status': 'recovered', 'receipt': str(receipt)}
        finally:
            if metadata is not None:
                os.close(metadata)
            os.close(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--workspace-id', required=True)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--public-key', required=True, help='Protected raw 32-byte Ed25519 verification key')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expect-plan-sha256')
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        parser.error('Run as the non-root owner of the private backend state and ledger')
    try:
        descriptor = os.open(args.public_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_size != 32
                    or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022):
                raise PermissionError('Untrusted raw Git verification key')
            key = Ed25519PublicKey.from_public_bytes(os.read(descriptor, 33))
        finally:
            os.close(descriptor)
        verifier = GitApprovalVerifier(key, args.ledger, existing_only=True)
        registry = WorkspaceRegistry({args.workspace_id: {'path': args.workspace, 'writable': True}})
        # Synthetic identity files live only in temporary storage; inspection
        # does not rewrite the stopped service's own sandbox identity files.
        with tempfile.TemporaryDirectory(prefix='git-recovery-') as temporary:
            sandbox = BubblewrapSandbox(Path(temporary))
            sandbox.state_dir = Path(args.state_dir)
            service = SimpleNamespace(registry=registry, sandbox=sandbox, verifier=verifier)
            result = recover_git(service, args.workspace_id, apply=args.apply,
                                 expected_plan_sha256=args.expect_plan_sha256)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
