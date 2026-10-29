"""Offline owner reconciliation of interrupted fetches; never fetches or retries."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_admission import inspect_recovery, resolve_recovery
from agentporter.git_approvals import GitApprovalRequest, GitApprovalVerifier, _decode
from agentporter.git_commits import _sync
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_pushes import _MAX_PACK, _write_private
from agentporter.git_smart_http import RemoteRepository
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_recovery import _directory, _maintenance
from agentporter.workspaces.leases import mutation_lease, workspace_key
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.git_fetches import _tracking_tip, _validate_tracking_ref

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read_guard(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 131072):
            raise PermissionError('Untrusted fetch recovery guard')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(131073)
        after = os.fstat(descriptor)
        if (len(raw) > 131072 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise PermissionError('Fetch recovery guard changed while reading')
    finally:
        os.close(descriptor)
    try:
        data = _decode(raw)
        if (not isinstance(data, dict) or set(data) != {'version', 'request', 'request_sha256',
                'approval_nonce', 'admission_token'} or type(data['version']) is not int or data['version'] != 2):
            raise ValueError('schema')
        for field in ('approval_nonce', 'admission_token'):
            if not isinstance(data[field], str) or not re.fullmatch('[0-9a-f]{32}', data[field]):
                raise ValueError('token')
        request = GitApprovalRequest.from_payload(data['request'])
        payload = request.to_payload()
        params = payload['parameters']
        fields = {'remote_id', 'remote_url', 'remote_ref', 'remote_oid', 'tracking_ref',
                  'old_oid', 'new_oid', 'pack_sha256', 'pack_size', 'policy_sha256'}
        if (payload['operation'] != 'fetch' or data['request_sha256'] != request.digest
                or set(params) != fields):
            raise ValueError('operation')
        tracking = _validate_tracking_ref(params['remote_id'], params['remote_ref'])
        if tracking != params['tracking_ref']:
            raise ValueError('tracking ref')
        width = len(params['remote_oid']) if isinstance(params['remote_oid'], str) else 0
        if width not in (40, 64):
            raise ValueError('object width')
        pattern = re.compile(r'[0-9a-f]{%d}' % width)
        for field in ('remote_oid', 'new_oid'):
            if not isinstance(params[field], str) or not pattern.fullmatch(params[field]):
                raise ValueError('remote object')
        if (not isinstance(params['old_oid'], str)
                or params['old_oid'] != '0' * width and not pattern.fullmatch(params['old_oid'])
                or params['remote_oid'] != params['new_oid']
                or len(payload['expected_tree']) != width):
            raise ValueError('old/new object')
        for field in ('pack_sha256', 'policy_sha256'):
            if not isinstance(params[field], str) or not re.fullmatch('[0-9a-f]{64}', params[field]):
                raise ValueError('digest')
        if (not isinstance(params['remote_id'], str)
                or not re.fullmatch('[A-Za-z0-9_-]{1,128}', params['remote_id'])
                or type(params['pack_size']) is not int or not 1 <= params['pack_size'] <= _MAX_PACK):
            raise ValueError('remote or pack')
        RemoteRepository(params['remote_url'])
    except (ValueError, TypeError, KeyError):
        raise PermissionError('Invalid fetch recovery scope') from None
    return data, request, hashlib.sha256(raw).hexdigest()


def recover_fetch(service, workspace_id, *, apply=False, expected_plan_sha256=None):
    """Inspect the exact tracking ref and release a guard only after owner review.

    An orphaned validated pack may remain in the object store if interruption
    happened after promotion. Recovery never deletes objects or updates refs.
    """
    state = Path(service.sandbox.state_dir).resolve(strict=True)
    workspace = Path(service.registry.get(workspace_id).path).resolve(strict=True)
    transactions = state / 'workspace-transactions'
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Fetch recovery state overlaps workspace')
    with _maintenance(state), mutation_lease(workspace, transactions, allow_pending=True):
        _directory(transactions, private=True)
        root = os.open(workspace, _DIRECTORY)
        try:
            identity = os.fstat(root)
            guard = transactions / (workspace_key(identity) + '.git-pending.json')
            data, request, guard_hash = _read_guard(guard)
            payload = request.to_payload()
            params = payload['parameters']
            if (payload['workspace_id'] != workspace_id or payload['repository_path'] != str(workspace)
                    or (payload['repository_device'], payload['repository_inode'])
                    != (identity.st_dev, identity.st_ino)):
                raise PermissionError('Fetch guard repository identity changed')
            service.verifier.assert_consumed(data['approval_nonce'], request)
            admission = inspect_recovery(state, data['admission_token'], request.digest, guard)
            grant, _ = service.authority.authorize(
                workspace_id, params['remote_id'], params['remote_ref'], 'fetch')
            if (grant.repository.url != params['remote_url']
                    or service.authority.policy_sha256 != params['policy_sha256']):
                raise PermissionError('Fetch authority differs from signed request')
            algorithm = 'sha256' if len(params['remote_oid']) == 64 else 'sha1'
            observed = _tracking_tip(service.sandbox, workspace, params['tracking_ref'], algorithm)
            status = ('approved_tip' if observed == params['remote_oid'] else
                      'original_tip' if observed == params['old_oid'] else 'conflict')
            plan = {'workspace_id': workspace_id, 'repository_path': str(workspace),
                'request_sha256': request.digest, 'approval_nonce': data['approval_nonce'],
                'guard_sha256': guard_hash, 'tracking_ref': params['tracking_ref'],
                'old_oid': params['old_oid'], 'approved_oid': params['remote_oid'],
                'observed_oid': observed, 'observed_state': status,
                'admission_token': data['admission_token'], 'admission_status': admission,
                'orphan_pack_possible': status == 'original_tip'}
            digest = hashlib.sha256(json.dumps(
                plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            report = {**plan, 'plan_sha256': digest}
            if not apply:
                return report
            if expected_plan_sha256 != digest or status == 'conflict':
                raise PermissionError('Fetch recovery plan changed or tracking ref conflicts')
            if _read_guard(guard)[2] != guard_hash:
                raise PermissionError('Fetch guard changed during owner review')
            current = workspace.stat()
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise PermissionError('Fetch workspace changed during recovery')
            latest = _tracking_tip(service.sandbox, workspace, params['tracking_ref'], algorithm)
            latest_status = ('approved_tip' if latest == params['remote_oid'] else
                'original_tip' if latest == params['old_oid'] else 'conflict')
            if latest != observed or latest_status != status:
                raise PermissionError('Fetch tracking ref changed during owner review')
            receipts = state / 'git-fetch-recovery-receipts'
            receipts.mkdir(mode=0o700, exist_ok=True)
            _directory(receipts, private=True)
            receipt = receipts / (uuid.uuid4().hex + '.json')
            _write_private(receipt, {**report, 'status': 'recovered'})
            _sync(receipts)
            _sync(state)
            resolve_recovery(state, data['admission_token'], request.digest, guard)
            guard.unlink()
            _sync(transactions)
            return {**report, 'status': 'recovered', 'receipt': str(receipt)}
        finally:
            os.close(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--workspace-id', required=True)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--public-key', required=True,
                        help='Protected raw 32-byte Ed25519 verification key')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expect-plan-sha256')
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        parser.error('Run as the non-root owner of the private backend state and ledger')
    try:
        descriptor = os.open(args.public_key,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
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
        authority = load_owner_git_remotes(args.config_dir, registry, args.state_dir)
        if authority is None:
            raise PermissionError('Owner Git remote policy is not installed')
        from agentporter.agents.development import DevelopmentRuntime
        pinned_bwrap = DevelopmentRuntime._sandbox_executable(
            {'sandbox_executable': '/opt/agentporter-bcc/bin/bwrap'})
        os.environ['PATH'] = str(Path(pinned_bwrap).parent) + os.pathsep + os.environ.get('PATH', '')
        with tempfile.TemporaryDirectory(prefix='git-fetch-recovery-') as temporary:
            sandbox = BubblewrapSandbox(Path(temporary))
            sandbox.state_dir = Path(args.state_dir)
            service = SimpleNamespace(registry=registry, sandbox=sandbox,
                verifier=verifier, authority=authority)
            result = recover_fetch(service, args.workspace_id, apply=args.apply,
                expected_plan_sha256=args.expect_plan_sha256)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError,
            subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
