"""Offline owner reconciliation of remote publication; never resends a pack."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from agentporter.git_admission import inspect_recovery, resolve_recovery
from agentporter.git_approvals import GitApprovalRequest, _decode
from agentporter.git_commits import _sync
from agentporter.git_pushes import _MAX_PACK, _write_private
from agentporter.git_smart_http import RefUpdate, RemoteRepository
from agentporter.sandbox.workspace_recovery import _directory, _maintenance
from agentporter.workspaces.leases import mutation_lease, workspace_key

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read_guard(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 131072):
            raise PermissionError('Untrusted publication recovery guard')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(131073)
        after = os.fstat(descriptor)
        if (len(raw) > 131072 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise PermissionError('Publication recovery guard changed while reading')
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
        if (payload['operation'] != 'push' or payload['branch'] is None or payload['expected_head'] is None
                or data['request_sha256'] != request.digest
                or set(params) != {'remote_id', 'remote_url', 'remote_ref', 'old_oid', 'new_oid',
                                   'pack_sha256', 'pack_size', 'policy_sha256'}):
            raise ValueError('request scope')
        update = RefUpdate(params['remote_ref'], params['old_oid'], params['new_oid'])
        RemoteRepository(params['remote_url'])
        if update.new_oid != payload['expected_head'] or update.new_oid == update.old_oid:
            raise ValueError('publication identity')
        for field in ('pack_sha256', 'policy_sha256'):
            if not isinstance(params[field], str) or not re.fullmatch('[0-9a-f]{64}', params[field]):
                raise ValueError('digest')
        if (not isinstance(params['remote_id'], str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', params['remote_id'])
                or type(params['pack_size']) is not int or not 1 <= params['pack_size'] <= _MAX_PACK):
            raise ValueError('remote or pack')
    except (ValueError, TypeError, KeyError):
        raise PermissionError('Invalid publication recovery scope') from None
    return data, request, hashlib.sha256(raw).hexdigest()


def recover_push(service, workspace_id, *, apply=False, expected_plan_sha256=None):
    """Inspect exact old/new remote state; owner acknowledges a fresh plan hash.

    A report describes current observation, not whether the remote ever accepted
    the earlier request. No retry, ref write, or nonce restoration is performed.
    """
    state = Path(service.sandbox.state_dir).resolve(strict=True)
    workspace = Path(service.registry.get(workspace_id).path).resolve(strict=True)
    transactions = state / 'workspace-transactions'
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Publication recovery state overlaps workspace')
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
                    or (payload['repository_device'], payload['repository_inode']) != (identity.st_dev, identity.st_ino)):
                raise PermissionError('Publication guard repository identity changed')
            service.verifier.assert_consumed(data['approval_nonce'], request)
            admission = inspect_recovery(state, data['admission_token'], request.digest, guard)
            grant, broker = service.authority.authorize(workspace_id, params['remote_id'], params['remote_ref'], 'push')
            if (grant.repository.url != params['remote_url']
                    or service.authority.policy_sha256 != params['policy_sha256']):
                raise PermissionError('Publication authority differs from signed request')
            advertised = broker.discover('git-receive-pack')
            width = len(params['new_oid'])
            if advertised.object_format != ('sha256' if width == 64 else 'sha1'):
                raise PermissionError('Remote object format differs from guarded publication')
            observed = advertised.refs.get(params['remote_ref'], '0' * width)
            status = ('approved_tip' if observed == params['new_oid'] else
                      'original_tip' if observed == params['old_oid'] else 'conflict')
            plan = {'workspace_id': workspace_id, 'repository_path': str(workspace),
                'request_sha256': request.digest, 'approval_nonce': data['approval_nonce'],
                'guard_sha256': guard_hash, 'remote_url': params['remote_url'],
                'remote_ref': params['remote_ref'], 'observed_oid': observed, 'observed_state': status,
                'admission_token': data['admission_token'], 'admission_status': admission}
            digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            report = {**plan, 'plan_sha256': digest}
            if not apply:
                return report
            if expected_plan_sha256 != digest or status == 'conflict':
                raise PermissionError('Publication recovery plan changed or remote state conflicts')
            if _read_guard(guard)[2] != guard_hash:
                raise PermissionError('Publication guard changed during owner review')
            current = workspace.stat()
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise PermissionError('Publication workspace changed during recovery')
            receipts = state / 'git-push-recovery-receipts'
            receipts.mkdir(mode=0o700, exist_ok=True)
            _directory(receipts, private=True)
            receipt = receipts / (uuid.uuid4().hex + '.json')
            _write_private(receipt, {**report, 'status': 'recovered'})
            _sync(state)
            resolve_recovery(state, data['admission_token'], request.digest, guard)
            guard.unlink()
            _sync(transactions)
            return {**report, 'status': 'recovered', 'receipt': str(receipt)}
        finally:
            os.close(root)
