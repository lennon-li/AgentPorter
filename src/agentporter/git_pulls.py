"""Signed/admitted pull acquisition, private integration and coherent publication.

The complete remote graph first crosses into a private transaction. Canonical
publication uses the transaction coordinator with exact consumed tracking
authority and retained ordinary+Git custody. Conflicts and refusals retain
nonpublished evidence. Runtime wiring still requires independent review and
authenticated delegated RPC acceptance.
"""
from dataclasses import dataclass
import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
import json
import os
from pathlib import Path
import tempfile

from agentporter.admission import execution_slot, synchronous_slot
from agentporter.git_admission import bind, resolve
from agentporter.git_approval_state import _INSPECT, _same_identity
from agentporter.git_approvals import GitApprovalRequest, _APPROVAL_DOMAIN, _AUDIENCE, _canonical, _decode
from agentporter.git_commits import _sync
from agentporter.git_fetches import (
    _INDEX, _TRACK, _UPDATE, _promote_quarantine, _validate_tracking_ref, _write_fetch_guard,
)
from agentporter.git_pull_integration import PrivateGitPullIntegration, _MODES, _PullMount, _PROGRAM
from agentporter.git_pushes import _MAX_PACK, _write_private
from agentporter.git_smart_http import validate_pack
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.workspaces.leases import workspace_key


@dataclass(frozen=True)
class _ConsumedTrackingAuthorization:
    """Exact future publication input; never a worker-controlled ref allowlist."""
    request_sha256: str
    approval_nonce: str
    repository_device: int
    repository_inode: int
    metadata_device: int
    metadata_inode: int
    tracking_ref: str
    old_oid: str
    new_oid: str
    pack_sha256: str
    policy_sha256: str
    mode: str
    request_canonical_payload: bytes
    approval_receipt: str
    owner_config_dir: str
    ledger_path: str
    ledger_identity: tuple
    ledger_parent_identity: tuple
    verification_key: str
    authorization_mode: str = 'owner_signature'

    def to_payload(self):
        tracking_fields = ('repository_device', 'repository_inode', 'metadata_device',
            'metadata_inode', 'tracking_ref', 'old_oid', 'new_oid', 'pack_sha256', 'policy_sha256', 'mode')
        result={'version': 1, 'request': GitApprovalRequest(self.request_canonical_payload).to_payload(),
            'request_sha256': self.request_sha256, 'approval_receipt': self.approval_receipt,
            'approval_nonce': self.approval_nonce,
            'verification_context': {'owner_config_dir': self.owner_config_dir,
                'policy_sha256': self.policy_sha256, 'ledger_path': self.ledger_path,
                'ledger_device': self.ledger_identity[0], 'ledger_inode': self.ledger_identity[1],
                'ledger_parent_device': self.ledger_parent_identity[0],
                'ledger_parent_inode': self.ledger_parent_identity[1],
                'verification_key': self.verification_key},
            'tracking': {key: getattr(self, key) for key in tracking_fields}}
        if self.authorization_mode=='workspace':result.update(version=2,authorization_mode='workspace')
        return result


def _consumed_tracking(request, approval, verifier, authority, receipt):
    if approval.request_digest != request.digest:
        raise PermissionError('Pull approval does not match exact tracking intent')
    verifier.assert_consumed(approval.nonce, request)
    payload = request.to_payload()
    parameters = payload['parameters']
    if payload['operation'] not in {'pull','fetch'}:
        raise PermissionError('Tracking intent requires a consumed pull request')
    if _validate_tracking_ref(parameters['remote_id'], parameters['remote_ref']) != parameters['tracking_ref']:
        raise PermissionError('Pull tracking intent is not exact')
    return _ConsumedTrackingAuthorization(request.digest, approval.nonce,
        payload['repository_device'], payload['repository_inode'],
        parameters['metadata_device'], parameters['metadata_inode'],
        parameters['tracking_ref'], parameters['old_oid'], parameters['new_oid'],
        parameters['pack_sha256'], parameters['policy_sha256'], parameters['mode'],
        request.canonical_payload, receipt, str(Path(authority._config_dir).resolve(strict=True)),
        str(verifier.ledger_path), tuple(verifier._ledger_identity), tuple(verifier._parent_identity),
        verifier.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        getattr(authority,'authorization_mode','owner_signature'))


def _relative(request):
    from agentporter.git_remote_policy import repository_relative
    return repository_relative(request.to_payload()['parameters'].get('repository_relative','.'))


def _history(transaction,repository='.'):
    key='.git' if repository=='.' else repository+'/.git'
    history=transaction.git_histories.get(key)
    if history is None:raise PermissionError('Pull requires its exact preexisting repository history')
    return history


class _MetadataMount(_PullMount):
    """Metadata-only fixed programs never remount an active overlay upper/work."""
    def wrap_command(self,command):
        command=list(command)
        matches=[i for i in range(len(command)-2) if command[i:i+3]==['--ro-bind',f'/proc/self/fd/{self.sandbox_workspace_fd}/.','/workspace']]
        if len(matches)!=1:raise PermissionError('Expected one metadata-only lower mount')
        command[matches[0]+1]=f'/proc/self/fd/{self.transaction.inspection_fd}'
        target='/workspace/'+('.git' if self.repository=='.' else self.repository+'/.git')
        os.lseek(self.history.mount.config,0,os.SEEK_SET)
        return command+['--bind',str(self.history.private),target,'--ro-bind-data',str(self.history.mount.config),target+'/config']


class _QuarantineMount(_MetadataMount):
    def __init__(self, transaction, history, source_fd, output_fd,repository='.'):
        super().__init__(transaction, history,repository)
        self.source_fd, self.output_fd = source_fd, output_fd

    @property
    def launch_fds(self):
        return (*super().launch_fds, self.source_fd, self.output_fd)

    def wrap_command(self, command):
        return super().wrap_command(command) + [
            '--ro-bind', f'/proc/self/fd/{self.source_fd}', '/in/pack',
            '--bind', f'/proc/self/fd/{self.output_fd}', '/out']


class _CanonicalMount(_PullMount):
    """Pin the exact selected canonical lower, never a path-following bind."""
    def __init__(self,transaction,history,repository='.'):
        super().__init__(transaction,history,repository)
        from agentporter.git_remote_policy import selected_repository
        self._selection=selected_repository(transaction.workspace,repository)
        self.selected,self.root_fd,_=self._selection.__enter__()
        if (os.fstat(self.root_fd).st_dev,os.fstat(self.root_fd).st_ino)!=(
                os.fstat(history.mount.root).st_dev,os.fstat(history.mount.root).st_ino):
            self.close();raise PermissionError('Selected canonical repository changed')

    def close(self):self._selection.__exit__(None,None,None)

    @property
    def launch_fds(self):
        return (*super().launch_fds,self.root_fd,self.history.mount.git)

    def wrap_command(self, command):
        transaction,history=self.transaction,self.history
        transaction._check_root_identity()
        command=list(command)
        matches=[i for i in range(len(command)-2)
                 if command[i:i+3]==['--ro-bind',f'/proc/self/fd/{self.sandbox_workspace_fd}/.','/workspace']]
        if len(matches)!=1 or '--' in command:raise PermissionError('Expected one read-only pull baseline mount')
        command[matches[0]+1]=f'/proc/self/fd/{self.root_fd}'
        fd=history.mount.config;os.lseek(fd,0,os.SEEK_SET)
        command += ['--ro-bind',f'/proc/self/fd/{history.mount.git}','/workspace/.git',
                    '--ro-bind-data',str(fd),'/workspace/.git/config']
        prefix='' if self.repository=='.' else self.repository+'/'
        for relative,directory in transaction.masks:
            if not relative.startswith(prefix):continue
            destination='/workspace/'+relative[len(prefix):]
            command += (['--tmpfs',destination,'--remount-ro',destination] if directory
                        else ['--ro-bind','/dev/null',destination])
        return command


class ApprovedGitPulls:
    """Unwired trusted pull backend; only the coherent coordinator can publish."""
    def __init__(self, registry, sandbox, authority, manager):
        self.registry, self.sandbox, self.authority, self.manager = registry, sandbox, authority, manager
        self.verifier = authority.verifier
        self.requires_receipt=getattr(authority,'requires_receipt',True)
        self.engine = PrivateGitPullIntegration(sandbox)
        self._require_runtime()

    def _require_runtime(self):
        if (self.sandbox.transactional_writes is not True or self.sandbox.resources is None
                or self.manager.resources is not self.sandbox.resources
                or Path(self.manager.state_dir).resolve() != Path(self.sandbox.state_dir).resolve()):
            raise PermissionError('Approved pull requires shared supervised runtime and admission')

    def _transaction(self, workspace_id):
        workspace = self.registry.get(workspace_id)
        if not workspace.allow_git or not workspace.writable:
            raise PermissionError('Workspace policy does not allow pull')
        return WorkspaceTransaction(Path(workspace.path),
            Path(self.sandbox.state_dir) / 'workspace-transactions', git_sandbox=self.sandbox)

    def _run(self, transaction, argv, *, mount=None, output=8192, timeout=90,repository='.'):
        history = _history(transaction,repository)
        if repository!='.' and not isinstance(mount,_CanonicalMount):
            target='/workspace/'+repository
            argv=list(argv)
            for index in (4,6):
                if index<len(argv) and argv[index] in {_INDEX,_TRACK,_INSPECT,_UPDATE}:
                    argv[index]='import os; os.chdir('+repr(target)+')\n'+argv[index].replace('/workspace',target)
        return self.sandbox._run_command(workspace_path=str(transaction.workspace),
            argv=argv, writable=False, git_metadata_writable=False, network_access=False,
            workspace_transaction=mount or _MetadataMount(transaction, history,repository), require_resources=True,
            timeout_seconds=timeout, max_output_bytes=output)

    def _import_pack(self, transaction, request, pack):
        """Strict index/connectivity in quarantine, promotion only to private .git."""
        repository=_relative(request)
        history = _history(transaction,repository)
        acquisition = Path(tempfile.mkdtemp(prefix='pull-acquisition-', dir=transaction.directory))
        source = acquisition / 'input.pack'
        with open(source, 'xb') as stream:
            os.chmod(source, 0o400)
            stream.write(pack)
            stream.flush()
            os.fsync(stream.fileno())
        output = acquisition / 'quarantine'
        output.mkdir(mode=0o700)
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            result = self._run(transaction,
                ['/usr/bin/python3', '-I', '-S', '-c', _INDEX,
                 request.canonical_payload.decode(), _INSPECT, request.to_payload()['parameters']['remote_oid']],
                mount=_QuarantineMount(transaction, history, source_fd, output_fd,repository),repository=repository)
        finally:
            os.close(source_fd)
            os.close(output_fd)
        pack_hash = result['stdout'].strip()
        width = len(request.to_payload()['parameters']['remote_oid'])
        if result['exit_code'] or len(pack_hash) != width or any(c not in '0123456789abcdef' for c in pack_hash):
            raise PermissionError('Pull quarantine graph validation failed')
        metadata = os.open(history.private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _promote_quarantine(metadata, output, pack_hash)
        finally:
            os.close(metadata)

    def _canonical_state(self, transaction,repository='.'):
        history=_history(transaction,repository)
        mount=_CanonicalMount(transaction,history,repository)
        try:
            result=self._run(transaction,
                ['/usr/bin/python3','-I','-S','-c',_PROGRAM,
                 json.dumps({'action':'inspect','private_metadata_identity':[os.fstat(history.mount.git).st_dev,os.fstat(history.mount.git).st_ino],'masked':[p if repository=='.' else p[len(repository)+1:]
                    for p,_ in transaction.masks if repository=='.' or p.startswith(repository+'/')]})],
                mount=mount,output=65536,repository=repository)
        finally:mount.close()
        if result['exit_code']:raise PermissionError('Cannot inspect canonical pull baseline')
        return json.loads(result['stdout'])

    def _assert_canonical(self, transaction, request):
        if self._canonical_state(transaction,_relative(request)) != request.to_payload()['parameters']['canonical_state']:
            raise PermissionError('Canonical owner state changed during pull')

    def _proposal(self, transaction, workspace_id, remote_id, ref, mode, grant, broker,*,operation='pull'):
        if not isinstance(mode, str) or mode not in _MODES:
            raise ValueError('Invalid exact pull mode')
        repository=grant.repository_relative
        history=_history(transaction,repository)
        state = self.engine.inspect(transaction,repository=repository)
        canonical = self._canonical_state(transaction,repository)
        if state['branch'] is None or state['unmerged']:
            raise PermissionError('Pull preparation requires a resolved local branch')
        tracking = _validate_tracking_ref(remote_id, ref)
        advertisement = broker.discover('git-upload-pack')
        remote_oid = advertisement.refs.get(ref)
        width = 40 if state['object_format'] == 'sha1' else 64
        if (advertisement.object_format != state['object_format']
                or not isinstance(remote_oid, str) or len(remote_oid) != width
                or any(c not in '0123456789abcdef' for c in remote_oid) or remote_oid == '0' * width):
            raise PermissionError('Remote pull branch is absent or uses another object format')
        observed = self._run(transaction,
            ['/usr/bin/python3', '-I', '-S', '-c', _TRACK, tracking, str(width)], output=1024,repository=repository)
        old_oid = observed['stdout'].strip()
        if observed['exit_code'] or len(old_oid) != width or any(c not in '0123456789abcdef' for c in old_oid):
            raise PermissionError('Cannot inspect exact private tracking baseline')
        pack = broker.fetch_pack(ref, remote_oid)
        if not isinstance(pack, bytes) or not 1 <= len(pack) <= _MAX_PACK:
            raise PermissionError('Pull pack exceeds protected acquisition bound')
        validate_pack(pack, state['object_format'])
        root = os.fstat(transaction.inspection_fd)
        metadata = os.fstat(history.mount.git)
        selected=os.fstat(history.mount.root)
        parameters = {'remote_id': remote_id, 'remote_url': grant.repository.url,
            'remote_ref': ref, 'remote_oid': remote_oid, 'object_format': state['object_format'],
            'tracking_ref': tracking, 'old_oid': old_oid, 'new_oid': remote_oid,
            'pack_sha256': hashlib.sha256(pack).hexdigest(), 'pack_size': len(pack),
            'policy_sha256': self.authority.policy_sha256, 'mode': mode,
            'metadata_device': metadata.st_dev, 'metadata_inode': metadata.st_ino,
            'private_state': state, 'canonical_state': canonical}
        if repository!='.':
            parameters.update(repository_relative=repository,workspace_identity={
                'path':str(transaction.workspace),'device':root.st_dev,'inode':root.st_ino})
        if operation not in {'pull','fetch'}:raise PermissionError('Unknown protected acquisition operation')
        request = GitApprovalRequest.from_payload({'operation': operation, 'workspace_id': workspace_id,
            'repository_path': str(transaction.workspace/repository), 'repository_device': selected.st_dev,
            'repository_inode': selected.st_ino, 'expected_head': state['head'],
            'expected_tree': state['tree'], 'branch': state['branch'], 'parameters': parameters})
        self._import_pack(transaction, request, pack)
        if self.engine.inspect(transaction,repository=repository) != state:
            raise PermissionError('Private pull baseline changed during acquisition')
        self._assert_canonical(transaction, request)
        return request

    def prepare(self, workspace_id, remote_id, ref, mode='ff-only'):
        self._require_runtime()
        with synchronous_slot(self.manager):
            grant, broker = self.authority.authorize(workspace_id, remote_id, ref, 'pull')
            transaction = self._transaction(workspace_id)
            try:
                return self._proposal(transaction, workspace_id, remote_id, ref, mode, grant, broker)
            finally:
                transaction.close()

    def pull(self, workspace_id, remote_id, ref, receipt='', mode='ff-only'):
        self._require_runtime()
        with execution_slot(self.manager) as token:
            transaction = None
            guarded = False
            consumed = False
            try:
                grant, broker = self.authority.authorize(workspace_id, remote_id, ref, 'pull')
                transaction = self._transaction(workspace_id)
                request = self._proposal(transaction, workspace_id, remote_id, ref, mode, grant, broker)
                self._assert_canonical(transaction, request)
                _write_private(transaction.directory / 'pull-approved-request.json', {
                    'version': 1, 'request': request.to_payload(), 'request_sha256': request.digest,
                    'approval_receipt': receipt, 'admission_token': token})
                _sync(transaction.directory)
                from agentporter.git_authorizations import claim
                approval = claim(self.authority,request,receipt)
                consumed = True
                # Once claimed, retain the private evidence even if the first
                # guard write fails. Never restore or silently retry the nonce.
                transaction._retain_directory = True
                transaction._private_pull_pending = True
                authorization = _consumed_tracking(request, approval, self.verifier, self.authority, receipt)
                transaction._approved_pull_intents = (authorization,)
                guard = Path(self.sandbox.state_dir) / 'workspace-transactions' / (
                    workspace_key(os.fstat(transaction.inspection_fd)) + '.git-pending.json')
                _write_fetch_guard(guard, {'version': 1, 'kind': 'private-pull-candidate',
                    'request': request.to_payload(), 'request_sha256': request.digest,
                    'approval_nonce': approval.nonce, 'admission_token': token,
                    'candidate_directory': str(transaction.directory),
                    'tracking_authorization': authorization.to_payload(), 'canonical_published': False})
                guarded = True
                bind(self.manager, token, request.digest, guard)
                current_grant, _ = self.authority.authorize(workspace_id, remote_id, ref, 'pull')
                parameters = request.to_payload()['parameters']
                if (current_grant.repository.url != parameters['remote_url']
                        or self.authority.policy_sha256 != parameters['policy_sha256']):
                    raise PermissionError('Pull authority changed after approval consumption')
                result = self.engine.run(transaction, parameters['remote_oid'], mode,
                                         expected=parameters['private_state'],repository=_relative(request))
                self._assert_canonical(transaction, request)
                _attach_publication_intent(self, transaction, authorization, request, token, guard, result)
                _write_private(transaction.directory / 'pull-private-result.json', {
                    'version': 1, 'request_sha256': request.digest, 'approval_nonce': approval.nonce,
                    'admission_token': token, 'tracking_authorization': authorization.to_payload(),
                    'canonical_published': False, 'result': result})
                _sync(transaction.directory)
                _sync(guard.parent)
                if result['status'] == 'integrated':
                    transaction.publish_approved_pull()
                    return {'operation': 'pull', 'status': 'published',
                        'candidate_status': 'integrated', 'canonical_published': True,
                        'request_sha256': request.digest, 'guard_retained': False,
                        'head': result['after']['head'], 'tracking_ref': parameters['tracking_ref'],
                        'remote_oid': parameters['remote_oid'],
                        'receipt': str(transaction.directory / 'publication-receipt.json'),
                        'candidate_directory': str(transaction.directory)}
                return {'operation': 'pull', 'status': 'recovery_required',
                    'candidate_status': result['status'], 'canonical_published': False,
                    'request_sha256': request.digest, 'guard': str(guard),
                    'candidate_directory': str(transaction.directory)}
            except BaseException as error:
                if guarded or consumed:
                    raise ResourceCleanupError('Private approved pull requires owner reconciliation; '
                                               'consumed approval and candidate retained') from error
                resolve(self.manager, token)
                raise
            finally:
                if transaction is not None:
                    transaction.close()


class JobBoundGitPulls:
    operation='pull'
    """Trusted job adapter; reuse the live transaction and asynchronous admission.

    This is an internal building block, not an RPC handler. A future worker
    route must authenticate the live peer and agent capabilities before making
    this object available. Current execution blocks ordinary finalization and
    leaves an owner-reconciliation guard; it cannot publish a partial pull.
    """
    def __init__(self, backend, job_id, workspace_id, agent, *, repository=None):
        self.backend = backend
        self.job_id, self.workspace_id, self.agent = job_id, workspace_id, agent
        self.repository=repository
        self.transaction = None
        self.token = None
        self._context()

    def _context(self):
        service = self.backend
        service._require_runtime()
        with service.manager.lock:
            transaction = service.manager._job_transactions.get(self.job_id)
        database = service.manager._get_db()
        try:
            row = database.execute('SELECT workspace_id,agent,argv,status FROM jobs WHERE job_id=?',
                                   (self.job_id,)).fetchone()
            admissions = database.execute('SELECT token FROM job_admissions WHERE job_id=?',
                                          (self.job_id,)).fetchall()
        finally:
            database.close()
        if (row is None or row['workspace_id'] != self.workspace_id or row['agent'] != self.agent
                or row['status'] != 'running'
                or json.loads(row['argv']) != ['confined-development-worker', self.agent]
                or len(admissions) != 1 or transaction is None
                or not isinstance(transaction, WorkspaceTransaction)
                or transaction._closed or transaction._applied
                or Path(service.registry.get(self.workspace_id).path).resolve() != transaction.workspace):
            raise PermissionError('Pull requires the exact live worker job and transaction')
        token = admissions[0]['token']
        if self.transaction is not None and (transaction is not self.transaction or token != self.token):
            raise PermissionError('Pull worker transaction or admission identity changed')
        self.transaction, self.token = transaction, token
        transaction._check_root_identity()
        return transaction

    def _proposal(self, remote_id, ref, mode):
        transaction = self._context()
        grant, broker = self.backend.authority.authorize(self.workspace_id, remote_id, ref, self.operation,repository=self.repository)
        request = self.backend._proposal(transaction, self.workspace_id, remote_id, ref, mode, grant, broker,operation=self.operation)
        payload = request.to_payload()
        identity = transaction.directory.stat()
        payload['parameters']['job_context'] = {
            'job_id': self.job_id, 'agent': self.agent, 'admission_token': self.token,
            'transaction_directory': str(transaction.directory),
            'transaction_device': identity.st_dev, 'transaction_inode': identity.st_ino}
        self._context()
        return GitApprovalRequest.from_payload(payload)

    def prepare(self, remote_id, ref, mode='ff-only'):
        transaction = self._context()
        with transaction._lifecycle_lock:
            self._context()
            return self._proposal(remote_id, ref, mode)

    def pull(self, remote_id, ref, receipt='', mode='ff-only'):
        transaction = self._context()
        with transaction._lifecycle_lock:
            self._context()
            return self._pull_locked(remote_id, ref, receipt, mode)

    def _pull_locked(self, remote_id, ref, receipt, mode):
        transaction = self._context()
        if getattr(type(transaction), '_private_pull_guard_supported', False) is not True:
            raise PermissionError('Job pull integration requires the coherent-publication blocker')
        if getattr(transaction, '_private_pull_pending', False):
            raise PermissionError('Job already has an unresolved private pull intent')
        request = self._proposal(remote_id, ref, mode)
        self.backend._assert_canonical(transaction, request)
        self._context()
        consumed = False
        intent_directory = Path(tempfile.mkdtemp(prefix='pull-intent-', dir=transaction.directory))
        _write_private(intent_directory / 'approved-request.json', {
            'version': 1, 'request': request.to_payload(), 'request_sha256': request.digest,
            'approval_receipt': receipt, 'admission_token': self.token,
            'job_id': self.job_id, 'agent': self.agent})
        _sync(intent_directory)
        _sync(transaction.directory)
        # Prevent ordinary finalization while signature verification/claiming is
        # in flight. On a refused receipt this transient marker is removed.
        transaction._private_pull_pending = True
        try:
            from agentporter.git_authorizations import claim
            approval = claim(self.backend.authority,request,receipt)
            consumed = True
            transaction._retain_directory = True
            authorization = _consumed_tracking(request, approval, self.backend.verifier, self.backend.authority, receipt)
            transaction._approved_pull_intents = (*getattr(transaction, '_approved_pull_intents', ()), authorization)
            guard = Path(self.backend.sandbox.state_dir) / 'workspace-transactions' / (
                workspace_key(os.fstat(transaction.inspection_fd)) + '.git-pending.json')
            _write_fetch_guard(guard, {'version': 1, 'kind': 'private-job-fetch-candidate' if self.operation=='fetch' else 'private-job-pull-candidate',
                'request': request.to_payload(), 'request_sha256': request.digest,
                'approval_nonce': approval.nonce, 'admission_token': self.token,
                'job_id': self.job_id, 'agent': self.agent,
                'intent_directory': str(intent_directory),
                'candidate_directory': str(transaction.directory),
                'tracking_authorization': authorization.to_payload(), 'canonical_published': False})
            database = self.backend.manager._get_db()
            try:
                with database:
                    database.execute('BEGIN IMMEDIATE')
                    owned = database.execute('SELECT job_id FROM job_admissions WHERE token=?',
                                             (self.token,)).fetchone()
                    if owned is None or owned['job_id'] != self.job_id:
                        raise PermissionError('Pull lost its exact asynchronous admission')
                    database.execute('INSERT INTO git_admissions VALUES (?,?,?,?)',
                        (self.token, request.digest, str(guard), 'active'))
            finally:
                database.close()
            self._context()
            parameters = request.to_payload()['parameters']
            current_grant, _ = self.backend.authority.authorize(self.workspace_id, remote_id, ref, self.operation,repository=self.repository)
            if (current_grant.repository.url != parameters['remote_url']
                    or self.backend.authority.policy_sha256 != parameters['policy_sha256']):
                raise PermissionError('Worker pull authority changed after consumption')
            if self.operation=='fetch':
                # Acquisition above imports validated objects only into private
                # metadata. Finalization applies solely the exact tracking CAS.
                after=self.backend.engine.inspect(transaction,repository=_relative(request))
                if after!=parameters['private_state']:raise PermissionError('Fetch private worktree/local branch changed during acquisition')
                update=self.backend._run(transaction,['/usr/bin/python3','-I','-S','-c',_UPDATE,
                    request.canonical_payload.decode(),_INSPECT],output=1024,timeout=30,repository=_relative(request))
                if update['exit_code'] or update['stdout'].strip()!=parameters['remote_oid']:
                    raise PermissionError('Private fetch tracking transition refused')
                result={'status':'integrated','after':after,'tracking_only':True}
            else:
                result = self.backend.engine.run(transaction, parameters['remote_oid'], mode,
                                                  expected=parameters['private_state'],repository=_relative(request))
            self._context()
            self.backend._assert_canonical(transaction, request)
            _attach_publication_intent(self.backend, transaction, authorization, request, self.token, guard, result)
            _write_private(transaction.directory / 'pull-private-result.json', {
                'version': 1, 'request_sha256': request.digest, 'approval_nonce': approval.nonce,
                'admission_token': self.token, 'job_id': self.job_id, 'agent': self.agent,
                'tracking_authorization': authorization.to_payload(),
                'canonical_published': False, 'result': result})
            _sync(transaction.directory)
            _sync(guard.parent)
            return {'operation': self.operation, 'status': 'recovery_required',
                'candidate_status': 'fetched' if self.operation=='fetch' else result['status'], 'canonical_published': False,
                'request_sha256': request.digest, 'guard': str(guard),
                'job_id': self.job_id, 'candidate_directory': str(transaction.directory)}
        except BaseException as error:
            if consumed:
                raise ResourceCleanupError('Private job pull requires owner reconciliation; '
                                           'consumed approval, transaction and admission retained') from error
            transaction._private_pull_pending = False
            raise


def validate_pull_authorization(document, *, registry, state_dir, owner_config_dir):
    """Read-only proof of one spent pull's exact protected ref and log path.

    owner_config_dir is mandatory trusted caller context, never taken from the
    guard. Recovery may validate an expired signature only after checking its
    actual consumed ledger row. No nonce is consumed/restored and no remote is
    contacted here. Returns an immutable pair of exact paths, never a pattern.
    """
    from agentporter.git_remote_policy import load_owner_git_remotes
    try:
        fields = {'version', 'request', 'request_sha256', 'approval_receipt', 'approval_nonce',
                  'verification_context', 'tracking'}
        local=isinstance(document,dict) and document.get('version')==2 and document.get('authorization_mode')=='workspace'
        if local:fields=fields|{'authorization_mode'}
        if (not isinstance(document, dict) or set(document) != fields
                or type(document['version']) is not int or document['version'] != (2 if local else 1)):
            raise ValueError('authorization schema')
        context = document['verification_context']
        context_fields = {'owner_config_dir', 'policy_sha256', 'ledger_path', 'ledger_device',
            'ledger_inode', 'ledger_parent_device', 'ledger_parent_inode', 'verification_key'}
        if not isinstance(context, dict) or set(context) != context_fields:
            raise ValueError('verification context')
        protected_config = Path(owner_config_dir).resolve(strict=True)
        if context['owner_config_dir'] != str(protected_config):
            raise ValueError('protected owner policy root')
        authority = load_owner_git_remotes(protected_config, registry, state_dir)
        if authority is None:
            raise ValueError('missing protected owner pull authority')
        verifier = authority.verifier
        policy_digest=context['policy_sha256']
        if not authority.accepts_policy_sha256(policy_digest,legacy=not local):raise ValueError('policy digest changed')
        expected_context = {'owner_config_dir': str(protected_config),
            'policy_sha256': policy_digest, 'ledger_path': str(verifier.ledger_path),
            'ledger_device': verifier._ledger_identity[0], 'ledger_inode': verifier._ledger_identity[1],
            'ledger_parent_device': verifier._parent_identity[0],
            'ledger_parent_inode': verifier._parent_identity[1],
            'verification_key': verifier.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
        if context != expected_context:
            raise ValueError('protected approval context changed')
        request = GitApprovalRequest.from_payload(document['request'])
        payload, parameters = request.to_payload(), request.to_payload()['parameters']
        required_parameters = {'remote_id', 'remote_url', 'remote_ref', 'remote_oid', 'object_format',
            'tracking_ref', 'old_oid', 'new_oid', 'pack_sha256', 'pack_size', 'policy_sha256', 'mode',
            'metadata_device', 'metadata_inode', 'private_state', 'canonical_state'}
        if (payload['operation'] not in ({'pull','fetch'} if local else {'pull'}) or document['request_sha256'] != request.digest
                or set(parameters) not in (required_parameters, required_parameters | {'job_context'},
                    required_parameters|{'repository_relative','workspace_identity'},
                    required_parameters|{'repository_relative','workspace_identity','job_context'})
                or parameters['mode'] not in _MODES or parameters['policy_sha256'] != policy_digest):
            raise ValueError('exact signed pull request')
        tracking_ref = _validate_tracking_ref(parameters['remote_id'], parameters['remote_ref'])
        width = 40 if parameters['object_format'] == 'sha1' else 64 if parameters['object_format'] == 'sha256' else 0
        if not width:
            raise ValueError('object format')
        for name in ('remote_oid', 'old_oid', 'new_oid'):
            if not isinstance(parameters[name], str) or not re.fullmatch('[0-9a-f]{%d}' % width, parameters[name]):
                raise ValueError('tracking object format')
        if (parameters['new_oid'] != parameters['remote_oid'] or parameters['new_oid'] == '0' * width
                or parameters['tracking_ref'] != tracking_ref or len(payload['expected_tree']) != width
                or not re.fullmatch('[0-9a-f]{64}', parameters['pack_sha256'])
                or type(parameters['pack_size']) is not int or not 1 <= parameters['pack_size'] <= _MAX_PACK):
            raise ValueError('exact tracking intent')
        expected_tracking = {key: payload[key] for key in ('repository_device', 'repository_inode')}
        expected_tracking.update({key: parameters[key] for key in ('metadata_device', 'metadata_inode',
            'tracking_ref', 'old_oid', 'new_oid', 'pack_sha256', 'policy_sha256', 'mode')})
        if document['tracking'] != expected_tracking:
            raise ValueError('redundant tracking scope differs from signature')
        from agentporter.git_remote_policy import selected_repository
        root=Path(registry.get(payload['workspace_id']).path).resolve(strict=True)
        root_info=root.stat()
        grant,_=authority.authorize(payload['workspace_id'],parameters['remote_id'],parameters['remote_ref'],payload['operation'],repository=parameters.get('repository_relative','.'))
        relative=grant.repository_relative
        if relative!='.':
            if (parameters.get('repository_relative')!=relative or parameters.get('workspace_identity')!={
                    'path':str(root),'device':root_info.st_dev,'inode':root_info.st_ino}):
                raise ValueError('parent workspace binding changed')
        elif 'repository_relative' in parameters or 'workspace_identity' in parameters:
            raise ValueError('unexpected nested repository binding')
        with selected_repository(root,relative) as (selected,descriptor,_):
            info=os.fstat(descriptor)
            if str(selected)!=payload['repository_path'] or (info.st_dev,info.st_ino)!=(payload['repository_device'],payload['repository_inode']):
                raise ValueError('selected repository identity changed')
            metadata=os.open('.git',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            try:metadata_info=os.fstat(metadata)
            finally:os.close(metadata)
        if (metadata_info.st_dev,metadata_info.st_ino)!=(parameters['metadata_device'],parameters['metadata_inode']):
            raise ValueError('Git metadata identity changed')
        if grant.repository.url!=parameters['remote_url']:
            raise ValueError('protected remote scope changed')
        receipt = document['approval_receipt']
        if local:
            if receipt!='':raise ValueError('Workspace claim cannot contain an external receipt')
            from agentporter.git_authorizations import assert_claim
            assert_claim(authority,request,document['approval_nonce'])
            return tracking_ref,'logs/'+tracking_ref
        if not isinstance(receipt, str) or not receipt.isascii() or len(receipt) > 8192:
            raise ValueError('approval receipt encoding')
        envelope = _decode(receipt)
        if not isinstance(envelope, dict) or set(envelope) != {'claims', 'signature'}:
            raise ValueError('approval envelope')
        claims, encoded = envelope['claims'], envelope['signature']
        if (not isinstance(claims, dict) or set(claims) != {'version', 'audience', 'nonce', 'issued_at', 'expires_at', 'request_sha256'}
                or type(claims['version']) is not int or claims['version'] != 1
                or claims['audience'] != _AUDIENCE or claims['request_sha256'] != request.digest
                or claims['nonce'] != document['approval_nonce']
                or not isinstance(claims['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', claims['nonce'])
                or type(claims['issued_at']) is not int or type(claims['expires_at']) is not int
                or claims['issued_at'] < 0 or not 1 <= claims['expires_at'] - claims['issued_at'] <= 300
                or not isinstance(encoded, str) or not re.fullmatch('[A-Za-z0-9_-]{86}', encoded)):
            raise ValueError('approval claims')
        signature = base64.urlsafe_b64decode(encoded + '==')
        if base64.urlsafe_b64encode(signature).rstrip(b'=').decode() != encoded:
            raise ValueError('approval signature encoding')
        verifier.public_key.verify(signature, _APPROVAL_DOMAIN + _canonical(claims))
        verifier.assert_consumed(document['approval_nonce'], request)
        return tracking_ref, 'logs/' + tracking_ref
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature) as error:
        raise PermissionError('Pull authorization does not prove one exact consumed protected tracking update') from error


@dataclass(frozen=True)
class _PullPublicationIntent:
    """Host-only ownership of one exact candidate, original guard and admission."""
    backend: object
    transaction: object
    authorization: _ConsumedTrackingAuthorization
    request: GitApprovalRequest
    admission_token: str
    guard: Path
    guard_record: dict
    expected_private: bytes

    def to_payload(self):
        payload={'authorization': self.authorization.to_payload(),
            'consumed_guard_record': self.guard_record,
            'consumed_guard_custody': str(Path(self.backend.sandbox.state_dir) / 'pull-guard-custody' / self.transaction.directory.name),
            'admission_token': self.admission_token,
            'candidate_directory': str(self.transaction.directory)}
        if _relative(self.request)!='.':payload['workspace_guard_path']=str(self.guard)
        return payload

    def validate(self, *, migrated=False):
        from agentporter.sandbox.workspace_delta import _read_deletion_file
        from agentporter.sandbox.workspace_custody import inspect_custody
        service, transaction = self.backend, self.transaction
        service._require_runtime()
        transaction._check_root_identity()
        if (getattr(transaction, '_pull_publication_intent', None) is not self
                or getattr(transaction, '_approved_pull_intents', ()) != (self.authorization,)):
            raise PermissionError('Pull publication lost its native consumed authorization instance')
        paths = validate_pull_authorization(self.authorization.to_payload(), registry=service.registry,
            state_dir=service.sandbox.state_dir, owner_config_dir=service.authority._config_dir)
        database = service.manager._get_db()
        try:
            admission = database.execute('SELECT job_id FROM job_admissions WHERE token=?',
                                         (self.admission_token,)).fetchone()
            binding = database.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',
                                       (self.admission_token,)).fetchone()
        finally:
            database.close()
        job_context = self.request.to_payload()['parameters'].get('job_context')
        expected_job = job_context['job_id'] if job_context else None
        if (admission is None or admission['job_id'] != expected_job or binding is None
                or tuple(binding) != (self.request.digest, str(self.guard), 'active')):
            raise PermissionError('Pull publication admission does not match consumed request')
        if migrated:
            observed = inspect_custody(self.guard.parent, Path(self.to_payload()['consumed_guard_custody']))
            if not observed['expected'] or observed['state'] not in {'captured_expected', 'captured_conflict'}:
                raise PermissionError('Consumed pull guard custody is not exact')
        else:
            descriptor = os.open(self.guard, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                raw, _, _ = _read_deletion_file(descriptor,
                    expected_signature=self.guard_record['signature'], expected_sha256=self.guard_record['sha256'])
            finally:
                os.close(descriptor)
            document = json.loads(raw)
            if (document.get('tracking_authorization') != self.authorization.to_payload()
                    or document.get('request_sha256') != self.request.digest
                    or document.get('admission_token') != self.admission_token
                    or document.get('candidate_directory') != str(transaction.directory)):
                raise PermissionError('Consumed pull guard does not bind native publication intent')
        return paths

    def prepare(self):
        """Quiescent finalizer only: verify final candidate then exact private ref CAS."""
        self.validate()
        service, transaction = self.backend, self.transaction
        observed = service.engine.inspect(transaction,repository=_relative(self.request))
        expected = _decode(self.expected_private)
        job_context = self.request.to_payload()['parameters'].get('job_context')
        if job_context:
            # A writable worker may continue ordinary edits and authorized local
            # Git operations after integration. Inspect that quiescent final
            # candidate afresh; the canonical baseline, spent authorization and
            # exact protected tracking old/new CAS remain independently bound.
            if observed['unmerged'] or observed['object_format'] != expected['object_format']:
                raise PermissionError('Worker pull final candidate is unresolved or has another object format')
            if any(observed[field] != expected[field] for field in ('head', 'branch')):
                raise PermissionError('Approved inbound Git does not authorize a subsequent worker commit or checkout')
        elif _canonical(observed) != self.expected_private:
            raise PermissionError('Private pull candidate changed before final publication')
        service._assert_canonical(transaction, self.request)
        after = observed
        payload = self.request.to_payload()
        update = GitApprovalRequest.from_payload({**payload,
            'expected_head': after['head'], 'expected_tree': after['tree'], 'branch': after['branch']})
        from agentporter.git_fetches import _UPDATE
        if payload['operation']=='fetch':
            tracking=service._run(transaction,['/usr/bin/python3','-I','-S','-c',_TRACK,
                self.authorization.tracking_ref,str(len(self.authorization.new_oid))],output=1024,repository=_relative(self.request))
            if tracking['exit_code'] or tracking['stdout'].strip()!=self.authorization.new_oid:
                raise PermissionError('Private fetched tracking ref changed before publication')
        else:
            result = service._run(transaction, ['/usr/bin/python3', '-I', '-S', '-c', _UPDATE,
                update.canonical_payload.decode(), _INSPECT], output=1024, timeout=30,repository=_relative(self.request))
            if result['exit_code'] or result['stdout'].strip() != self.authorization.new_oid:
                raise PermissionError('Exact private pull tracking transition was refused')
        history = _history(transaction,_relative(self.request))
        history.attach_approved_pull(self)

    def resolve_after_publication(self):
        """Called after ordinary+Git receipt and both guard endpoints are durable."""
        self.validate(migrated=True)
        database = self.backend.manager._get_db()
        try:
            with database:
                changed = database.execute("UPDATE git_admissions SET status='resolved' WHERE token=? AND request_sha256=? AND guard_path=? AND status='active'",
                    (self.admission_token, self.request.digest, str(self.guard)))
                if changed.rowcount != 1:
                    raise PermissionError('Pull publication admission resolution raced')
                if 'job_context' not in self.request.to_payload()['parameters']:
                    database.execute('DELETE FROM job_admissions WHERE token=? AND job_id IS NULL', (self.admission_token,))
        finally:
            database.close()


def _attach_publication_intent(backend, transaction, authorization, request, token, guard, result):
    if result['status'] != 'integrated':
        return
    from agentporter.sandbox.recovery_guards import _guard_record
    from agentporter.sandbox.workspace_delta import backup_workspace_deletion
    custody_parent = Path(backend.sandbox.state_dir) / 'pull-guard-custody'
    custody_parent.mkdir(mode=0o700, exist_ok=True)
    record = _guard_record(guard)
    backup = backup_workspace_deletion(guard.parent, guard.name,
        transaction.directory / 'pull-consumed-guard.backup', expected_signature=record['signature'])
    if any(backup.get(key) != value for key, value in record.items()):
        raise PermissionError('Consumed pull guard changed before publication attachment')
    intent = _PullPublicationIntent(backend, transaction, authorization, request, token, guard,
                                    record, _canonical(result['after']))
    transaction._pull_publication_intent = intent
    intent.validate()


class JobBoundGitFetch(JobBoundGitPulls):
    """Tracking-only acquisition inside the original admitted job transaction."""
    operation='fetch'

    def prepare(self,remote_id,ref):
        return super().prepare(remote_id,ref,'ff-only')

    def fetch(self,remote_id,ref,receipt=''):
        if getattr(self.backend.authority,'requires_receipt',True):
            raise PermissionError('Job fetch requires workspace authorization')
        return super().pull(remote_id,ref,receipt,'ff-only')
