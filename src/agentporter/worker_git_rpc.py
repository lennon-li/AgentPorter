"""Trusted service-side Git pull RPC for delegated workers.

Server-side contract and adapter only; it opens no listener and enables
nothing by being imported. The parent transport must call
``WorkerGitRPC.channel(job_id)`` for the per-job channel it created, then pass
each raw frame to ``WorkerGitChannel.handle``. The job identity comes from the
channel and the service-issued grant, never from request fields.

The worker may only name an exact workspace/repository/remote ID/full ref/mode
(the service prepares and binds the exact request internally for execution). URL, credentials, signing authority, argv,
backend and grants are never accepted from a worker. Prepared requests must
carry the canonical parameters ``mode``, ``remote_id`` and ``remote_ref``. Push is denied
unconditionally. The injected backend owns the single workspace mutation
transaction/lease; this adapter never takes or nests a mutation lease.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import struct
import threading
import time
from pathlib import PurePosixPath
from typing import Callable

from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.git_approvals import GitApprovalRequest
from agentporter.git_smart_http import _ref

VERSION = 1
MODES = frozenset({'ff-only', 'merge', 'rebase'})
CAPABILITIES = frozenset({'read', 'write'})
MAX_FRAME = 65536
MAX_RECEIPT = 8192
MAX_OUTCOME = 262144
PREPARED_TTL = 300
MAX_PREPARED_PER_JOB = 32
MAX_PREPARED_TOTAL = 1024
_JOB = re.compile(r'job_[0-9a-f]{24}\Z')
_REMOTE = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_REPO = re.compile(r'[A-Za-z0-9._/-]{1,256}\Z')
_COMMON = {'version', 'op', 'job_id', 'agent', 'workspace_id', 'repository', 'remote', 'ref', 'mode'}
_CLONE_COMMON=(_COMMON-{'mode'})|{'branch'}
_FETCH_COMMON=_COMMON-{'mode'}
_FIELDS = {'prepare': _COMMON, 'pull': _COMMON | {'request_sha256', 'approval_receipt'},
           'wait': _COMMON | {'request_sha256'},'clone_prepare':_CLONE_COMMON,
           'clone':_CLONE_COMMON|{'request_sha256','approval_receipt'},'wait_clone':_CLONE_COMMON|{'request_sha256'},
           'fetch':_FETCH_COMMON}
_AUTHORITY_FIELDS = frozenset({
    'url', 'remote_url', 'credential', 'credentials', 'token', 'password', 'secret', 'key',
    'private_key', 'signing_key', 'signature', 'argv', 'command', 'cmd', 'args', 'env',
    'backend', 'grant', 'grants', 'capabilities', 'lease', 'ledger', 'allow_push', 'push',
    'force', 'transport', 'path', 'repository_path', 'config'})


class WorkerGitDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WorkerGitGrant:
    """Service-issued scope for one live job; never constructed from worker input."""
    job_id: str
    agent: str
    workspace_id: str
    repository: str
    repository_path: str
    capabilities: frozenset
    allowed: frozenset
    expires_at: int
    alternates: tuple = ()
    clone_allowed: frozenset = frozenset()
    fetch_allowed: frozenset = frozenset()

    def __post_init__(self):
        if not isinstance(self.job_id, str) or not _JOB.match(self.job_id):
            raise ValueError('Invalid job ID')
        if self.agent not in PUBLIC_AGENT_IDS:
            raise ValueError('Grant requires one named public agent')
        if not isinstance(self.workspace_id, str) or not 0 < len(self.workspace_id) <= 256 or self.workspace_id == '*':
            raise ValueError('Grant requires one workspace')
        if (not isinstance(self.repository, str) or not _REPO.match(self.repository)
                or '..' in PurePosixPath(self.repository).parts or self.repository.startswith('/')):
            raise ValueError('Invalid repository scope')
        path = self.repository_path
        if (not isinstance(path, str) or not path.startswith('/') or path == '/'
                or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path):
            raise ValueError('Grant requires a canonical absolute repository path')
        if not isinstance(self.capabilities, frozenset) or not self.capabilities <= CAPABILITIES:
            raise ValueError('Invalid capabilities')
        if (not isinstance(self.allowed,frozenset) or not isinstance(self.clone_allowed,frozenset)
                or not isinstance(self.fetch_allowed,frozenset) or not (self.allowed or self.clone_allowed or self.fetch_allowed)):
            raise ValueError('Grant requires exact remote/ref/mode entries')
        for entry in self.allowed:
            if (not isinstance(entry, tuple) or len(entry) != 3 or not isinstance(entry[0], str)
                    or not _REMOTE.match(entry[0]) or not isinstance(entry[1], str)
                    or not _ref(entry[1], branch=True) or entry[2] not in MODES):
                raise ValueError('Invalid exact remote/ref/mode entry')
        for entry in self.clone_allowed|self.fetch_allowed:
            if (not isinstance(entry,tuple) or len(entry)!=2 or not isinstance(entry[0],str)
                    or not _REMOTE.fullmatch(entry[0]) or not _ref(entry[1],branch=True)):
                raise ValueError('Invalid exact clone remote/ref entry')
        if self.clone_allowed and self.repository=='.':raise ValueError('Clone requires an exact child repository')
        if type(self.expires_at) is not int or self.expires_at <= 0:
            raise ValueError('Invalid grant expiry')
        if not isinstance(self.alternates,tuple) or len(self.alternates)>127:
            raise ValueError('Invalid server repository catalog')
        repositories={self.repository}
        for grant in self.alternates:
            if (not isinstance(grant,WorkerGitGrant) or grant.alternates
                    or any(getattr(grant,key)!=getattr(self,key) for key in ('job_id','agent','workspace_id','capabilities','expires_at'))
                    or grant.repository in repositories):raise ValueError('Inconsistent server repository catalog')
            repositories.add(grant.repository)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def _strict(raw, limit):
    if isinstance(raw, str):
        if not raw.isascii():
            raise ValueError('nonascii')
        raw = raw.encode()
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > limit:
        raise ValueError('size')
    def bad(_):
        raise ValueError('nonfinite')
    return json.loads(bytes(raw), object_pairs_hook=_unique, parse_constant=bad)


def _deny(code, **context):
    return {'version': VERSION, 'ok': False, 'status': 'denied', 'code': code, **context}


class WorkerGitRPC:
    """Admission and dispatch; the backend is trusted code supplied by the service."""

    def __init__(self, backend, is_live: Callable[[str, str, str], bool], *,
                 clock: Callable[[], float] = time.time, prepared_ttl: int = PREPARED_TTL):
        if not callable(getattr(backend, 'prepare', None)) or not callable(getattr(backend, 'pull', None)):
            raise TypeError('Backend must provide prepare(...) and pull(...)')
        if not callable(is_live):
            raise TypeError('A live-job check is required')
        if type(prepared_ttl) is not int or not 1 <= prepared_ttl <= PREPARED_TTL:
            raise ValueError('Invalid prepared-request lifetime')
        self._backend = backend
        self._is_live = is_live
        self._clock = clock
        self._ttl = prepared_ttl
        self._grants: dict[str, WorkerGitGrant] = {}
        self._selected_repositories = {}
        # digest -> record; claimed at dispatch and never reset, so uncertainty
        # cannot turn into a blind retry of the same request.
        self._prepared: dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def issue_grant(self, grant: WorkerGitGrant):
        if not isinstance(grant, WorkerGitGrant):
            raise TypeError('Grant must be service-issued')
        with self._lock:
            if grant.job_id in self._grants:
                raise ValueError('Job already has a grant')
            self._grants[grant.job_id] = grant

    def revoke(self, job_id):
        with self._lock:
            self._grants.pop(job_id, None)
            self._selected_repositories.pop(job_id,None)
            for key in [k for k in self._prepared if k[0] == job_id]:
                self._prepared[key]['event'].set()
                del self._prepared[key]

    def _registered(self,grant):
        primary=self._grants.get(grant.job_id)
        return primary is grant or (primary is not None and any(item is grant for item in primary.alternates))

    def selected_repository(self,job_id):
        with self._lock:return self._selected_repositories.get(job_id)

    def channel(self, job_id) -> 'WorkerGitChannel':
        with self._lock:
            grant = self._grants.get(job_id)
        if grant is None:
            raise PermissionError('No worker Git grant for this job')
        return WorkerGitChannel(self, grant)

    def _handle(self, grant, raw):
        try:
            return self._admit_and_run(grant, raw)
        except WorkerGitDenied as error:
            return _deny(error.code)

    def _admit_and_run(self, grant, raw):
        try:
            data = _strict(raw, MAX_FRAME)
        except (ValueError, RecursionError, UnicodeError):
            raise WorkerGitDenied('invalid_request')
        if not isinstance(data, dict):
            raise WorkerGitDenied('invalid_request')
        op = data.get('op')
        if op == 'push' or data.get('push') or data.get('allow_push'):
            raise WorkerGitDenied('push_denied')
        if op not in _FIELDS:
            raise WorkerGitDenied('invalid_request')
        if set(data) & _AUTHORITY_FIELDS:
            raise WorkerGitDenied('forbidden_field')
        requires_receipt=getattr(self._backend,'requires_receipt',True) is not False
        if op in {'pull','clone'} and not requires_receipt:
            required=_COMMON if op=='pull' else _CLONE_COMMON
            if not required<=set(data) or set(data)-_FIELDS[op]:
                raise WorkerGitDenied('invalid_request')
        elif set(data) != _FIELDS[op]:
            raise WorkerGitDenied('invalid_request')
        if type(data['version']) is not int or data['version'] != VERSION:
            raise WorkerGitDenied('invalid_request')
        clone=op in {'clone_prepare','clone','wait_clone'}
        fetch=op=='fetch'
        names=('job_id','agent','workspace_id','repository','remote','ref')
        for name in names+(() if fetch else ('branch' if clone else 'mode',)):
            if not isinstance(data[name], str):
                raise WorkerGitDenied('invalid_request')
        if (not _REMOTE.match(data['remote']) or not _ref(data['ref'],branch=True)
                or (not fetch and (_ref(data['branch'],branch=True) is not True if clone else data['mode'] not in MODES))):
            raise WorkerGitDenied('invalid_request')
        digest=data.get('request_sha256','')
        if 'request_sha256' in data and not isinstance(digest,str):raise WorkerGitDenied('invalid_request')
        if op in {'wait','wait_clone'} or (op in {'pull','clone'} and (requires_receipt or digest)):
            if not isinstance(digest,str) or not _DIGEST.match(digest):
                raise WorkerGitDenied('invalid_request')
        if op in {'pull','clone'}:
            receipt=data.get('approval_receipt','')
            if not isinstance(receipt,str) or len(receipt)>MAX_RECEIPT or not receipt.isascii():
                raise WorkerGitDenied('invalid_request')
            if requires_receipt and not receipt:raise WorkerGitDenied('invalid_request')
            if not requires_receipt and receipt:raise WorkerGitDenied('receipt_not_supported')
        if fetch and requires_receipt:raise WorkerGitDenied('workspace_authority_required')

        now = self._clock()
        # Identity/scope: channel-bound grant versus claimed fields.
        if data['job_id'] != grant.job_id:
            raise WorkerGitDenied('job_mismatch')
        if data['agent'] != grant.agent:
            raise WorkerGitDenied('agent_mismatch')
        if data['workspace_id'] != grant.workspace_id:
            raise WorkerGitDenied('workspace_mismatch')
        selected=next((item for item in (grant,*grant.alternates) if item.repository==data['repository']),None)
        if selected is None:raise WorkerGitDenied('repository_mismatch')
        grant=selected
        with self._lock:
            if not self._registered(grant):
                raise WorkerGitDenied('grant_revoked')
        if now >= grant.expires_at:
            raise WorkerGitDenied('grant_expired')
        if not self._live(grant):
            raise WorkerGitDenied('job_not_live')
        # Both phases mutate or authorize mutation of the worktree and Git state.
        if not CAPABILITIES <= grant.capabilities:
            raise WorkerGitDenied('read_only')
        scope = (data['remote'],data['ref']) if fetch else (data['remote'],data['ref'],data['branch'] if clone else data['mode'])
        allowed=grant.fetch_allowed if fetch else grant.clone_allowed if clone else grant.allowed
        if (scope[:2] if clone else scope) not in allowed:
            raise WorkerGitDenied('scope_denied')
        with self._lock:
            selected=self._selected_repositories.setdefault(grant.job_id,grant.repository)
            if selected!=grant.repository:raise WorkerGitDenied('repository_bound_elsewhere')
        if fetch:
            prepared=self._prepare(grant,scope,now,operation='fetch')
            return self._pull(grant,scope,prepared['request_sha256'],'',now,operation='fetch')
        if op=='clone_prepare':return self._prepare_clone(grant,scope,now)
        if op=='wait_clone':return self._wait(grant,scope,data['request_sha256'],operation='clone')
        if op=='clone':
            if not digest:digest=self._prepare_clone(grant,scope,now)['request_sha256']
            return self._pull(grant,scope,digest,receipt,now,operation='clone')
        if op == 'prepare':
            return self._prepare(grant, scope, now)
        if op == 'wait':
            return self._wait(grant, scope, data['request_sha256'])
        if not digest:digest=self._prepare(grant,scope,now)['request_sha256']
        return self._pull(grant,scope,digest,receipt,now)

    def _wait(self, grant, scope, digest,*,operation='pull'):
        """Bounded outcome delivery for a proposal made by this same live job."""
        with self._lock:
            record = self._prepared.get((grant.job_id, digest))
            if record is None or record['scope']!=scope or record.get('operation','pull')!=operation:
                raise WorkerGitDenied('not_prepared')
        record['event'].wait(min(30, max(0, grant.expires_at-self._clock())))
        if not self._active(grant):
            raise WorkerGitDenied('grant_revoked')
        with self._lock:
            response = record.get('response')
        return response if response is not None else {'version': VERSION, 'ok': True,
            'status': 'pending', 'job_id': grant.job_id, 'request_sha256': digest}

    def _active(self, grant):
        with self._lock:
            if not self._registered(grant):
                return False
        return self._clock() < grant.expires_at and self._live(grant)

    def _live(self, grant):
        try:
            return self._is_live(grant.job_id, grant.agent, grant.workspace_id) is True
        except Exception:
            return False

    def _prepare(self, grant, scope, now,*,operation='pull'):
        remote,ref=scope[:2]
        mode=scope[2] if operation=='pull' else None
        try:
            request = self._backend.prepare_fetch_repository(grant.workspace_id,grant.repository,remote,ref) if operation=='fetch' else (self._backend.prepare_repository(grant.workspace_id,grant.repository,remote,ref,mode)
                       if callable(getattr(self._backend,'prepare_repository',None))
                       else self._backend.prepare(grant.workspace_id,remote,ref,mode))
        except Exception:
            raise WorkerGitDenied('backend_refused')
        if not isinstance(request, GitApprovalRequest):
            raise WorkerGitDenied('backend_refused')
        payload = request.to_payload()
        params = payload['parameters']
        if (payload['operation'] != operation or payload['workspace_id'] != grant.workspace_id
                or payload['repository_path'] != grant.repository_path):
            raise WorkerGitDenied('request_scope_mismatch')
        # Canonical parameters are mandatory; no optional aliases.
        if getattr(self._backend,'requires_receipt',True) is False:
            context=params.get('job_context',{})
            if context.get('job_id')!=grant.job_id or context.get('agent')!=grant.agent:
                raise WorkerGitDenied('request_scope_mismatch')
        expected_params=(('remote_id',remote),('remote_ref',ref))+((('mode',mode),) if operation=='pull' else ())
        for name, expected in expected_params:
            if name not in params or params[name] != expected:
                raise WorkerGitDenied('request_scope_mismatch')
        key = (grant.job_id, request.digest)
        with self._lock:
            if not self._registered(grant):
                raise WorkerGitDenied('grant_revoked')
            existing = self._prepared.get(key)
            if existing is not None:
                # Never reset a dispatched nonce; re-preparing is a no-op for it.
                if existing['scope'] != scope:
                    raise WorkerGitDenied('request_scope_mismatch')
                if not existing['dispatched']:
                    existing['at'] = now
            else:
                self._make_room(grant.job_id, now)
                self._prepared[key] = {'scope': scope,'operation':operation, 'at': now, 'dispatched': False,
                                       'event': threading.Event()}
        return {'version': VERSION, 'ok': True, 'status': 'prepared', 'job_id': grant.job_id,
                'agent': grant.agent, 'workspace_id': grant.workspace_id,
                'repository': grant.repository, 'remote': remote, 'ref': ref, 'mode': mode,
                'request': payload, 'request_sha256': request.digest}

    def _clone_proposal(self,grant,scope,request):
        remote,ref,branch=scope
        return {'version':VERSION,'ok':True,'status':'prepared','operation':'clone','job_id':grant.job_id,
            'agent':grant.agent,'workspace_id':grant.workspace_id,'repository':grant.repository,
            'remote':remote,'ref':ref,'branch':branch,'request':request.to_payload(),'request_sha256':request.digest}

    def _prepare_clone(self,grant,scope,now):
        remote,ref,branch=scope
        with self._lock:
            if not self._registered(grant):raise WorkerGitDenied('grant_revoked')
            existing=next((record for (job,_),record in self._prepared.items()
                if job==grant.job_id and record.get('operation')=='clone' and record['scope']==scope),None)
            if existing is not None and now-existing['at']<self._ttl:
                if not existing['dispatched']:existing['at']=now
                return self._clone_proposal(grant,scope,existing['request'])
        try:request=self._backend.prepare_clone_repository(grant.workspace_id,grant.repository,remote,ref,branch)
        except Exception:raise WorkerGitDenied('backend_refused')
        if not isinstance(request,GitApprovalRequest):raise WorkerGitDenied('backend_refused')
        payload=request.to_payload();params=payload['parameters']
        parent=PurePosixPath(grant.repository_path)
        for _ in PurePosixPath(grant.repository).parts:parent=parent.parent
        if (payload['operation']!='clone' or payload['workspace_id']!=grant.workspace_id
                or payload['repository_path']!=str(parent) or payload['expected_head'] is not None
                or payload['branch']!=branch or params.get('identity_kind')!='parent_workspace'
                or params.get('repository')!=grant.repository
                or any(params.get(key)!=value for key,value in (('remote_id',remote),('remote_ref',ref),('local_branch',branch)))
                or params.get('job_context',{}).get('job_id')!=grant.job_id
                or params.get('job_context',{}).get('agent')!=grant.agent):
            raise WorkerGitDenied('request_scope_mismatch')
        key=(grant.job_id,request.digest)
        with self._lock:
            if not self._registered(grant):raise WorkerGitDenied('grant_revoked')
            existing=self._prepared.get(key)
            if existing is not None:
                if existing['scope']!=scope or existing.get('operation')!='clone':raise WorkerGitDenied('request_scope_mismatch')
                if not existing['dispatched']:existing['at']=now
            else:
                self._make_room(grant.job_id,now)
                self._prepared[key]={'scope':scope,'operation':'clone','request':request,'at':now,'dispatched':False,'event':threading.Event()}
        return self._clone_proposal(grant,scope,request)

    def _make_room(self, job_id, now):
        # Called with the lock held. Only never-dispatched records are ever
        # dropped; dispatched ones stay until revoke so a nonce cannot become
        # replayable. A full store of dispatched records refuses new prepares.
        for key in [k for k, r in self._prepared.items()
                    if not r['dispatched'] and now - r['at'] >= self._ttl]:
            del self._prepared[key]
        mine = [k for k in self._prepared if k[0] == job_id]
        if len(mine) >= MAX_PREPARED_PER_JOB or len(self._prepared) >= MAX_PREPARED_TOTAL:
            pool = mine if len(mine) >= MAX_PREPARED_PER_JOB else list(self._prepared)
            idle = [k for k in pool if not self._prepared[k]['dispatched']]
            if not idle:
                raise WorkerGitDenied('prepared_full')
            del self._prepared[min(idle, key=lambda k: self._prepared[k]['at'])]

    def _receipt_claims(self, receipt, digest, now):
        # Unsigned shape/freshness screen only. The backend's verifier checks
        # the signature and atomically consumes the receipt.
        try:
            envelope = _strict(receipt, MAX_RECEIPT)
            claims = envelope['claims']
            issued, expires, bound = claims['issued_at'], claims['expires_at'], claims['request_sha256']
            if (not isinstance(envelope, dict) or set(envelope) != {'claims', 'signature'}
                    or not isinstance(claims, dict) or type(issued) is not int or type(expires) is not int):
                raise ValueError
        except (ValueError, KeyError, TypeError, RecursionError):
            raise WorkerGitDenied('receipt_invalid')
        if bound != digest:
            raise WorkerGitDenied('receipt_mismatch')
        if issued > now or now >= expires:
            raise WorkerGitDenied('receipt_stale')

    def _pull(self,grant,scope,digest,receipt,now,*,operation='pull'):
        remote,ref=scope[:2]
        mode=scope[2] if operation!='fetch' else None
        key = (grant.job_id, digest)
        if getattr(self._backend,'requires_receipt',True) is not False:
            self._receipt_claims(receipt,digest,now)
        elif receipt:raise WorkerGitDenied('receipt_not_supported')
        with self._lock:
            record = self._prepared.get(key)
            if record is None:
                raise WorkerGitDenied('not_prepared')
            if record['scope']!=scope or record.get('operation','pull')!=operation:
                raise WorkerGitDenied('prepared_scope_mismatch')
            if record['dispatched']:
                raise WorkerGitDenied('replay')
            if now - record['at'] >= self._ttl:
                raise WorkerGitDenied('prepared_stale')
            if not self._registered(grant):
                raise WorkerGitDenied('grant_revoked')
            record['dispatched'] = True
        base = {'version': VERSION, 'job_id': grant.job_id, 'agent': grant.agent,
                'workspace_id': grant.workspace_id, 'repository': grant.repository,
                'remote': remote, 'ref': ref, 'mode': mode, 'request_sha256': digest}
        if operation=='clone':
            base.pop('mode');base.update(operation='clone',branch=mode)
        elif operation=='fetch':
            base.pop('mode');base['operation']='fetch'
        try:
            if operation=='fetch':
                outcome=self._backend.fetch_repository(grant.workspace_id,grant.repository,remote,ref,'')
            elif operation=='clone':
                outcome=self._backend.clone_repository(grant.workspace_id,grant.repository,remote,ref,mode,digest,receipt)
            else:
                outcome = (self._backend.pull_repository(grant.workspace_id,grant.repository,remote,ref,receipt,mode)
                           if callable(getattr(self._backend,'pull_repository',None))
                           else self._backend.pull(grant.workspace_id,remote,ref,receipt,mode))
            encoded = json.dumps(outcome, sort_keys=True, allow_nan=False)
            if not isinstance(outcome, dict) or len(encoded) > MAX_OUTCOME:
                raise ValueError
            outcome = json.loads(encoded)
        except PermissionError:
            response = {**base, 'ok': False, 'status': 'denied', 'code': 'backend_denied'}
        except Exception:
            # The backend may have consumed the receipt or changed state. Do not
            # retry; ordinary recovery/reconciliation must inspect its guard.
            response = {**base, 'ok': False, 'status': 'uncertain', 'recovery_required': True,
                    'code': 'backend_outcome_unavailable'}
        else:
            response = {**base, 'ok': True, 'status': 'completed', 'outcome': outcome}
        with self._lock:
            record['response'] = response
            record['event'].set()
        return response


class WorkerGitChannel:
    """One per-job transport endpoint bound to its service-issued grant."""

    def __init__(self, rpc: WorkerGitRPC, grant: WorkerGitGrant):
        self._rpc = rpc
        self._grant = grant

    @property
    def job_id(self):
        return self._grant.job_id

    def active(self) -> bool:
        """True while this channel's own grant is current, unexpired and its job live."""
        return self._rpc._active(self._grant)

    def handle(self, raw) -> dict:
        return self._rpc._handle(self._grant, raw)

    def handle_bytes(self, raw) -> bytes:
        return json.dumps(self.handle(raw), sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

    def serve_frame(self, read, write):
        """Serve one length-prefixed frame: 4-byte big-endian size, then JSON."""
        header = _read_exact(read, 4)
        (size,) = struct.unpack('>I', header)
        if size > MAX_FRAME:
            body = json.dumps(_deny('invalid_request'), sort_keys=True).encode()
        else:
            body = self.handle_bytes(_read_exact(read, size))
        write(struct.pack('>I', len(body)) + body)


def _read_exact(read, size):
    data = b''
    while len(data) < size:
        chunk = read(size - len(data))
        if not chunk:
            raise EOFError('short frame')
        data += chunk
    return data
