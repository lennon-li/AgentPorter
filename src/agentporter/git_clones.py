"""Owner-scoped clone on one existing admitted worker transaction."""
from dataclasses import dataclass
import json,os,sqlite3,time
from urllib.parse import quote
from pathlib import Path
from agentporter.git_clone_preparation import CloneScope,prepare_clone,consume_clone,target_before,_PROGRAM as _CLONE_PROGRAM
from agentporter.git_clone_authority import CloneBirthAuthorization,validate_clone_authorization
from agentporter.git_approvals import _canonical,_decode
from agentporter.git_pulls import ApprovedGitPulls,JobBoundGitPulls
from agentporter.git_fetches import _write_fetch_guard
from agentporter.git_pushes import _write_private
from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import workspace_key
from agentporter.sandbox.recovery_guards import _guard_record
from agentporter.sandbox.workspace_custody import capture_workspace_entry,inspect_custody,preflight_workspace_custody,_rename_noreplace
from agentporter.git_commits import _sync


class ApprovedGitClones:
    _require_runtime=ApprovedGitPulls._require_runtime
    def __init__(self,registry,sandbox,authority,manager):
        self.registry,self.sandbox,self.authority,self.manager=registry,sandbox,authority,manager
        self.verifier=authority.verifier;self._require_runtime()
        self.requires_receipt=getattr(authority,'requires_receipt',True)
    def bind_job(self,workspace_id,job_id,agent,*,repository):return JobBoundGitClone(self,job_id,workspace_id,agent,repository=repository)
    def _validate_job(self,request,*,allow_finalizing=False):
        self._require_runtime();p=request.to_payload();c=p['parameters']['job_context']
        with self.manager.lock:tx=self.manager._job_transactions.get(c['job_id'])
        db=self.manager._get_db()
        try:
            row=db.execute('SELECT workspace_id,agent,argv,status,workspace_transaction FROM jobs WHERE job_id=?',(c['job_id'],)).fetchone()
            admissions=db.execute('SELECT token FROM job_admissions WHERE job_id=?',(c['job_id'],)).fetchall()
        finally:db.close()
        if not allow_finalizing:
            with self.manager.lock:process=self.manager.active_processes.get(c['job_id'])
            if process is None or process.poll() is not None:raise PermissionError('Clone requires its actual live owned worker process')
        statuses={'running','finalizing'} if allow_finalizing else {'running'}
        if (row is None or row['workspace_id']!=p['workspace_id'] or row['agent']!=c['agent'] or row['status']not in statuses or json.loads(row['argv'])!=['confined-development-worker',c['agent']] or len(admissions)!=1 or admissions[0]['token']!=c['admission_token'] or tx is None or tx._closed or tx._applied or row['workspace_transaction']!=str(tx.directory)):
            raise PermissionError('Clone requires its exact active parent job admission')
        st=tx.directory.stat();root=os.fstat(tx._root_fd)
        if (str(tx.directory),st.st_dev,st.st_ino)!=(c['transaction_directory'],c['transaction_device'],c['transaction_inode']) or (str(tx.workspace),root.st_dev,root.st_ino)!=(p['repository_path'],p['repository_device'],p['repository_inode']):raise PermissionError('Clone parent transaction identity changed')
        ws=self.registry.get(p['workspace_id'])
        if not ws.writable or not ws.allow_git or not tx._allow_git_birth or Path(ws.path).resolve()!=tx.workspace:raise PermissionError('Clone requires authoritative writable local Git policy')
        tx._check_root_identity();return tx


class JobBoundGitClone(JobBoundGitPulls):
    def __init__(self,backend,job_id,workspace_id,agent,*,repository):
        self.backend=backend;self.job_id=job_id;self.workspace_id=workspace_id;self.agent=agent;self.repository=repository
        self.transaction=None;self.token=None;self._prepared=None;self._context()
    def _job_context(self):
        tx=self._context();st=tx.directory.stat()
        return {'job_id':self.job_id,'agent':self.agent,'admission_token':self.token,'transaction_directory':str(tx.directory),'transaction_device':st.st_dev,'transaction_inode':st.st_ino}
    def prepare(self,remote_id,ref,branch='refs/heads/main'):
        tx=self._context()
        with tx._lifecycle_lock:
            self._context()
            if self._prepared is not None:raise PermissionError('Clone proposal already prepared for this job')
            grant,broker=self.backend.authority.authorize(self.workspace_id,remote_id,ref,'clone',repository=self.repository)
            scope=CloneScope(self.workspace_id,str(tx.workspace),grant.repository_relative,remote_id,grant.repository.url,ref,branch,self.backend.authority.policy_sha256)
            request,candidate=prepare_clone(tx,self.backend.sandbox,scope,broker,job_context=self._job_context())
            self.backend._validate_job(request);self._prepared=(request,candidate,scope)
            return request
    def execute(self,request_sha256,receipt=''):
        tx=self._context()
        with tx._lifecycle_lock:return self._execute_locked(request_sha256,receipt)
    def _execute_locked(self,digest,receipt):
        if not isinstance(receipt,str) or not receipt.isascii() or len(receipt)>8192:raise PermissionError('Clone receipt exceeds bounded signed envelope')
        if self._prepared is None or self._prepared[0].digest!=digest:raise PermissionError('Clone requires its exact protected prepared request')
        request,candidate,scope=self._prepared;tx=self.backend._validate_job(request)
        from agentporter.git_authorizations import workspace_mode,local_nonce,claim
        local=workspace_mode(self.backend.authority)
        if local and receipt:raise ValueError('Workspace clone does not accept external approval receipts')
        if getattr(tx,'_private_clone_pending',False) or getattr(tx,'_private_pull_pending',False):raise PermissionError('Parent job already has unresolved approved Git work')
        grant,broker=self.backend.authority.authorize(self.workspace_id,scope.remote_id,scope.remote_ref,'clone',repository=self.repository)
        p=request.to_payload()['parameters']
        if grant.repository.url!=scope.remote_url or self.backend.authority.policy_sha256!=scope.policy_sha256 or target_before(tx,scope)!=p['target_before']:raise PermissionError('Clone owner scope or target changed before claim')
        ad=broker.discover('git-upload-pack')
        if ad.object_format!=p['object_format'] or ad.refs.get(scope.remote_ref)!=p['remote_oid']:raise PermissionError('Clone advertised graph changed since owner review')
        envelope=None if local else _decode(receipt)
        nonce=local_nonce() if local else envelope['claims']['nonce']
        verifier=self.backend.verifier
        context={'owner_config_dir':str(Path(self.backend.authority._config_dir).resolve(strict=True)),'policy_sha256':self.backend.authority.policy_sha256,'ledger_path':str(verifier.ledger_path),'ledger_identity':list(verifier._ledger_identity),'ledger_parent_identity':list(verifier._parent_identity)}
        doc={'version':1,'request':request.to_payload(),'request_sha256':request.digest,'approval_receipt':receipt,'approval_nonce':nonce,'verification_context':context}
        if local:doc.update(version=2,authorization_mode='workspace')
        validate_clone_authorization(doc,registry=self.backend.registry,state_dir=self.backend.sandbox.state_dir,owner_config_dir=self.backend.authority._config_dir,require_consumed=False)
        cap=CloneBirthAuthorization(self.backend,tx,_canonical(doc))
        guard=Path(self.backend.sandbox.state_dir)/'workspace-transactions'/(workspace_key(os.fstat(tx._root_fd))+'.git-pending.json')
        guarddoc={'version':1,'kind':'private-job-clone-candidate','authorization':doc,'candidate_directory':str(tx.directory),'admission_token':self.token,'canonical_published':False}
        # Signature, current expiry and replay are checked read-only before any
        # durable activity. The actual ledger claim repeats all these checks.
        if not local:
            claims=envelope['claims'];now=int(time.time())
            if not claims['issued_at']<=now<claims['expires_at']:raise PermissionError('Clone receipt is not currently valid')
        verifier._check_ledger_identity()
        with sqlite3.connect('file:'+quote(str(verifier.ledger_path))+'?mode=ro',uri=True) as ledger:
            if ledger.execute('SELECT 1 FROM consumed WHERE nonce=?',(nonce,)).fetchone():raise PermissionError('Clone receipt already consumed')
        if os.path.lexists(guard):raise PermissionError('Canonical workspace already has unresolved Git activity')
        prepared=tx.directory/'clone-guard-prepared.json'
        tx._private_clone_pending=True;tx._retain_directory=True
        published=False;record=None;before_record=None
        try:
            # Record the exact private inode before its create-only rename.
            _write_private(prepared,guarddoc);before_record=_guard_record(prepared)
            _write_private(tx.directory/'clone-intent.json',{'version':1,'authorization':doc,'guard':str(guard),'guard_record':before_record,'candidate_directory':str(tx.directory),'prepared_guard':str(prepared)})
            source=os.open(tx.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            target=os.open(guard.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                _rename_noreplace(source,prepared.name,target,guard.name);published=True
                os.fsync(source);os.fsync(target)
            finally:os.close(source);os.close(target)
            record=_guard_record(guard)
            if record['signature'][:-1]!=before_record['signature'][:-1] or record['signature'][-1]<before_record['signature'][-1] or any(record[k]!=before_record[k] for k in record if k!='signature'):raise PermissionError('Clone prepared guard changed during rename')
            _write_private(tx.directory/'clone-guard-record.json',record)
            db=self.backend.manager._get_db()
            try:
                with db:
                    db.execute('BEGIN IMMEDIATE')
                    owned=db.execute('SELECT job_id FROM job_admissions WHERE token=?',(self.token,)).fetchone()
                    if owned is None or owned['job_id']!=self.job_id:raise PermissionError('Clone lost exact original admission')
                    db.execute('INSERT INTO git_admissions VALUES (?,?,?,?)',(self.token,request.digest,str(guard),'active'))
            finally:db.close()
            class Claim:
                def verify_and_consume(_claim,receipt,expected):
                    self.backend._validate_job(request)
                    approval=claim(self.backend.authority,expected,receipt,nonce=nonce if local else None)
                    self.backend._validate_job(request);cap.validate()
                    tx._approved_clone_births={scope.repository:cap}
                    return approval
            result=consume_clone(tx,self.backend.sandbox,scope,request,candidate,receipt,Claim(),job_context=self._job_context(),birth_authorization=cap)
            self.backend._validate_job(request);cap.validate()
            intent=ClonePublicationIntent(self.backend,tx,cap,guard,record)
            tx._clone_publication_intent=intent
            _write_private(tx.directory/'clone-private-result.json',{'request_sha256':request.digest,'result':result,'canonical_published':False})
            return {'operation':'clone','status':'completed','candidate_status':'cloned','canonical_published':False,'request_sha256':request.digest,'job_id':self.job_id}
        except BaseException as error:
            # A refusal before claim must not masquerade as consumed activity.
            # If claim outcome cannot be proved unspent, retain every guard and
            # the original admission for explicit owner reconciliation.
            unclaimed=False
            try:
                verifier._check_ledger_identity()
                with sqlite3.connect('file:'+quote(str(verifier.ledger_path))+'?mode=ro',uri=True) as ledger:
                    claim=ledger.execute('SELECT request_sha256 FROM consumed WHERE nonce=?',(nonce,)).fetchone()
                    unclaimed=claim is None or claim[0]!=request.digest
                if unclaimed:
                    if not published and before_record is not None and os.path.lexists(guard) and not os.path.lexists(prepared):
                        observed=_guard_record(guard)
                        if observed['signature'][:-1]!=before_record['signature'][:-1] or any(observed[k]!=before_record[k] for k in observed if k!='signature'):raise PermissionError('Clone guard rename outcome is foreign')
                        published=True;record=observed
                    if published:
                        expected=record if record is not None else _guard_record(guard)
                        original=before_record
                        if expected['signature'][:-1]!=original['signature'][:-1] or any(expected[k]!=original[k] for k in expected if k!='signature'):raise PermissionError('Unclaimed clone guard identity changed')
                        slot=Path(self.backend.sandbox.state_dir)/'clone-rejected-guard-custody'/tx.directory.name
                        slot.parent.mkdir(mode=0o700,exist_ok=True)
                        support=preflight_workspace_custody(guard.parent,guard.name,slot)
                        observed=capture_workspace_entry(guard.parent,guard.name,slot,expected_record=expected,expected_support=support)
                        if not observed['expected'] or observed['state']!='captured_expected':raise PermissionError('Unclaimed clone guard cleanup conflicts')
                    db=self.backend.manager._get_db()
                    try:
                        with db:db.execute("UPDATE git_admissions SET status='resolved' WHERE token=? AND request_sha256=? AND guard_path=? AND status='active'",(self.token,request.digest,str(guard)))
                    finally:db.close()
                    tx._private_clone_pending=False
                    raise PermissionError('Clone refused before approval consumption; parent job admission remains owned') from error
            except BaseException as cleanup:
                if not tx._private_clone_pending:raise
                raise ResourceCleanupError('Unconsumed clone cleanup retained exact guard, candidate and admission') from cleanup
            raise ResourceCleanupError('Clone claim/execution requires exact retained guard, candidate and admission recovery') from error



@dataclass(frozen=True)
class ClonePublicationIntent:
    backend:object
    transaction:object
    authority:CloneBirthAuthorization
    guard:Path
    guard_record:dict
    def to_payload(self):return {'authorization':self.authority.document,'guard':str(self.guard),'guard_record':self.guard_record,'candidate_directory':str(self.transaction.directory)}
    def validate(self):
        self.authority.validate()
        if getattr(self.transaction,'_clone_publication_intent',None)is not self:raise PermissionError('Clone publication intent substituted')
        p=self.authority.document['request']['parameters'];db=self.backend.manager._get_db()
        try:row=db.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',(p['job_context']['admission_token'],)).fetchone()
        finally:db.close()
        if row is None or tuple(row)!=(self.authority.document['request_sha256'],str(self.guard),'active') or _guard_record(self.guard)!=self.guard_record:raise PermissionError('Clone consumed guard/admission changed')
    def finish(self):
        # Keep the exact admission stable while retiring its consumed guard.
        receipt=json.loads((self.transaction.directory/'publication-receipt.json').read_text())
        if receipt.get('approved_clone')!=self.to_payload() or receipt.get('status')!='published':raise PermissionError('Clone outcome receipt differs from exact consumed intent')
        db=self.backend.manager._get_db()
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                self.validate()
                slot=Path(self.backend.sandbox.state_dir)/'clone-guard-custody'/self.transaction.directory.name
                slot.parent.mkdir(mode=0o700,exist_ok=True)
                expected=preflight_workspace_custody(self.guard.parent,self.guard.name,slot)
                observed=capture_workspace_entry(self.guard.parent,self.guard.name,slot,expected_record=self.guard_record,expected_support=expected)
                if not observed['expected'] or observed['state']!='captured_expected':raise ResourceCleanupError('Clone guard retirement conflicts with later owner bytes')
                p=self.authority.document['request']['parameters']
                changed=db.execute("UPDATE git_admissions SET status='resolved' WHERE token=? AND request_sha256=? AND guard_path=? AND status='active'",(p['job_context']['admission_token'],self.authority.document['request_sha256'],str(self.guard)))
                if changed.rowcount!=1:raise ResourceCleanupError('Clone exact admission resolution raced')
        finally:db.close()
        self.transaction._private_clone_pending=False
