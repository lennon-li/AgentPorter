"""Offline clone outcome reconciliation. Never replays acquisition or checkout."""
import hashlib,json,os,sqlite3
from urllib.parse import quote
from pathlib import Path
from types import SimpleNamespace
from agentporter.git_clone_authority import validate_clone_authorization
from agentporter.git_clone_preparation import CloneScope,target_before
from agentporter.git_admission import _recovery_database
from agentporter.git_approvals import _canonical
from agentporter.sandbox.workspace_recovery import _maintenance,_directory,_read_private_json,_write_receipt,recover_workspace
from agentporter.sandbox.workspace_custody import inspect_custody,capture_workspace_entry,preflight_workspace_custody
from agentporter.sandbox.recovery_guards import _guard_record
from agentporter.sandbox.workspace_directories import inspect_directory
from agentporter.workspaces.leases import mutation_lease,workspace_key


def _binding(state,request,transaction,guard,*,resolve=False,database=None):
    p=request.to_payload();c=p['parameters']['job_context']
    owned=database is None;db=_recovery_database(state,write=resolve) if owned else database
    try:
        # All ownership reads and state changes share the same writer lock.
        # An externally supplied transaction also covers guard retirement.
        if resolve and not db.in_transaction:db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT workspace_id,agent,workspace_transaction,status FROM jobs WHERE job_id=?',(c['job_id'],)).fetchone()
        admission=db.execute('SELECT job_id FROM job_admissions WHERE token=?',(c['admission_token'],)).fetchone()
        binding=db.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',(c['admission_token'],)).fetchone()
        if row is None or row[:3]!=(p['workspace_id'],c['agent'],str(transaction)) or row[3]not in {'cleanup_failed','finalizing','recovered'}:raise PermissionError('Clone recovery requires its stopped matching job')
        if binding is not None and (binding[:2]!=(request.digest,str(guard)) or binding[2]not in {'active','resolved'}):raise PermissionError('Clone recovery Git admission changed')
        if (binding is None or binding[2]=='active') and (admission is None or admission[0]!=c['job_id']):raise PermissionError('Clone recovery lost exact original admission')
        if binding is not None and binding[2]=='resolved' and admission is not None and admission[0]!=c['job_id']:raise PermissionError('Clone admission token rebound to later work')
        if resolve:
            if binding is None:db.execute('INSERT INTO git_admissions VALUES (?,?,?,?)',(c['admission_token'],request.digest,str(guard),'resolved'))
            else:
                changed=db.execute("UPDATE git_admissions SET status='resolved' WHERE token=? AND request_sha256=? AND guard_path=? AND status=?",(c['admission_token'],request.digest,str(guard),binding[2]))
                if changed.rowcount!=1:raise PermissionError('Clone Git admission ownership changed before resolution')
            changed=db.execute("UPDATE jobs SET status='recovered',exit_code=1 WHERE job_id=? AND workspace_id=? AND agent=? AND workspace_transaction=? AND status=?",(c['job_id'],p['workspace_id'],c['agent'],str(transaction),row[3]))
            if changed.rowcount!=1:raise PermissionError('Clone job ownership changed before resolution')
            if admission is not None:
                changed=db.execute('DELETE FROM job_admissions WHERE token=? AND job_id=?',(c['admission_token'],c['job_id']))
                if changed.rowcount!=1:raise PermissionError('Clone parent admission ownership changed before resolution')
            if owned:db.commit()
        return 'unbound' if binding is None else binding[2]
    except BaseException:
        if owned and resolve:db.rollback()
        raise
    finally:
        if owned:db.close()


def _intent(transaction,state,workspace,registry,owner_config_dir,*,consumed=True):
    intent,_=_read_private_json(transaction/'clone-intent.json')
    if not isinstance(intent,dict) or set(intent)!={'version','authorization','guard','guard_record','candidate_directory','prepared_guard'} or intent['version']!=1 or intent['candidate_directory']!=str(transaction):raise PermissionError('Invalid exact clone recovery intent')
    request=validate_clone_authorization(intent['authorization'],registry=registry,state_dir=state,owner_config_dir=owner_config_dir,require_consumed=consumed)
    p=request.to_payload();c=p['parameters']['job_context'];info=transaction.stat();parent=workspace.stat()
    guard=state/'workspace-transactions'/(workspace_key(parent)+'.git-pending.json')
    if (p['repository_path']!=str(workspace) or c['transaction_directory']!=str(transaction) or (info.st_dev,info.st_ino)!=(c['transaction_device'],c['transaction_inode']) or intent['guard']!=str(guard)):raise PermissionError('Clone recovery transaction or guard identity changed')
    prepared=transaction/'clone-guard-prepared.json'
    if intent['prepared_guard']!=str(prepared):raise PermissionError('Clone preclaim guard escapes exact transaction')
    actual_record=transaction/'clone-guard-record.json'
    frozen=os.path.lexists(actual_record)
    original=intent['guard_record']
    if frozen:
        record,_=_read_private_json(actual_record)
        if record['signature'][:-1]!=original['signature'][:-1] or record['signature'][-1]<original['signature'][-1] or any(record[k]!=original[k] for k in record if k!='signature'):raise PermissionError('Clone published guard differs from prepared exact inode')
        intent['guard_record']=record
    slot=state/'clone-guard-custody'/transaction.name
    if os.path.lexists(guard):
        observed=_guard_record(guard)
        if not frozen and observed['signature'][:-1]==original['signature'][:-1] and observed['signature'][-1]>=original['signature'][-1] and all(observed[k]==original[k] for k in observed if k!='signature'):
            intent['guard_record']=observed
        if _guard_record(guard)!=intent['guard_record']:raise PermissionError('Clone consumed guard was substituted')
        raw,_=_read_private_json(guard)
    elif os.path.lexists(prepared):
        if frozen or _guard_record(prepared)!=original:raise PermissionError('Clone private preclaim guard changed')
        raw,_=_read_private_json(prepared)
    else:
        held=inspect_custody(guard.parent,slot)
        if not held['expected'] or held['state']!='captured_expected':raise PermissionError('Clone consumed guard custody unresolved')
        raw,_=_read_private_json(slot/'captured')
        # Custody's durable intent binds exact original inode and bytes.
        custody,_=_read_private_json(slot/'intent.json')
        if custody['path']!=guard.name or custody['expected']['sha256']!=intent['guard_record']['sha256'] or custody['expected']['signature']!=intent['guard_record']['signature']:raise PermissionError('Clone guard custody names another original')
    expected={'version':1,'kind':'private-job-clone-candidate','authorization':intent['authorization'],'candidate_directory':str(transaction),'admission_token':c['admission_token'],'canonical_published':False}
    if raw!=expected:raise PermissionError('Clone recovery guard does not match spent authority')
    _binding(state,request,transaction,guard)
    return intent,request,guard,slot


def validate_clone_recovery_context(context,*,registry,state_dir,owner_config_dir,transaction,workspace):
    state=Path(state_dir);transaction=Path(transaction);workspace=Path(workspace)
    intent,request,guard,slot=_intent(transaction,state,workspace,registry,owner_config_dir)
    expected={'authorization':intent['authorization'],'guard':str(guard),'guard_record':intent['guard_record'],'candidate_directory':str(transaction)}
    if context!=expected:raise PermissionError('Publication clone context differs from exact consumed intent')
    return request


def recover_clone(registry,state_dir,owner_config_dir,workspace_id,transaction_directory,*,apply=False,expected_plan_sha256=None):
    state=Path(state_dir).resolve(strict=True);workspace=Path(registry.get(workspace_id).path).resolve(strict=True)
    transaction=Path(transaction_directory).resolve(strict=True);transactions=state/'workspace-transactions'
    if transaction.parent!=transactions or not transaction.name.startswith(workspace_key(workspace.stat())[:12]+'-'):raise PermissionError('Clone recovery target escapes private parent transaction')
    _directory(transaction,private=True)
    # Workspace recovery owns its own stopped-service lock. Read-only planning
    # first avoids nesting independent flock handles and binds apply by digest.
    journal=transactions/(workspace_key(workspace.stat())+'.pending.json')
    rollback=None
    if os.path.lexists(journal):
        rollback=recover_workspace(state,workspace,pull_registry=registry,pull_owner_config_dir=owner_config_dir)
    from agentporter.git_remote_policy import selected_repository
    from agentporter.sandbox.common_publication import preflight_common_publication
    preflight_common_publication(workspace,transactions)
    with _maintenance(state),mutation_lease(workspace,transactions,allow_pending=True), selected_repository(
            workspace,'.',publication=True,state_dir=transactions) as (_,publication_fd,_):
        data_workspace=f'/proc/self/fd/{publication_fd}/.'
        intent,request,guard,slot=_intent(transaction,state,workspace,registry,owner_config_dir,consumed=False)
        p=request.to_payload();params=p['parameters']
        if p['workspace_id']!=workspace_id:raise PermissionError('Clone recovery workspace differs from exact request')
        # A spent request is independently checked when publication began.
        from agentporter.git_remote_policy import load_owner_git_remotes
        owner=load_owner_git_remotes(owner_config_dir,registry,state);owner.verifier._check_ledger_identity()
        with sqlite3.connect('file:'+quote(str(owner.verifier.ledger_path))+'?mode=ro',uri=True) as ledger:
            claim=ledger.execute('SELECT request_sha256 FROM consumed WHERE nonce=?',(intent['authorization']['approval_nonce'],)).fetchone()
        consumed=claim is not None and claim[0]==request.digest
        receipt_path=transaction/'publication-receipt.json';publication=None
        if rollback is not None:endpoint='rollback_pending'
        elif os.path.lexists(receipt_path) and not os.path.lexists(state/'recovery-receipts'/(transaction.name+'.rollback.json')):
            publication,_=_read_private_json(receipt_path)
            expected={'authorization':intent['authorization'],'guard':str(guard),'guard_record':intent['guard_record'],'candidate_directory':str(transaction)}
            if not consumed or publication.get('approved_clone')!=expected or publication.get('status')!='published' or publication.get('workspace')!=str(workspace) or publication.get('transaction')!=str(transaction):raise PermissionError('Clone terminal publication receipt differs from consumed authority')
            for item in publication['directories']:
                if inspect_directory(data_workspace,item['path'],transaction/item['operation'])!={'state':'published','intent':item['intent']}:raise PermissionError('Clone published directory now contains later owner work')
            endpoint='after'
        else:
            rollback_receipt=state/'recovery-receipts'/(transaction.name+'.rollback.json')
            if os.path.lexists(rollback_receipt):
                rolled,_=_read_private_json(rollback_receipt)
                if rolled.get('transaction')!=str(transaction) or rolled.get('endpoint')!='before' or rolled.get('status')!='recovered':raise PermissionError('Clone rollback receipt differs from exact parent transaction')
                endpoint='before'
            else:
                fd=os.dup(publication_fd)
                try:
                    fake=SimpleNamespace(workspace=workspace,_root_path=str(data_workspace),_root_fd=fd,_closed=False,_applied=False,writable=True,_allow_git_birth=True,_birth_empty_directories={params['repository']:params['target_before'].get('directory')},_check_root_identity=lambda:None)
                    scope=CloneScope(workspace_id,str(workspace),params['repository'],params['remote_id'],params['remote_url'],params['remote_ref'],params['local_branch'],params['policy_sha256'])
                    if target_before(fake,scope)!=params['target_before']:raise PermissionError('Interrupted private clone canonical target changed')
                finally:os.close(fd)
                endpoint='before'
        plan={'operation':'clone','status':'planned','workspace':str(workspace),'transaction':str(transaction),'request_sha256':request.digest,'guard_sha256':intent['guard_record']['sha256'],'endpoint':endpoint,'consumed':consumed,'workspace_rollback':rollback,'retention':'retain_private_candidate_and_guard_custody'}
        digest=hashlib.sha256(_canonical(plan)).hexdigest();plan['plan_sha256']=digest
        if not apply:return plan
        if expected_plan_sha256!=digest:raise PermissionError('Clone recovery requires exact reviewed plan digest')
        if rollback is None:
            database=_recovery_database(state,write=True)
            try:
                database.execute('BEGIN IMMEDIATE')
                _binding(state,request,transaction,guard,database=database)
                slot.parent.mkdir(mode=0o700,exist_ok=True)
                if os.path.lexists(guard):
                    support=preflight_workspace_custody(guard.parent,guard.name,slot)
                    observed=capture_workspace_entry(guard.parent,guard.name,slot,expected_record=intent['guard_record'],expected_support=support)
                    if not observed['expected'] or observed['state']!='captured_expected':raise PermissionError('Clone guard retirement conflicts with later owner work')
                _binding(state,request,transaction,guard,resolve=True,database=database)
                database.commit()
            except BaseException:
                database.rollback();raise
            finally:database.close()
            result={**plan,'status':'recovered','guard_retained_in_custody':True}
            path=transaction/'clone-recovery-receipt.json'
            if not os.path.lexists(path):_write_receipt(path,result)
            return result
    # Only the independently reviewed workspace rollback may alter canonical
    # entries, using its existing exact-inode custody and crash-safe journal.
    recover_workspace(state,workspace,apply=True,expected_plan_sha256=rollback['plan_sha256'],restore_deletions=True,pull_registry=registry,pull_owner_config_dir=owner_config_dir)
    next_plan=recover_clone(registry,state,owner_config_dir,workspace_id,transaction)
    return recover_clone(registry,state,owner_config_dir,workspace_id,transaction,apply=True,expected_plan_sha256=next_plan['plan_sha256'])
