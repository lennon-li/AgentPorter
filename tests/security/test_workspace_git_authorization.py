"""Policy-authorized inbound Git: no phone receipt, exact durable claims."""
import json,os,sqlite3
from pathlib import Path
import pytest
from agentporter.git_authorizations import workspace_policy_document,claim,assert_claim
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_fetches import ApprovedGitFetches
from agentporter.git_pulls import ApprovedGitPulls
from agentporter.git_approvals import issue_git_approval
from tests.security.test_approved_git_pull import backend,git
from tests.security.test_development_runtime import runtime_factory


def activate(service,*,operations=None):
    path=Path(service.authority._config_dir)/'git-remote-policy.json';raw=path.read_bytes();data=json.loads(raw)
    if operations is not None:
        for grant in data['grants']:grant['operations']=operations
    data=workspace_policy_document(data,previous_raw=raw)
    path.write_text(json.dumps(data))
    authority=load_owner_git_remotes(path.parent,service.registry,service.sandbox.state_dir)
    return authority


@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_unsigned_fetch_then_pull_uses_exact_grant_and_existing_ledger(tmp_path,monkeypatch,algorithm):
    root,old,key,manager,remote=backend(tmp_path,monkeypatch,algorithm)
    authority=activate(old,operations=['fetch','pull']);ledger=authority.verifier.ledger_path;inode=ledger.stat().st_ino
    fetch=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    before=git(root,'rev-parse','HEAD'),(root/'ordinary').read_bytes()
    assert fetch.requires_receipt is False
    assert fetch.fetch('repo','origin','refs/heads/reviewed')==remote['oid']
    assert (git(root,'rev-parse','HEAD'),(root/'ordinary').read_bytes())==before
    assert git(root,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
    pull=ApprovedGitPulls(old.registry,old.sandbox,authority,manager)
    result=pull.pull('repo','origin','refs/heads/reviewed')
    assert result['canonical_published'] is True
    assert git(root,'rev-parse','HEAD')==remote['oid'] and (root/'ordinary').read_text()=='remote\n'
    assert ledger.stat().st_ino==inode
    with sqlite3.connect(ledger) as db:
        rows=db.execute('SELECT nonce,request_sha256,expires_at FROM consumed').fetchall()
    assert len(rows)==2 and all(row[2]==0 for row in rows)


def test_exact_scope_external_receipts_replay_and_policy_drift_refuse(tmp_path,monkeypatch):
    root,old,key,manager,remote=backend(tmp_path,monkeypatch)
    authority=activate(old,operations=['fetch']);fetch=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    request=fetch.prepare('repo','origin','refs/heads/reviewed')
    with pytest.raises(ValueError):claim(authority,request,issue_git_approval(key,request))
    for args in [('repo','other','refs/heads/reviewed','fetch'),('repo','origin','refs/heads/other','fetch'),('repo','origin','refs/heads/reviewed','push'),('repo','origin','refs/heads/reviewed','pull')]:
        with pytest.raises(PermissionError):authority.authorize(*args)
    approval=claim(authority,request);assert_claim(authority,request,approval.nonce)
    with pytest.raises(PermissionError):claim(authority,request,nonce=approval.nonce)
    path=Path(authority._config_dir)/'git-remote-policy.json';path.write_text(path.read_text()+' ')
    with pytest.raises(PermissionError):claim(authority,request)


def test_readonly_and_push_policy_never_enable_workspace_claims(tmp_path,monkeypatch):
    root,old,key,manager,remote=backend(tmp_path,monkeypatch)
    path=Path(old.authority._config_dir)/'git-remote-policy.json';data=json.loads(path.read_text())
    data['grants'][0]['operations']=['push']
    with pytest.raises(PermissionError):workspace_policy_document(data)
    data['authorization_mode']='workspace';path.write_text(json.dumps(data))
    with pytest.raises(PermissionError):load_owner_git_remotes(path.parent,old.registry,old.sandbox.state_dir)
    data['grants'][0]['operations']=['fetch'];path.write_text(json.dumps(data));old.registry.get('repo').writable=False
    with pytest.raises(PermissionError):load_owner_git_remotes(path.parent,old.registry,old.sandbox.state_dir)


def test_unsigned_fetch_interruption_recovers_without_replay_or_ledger_reset(tmp_path,monkeypatch):
    from agentporter.git_fetch_recovery import recover_fetch
    from agentporter.git_fetches import _UPDATE
    from agentporter.resources import ResourceCleanupError
    import agentporter.sandbox.workspace_recovery as recovery
    root,old,key,manager,remote=backend(tmp_path,monkeypatch)
    authority=activate(old,operations=['fetch']);service=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    original=old.sandbox._run_command
    def interrupted(**options):
        result=original(**options)
        if options['argv'][4]==_UPDATE:raise RuntimeError('disposable interruption after tracking')
        return result
    monkeypatch.setattr(old.sandbox,'_run_command',interrupted)
    with pytest.raises(ResourceCleanupError):service.fetch('repo','origin','refs/heads/reviewed')
    monkeypatch.setattr(old.sandbox,'_run_command',original)
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recover_fetch(service,'repo');assert plan['observed_state']=='approved_tip'
    assert recover_fetch(service,'repo',apply=True,expected_plan_sha256=plan['plan_sha256'])['status']=='recovered'
    with sqlite3.connect(authority.verifier.ledger_path) as db:assert db.execute('SELECT count(*) FROM consumed').fetchone()[0]==1


def test_legacy_signed_tracking_evidence_remains_readable_after_explicit_conversion(tmp_path,monkeypatch):
    from agentporter.git_pulls import _consumed_tracking,validate_pull_authorization
    root,service,key,manager,remote=backend(tmp_path,monkeypatch)
    request=service.prepare('repo','origin','refs/heads/reviewed');receipt=issue_git_approval(key,request)
    approval=service.verifier.verify_and_consume(receipt,request)
    evidence=_consumed_tracking(request,approval,service.verifier,service.authority,receipt).to_payload()
    activate(service)
    assert validate_pull_authorization(evidence,registry=service.registry,state_dir=service.sandbox.state_dir,owner_config_dir=service.authority._config_dir)[0]=='refs/remotes/origin/reviewed'


def test_unsigned_owned_job_fetch_is_tracking_only_and_uses_original_admission(tmp_path,monkeypatch,runtime_factory):
    from tests.security.test_nested_repository_scope import configured_nested
    from tests.security.test_worker_git_runtime import wait_output,terminal
    from agentporter.agents.policy import ExecutionPolicy
    root,selected,other,old,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
    authority=activate(old,operations=['fetch','pull']);pull=ApprovedGitPulls(old.registry,old.sandbox,authority,manager)
    fetch=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    manager.approved_git_pulls=pull;manager.approved_git_fetches=fetch
    before=git(selected,'rev-parse','HEAD'),(selected/'ordinary').read_bytes()
    worker="""import time,subprocess
from pathlib import Path
print('READY',flush=True)
for _ in range(1200):
 if Path('/workspace/.fetch-ready').exists():break
 time.sleep(.05)
else:raise RuntimeError('fixture wait')
p=Path('/workspace/acceptance/selected')
def git(*a):return subprocess.check_output(['/usr/bin/git','-C',str(p),'-c','safe.directory='+str(p),*a],text=True).strip()
assert git('rev-parse','HEAD')!=git('rev-parse','refs/remotes/origin/reviewed')
print('FETCH_VISIBLE',flush=True)
"""
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
    try:
        wait_output(manager,job,'READY');tx=manager._job_transactions[job]
        bound=fetch.bind_job('repo',job,'codex_impl',repository='acceptance/selected')
        request=bound.prepare('origin','refs/heads/reviewed');assert request.to_payload()['operation']=='fetch'
        result=bound.fetch('origin','refs/heads/reviewed');assert result['candidate_status']=='fetched'
        assert (git(selected,'rev-parse','HEAD'),(selected/'ordinary').read_bytes())==before
        db=manager._get_db()
        try:assert db.execute('SELECT count(*) FROM job_admissions WHERE job_id=?',(job,)).fetchone()[0]==1
        finally:db.close()
        fd=os.open('.fetch-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(fd)
        assert terminal(manager,job)['status']=='completed',manager.get_output(job)
        assert (git(selected,'rev-parse','HEAD'),(selected/'ordinary').read_bytes())==before
        assert git(selected,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
    finally:
        if job in manager.active_processes:manager.cancel(job)


def test_unsigned_clone_uses_typed_authority_original_job_and_publish(tmp_path,monkeypatch,runtime_factory):
    from tests.security.test_clone_service import setup_clone
    from tests.security.test_worker_git_runtime import terminal
    from agentporter.git_clones import ApprovedGitClones
    root,old,key,manager,tx,oldbound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
    _,broker=oldbound.backend.authority.authorize('repo','origin','refs/heads/main','clone',repository='new-clone')
    authority=activate(oldbound.backend)
    original=authority.authorize
    def offline(*a,**kw):
        grant,_=original(*a,**kw);return grant,broker
    monkeypatch.setattr(authority,'authorize',offline)
    service=ApprovedGitClones(old.registry,old.sandbox,authority,manager)
    bound=service.bind_job('repo',oldbound.job_id,'codex_impl',repository='new-clone')
    request=bound.prepare('origin','refs/heads/main')
    try:
        assert bound.execute(request.digest)['candidate_status']=='cloned'
        fd=os.open('.clone-fixture-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(fd)
        assert terminal(manager,bound.job_id)['status']=='completed',manager.get_output(bound.job_id)
        assert (root/'new-clone/remote-file').is_file()
    finally:
        if bound.job_id in manager.active_processes:manager.cancel(bound.job_id)


def test_unsigned_clone_failure_recovers_exact_original_job_claim(tmp_path,monkeypatch,runtime_factory):
    from tests.security.test_clone_service import setup_clone
    from tests.security.test_worker_git_runtime import terminal
    from tests.security.custody.test_integration import stopped
    from agentporter.git_clones import ApprovedGitClones
    from agentporter.git_clone_recovery import recover_clone
    import agentporter.sandbox.workspace_recovery as recovery
    worker="import time\nfrom pathlib import Path\nprint('READY',flush=True)\nwhile not Path('/workspace/.clone-fail').exists():time.sleep(.02)\nraise SystemExit(7)"
    root,old,key,manager,tx,oldbound,request=setup_clone(tmp_path,monkeypatch,runtime_factory,worker=worker)
    _,broker=oldbound.backend.authority.authorize('repo','origin','refs/heads/main','clone',repository='new-clone')
    authority=activate(oldbound.backend);original=authority.authorize
    def offline(*a,**kw):grant,_=original(*a,**kw);return grant,broker
    monkeypatch.setattr(authority,'authorize',offline)
    bound=ApprovedGitClones(old.registry,old.sandbox,authority,manager).bind_job('repo',oldbound.job_id,'codex_impl',repository='new-clone')
    request=bound.prepare('origin','refs/heads/main')
    assert bound.execute(request.digest)['candidate_status']=='cloned'
    fd=os.open('.clone-fail',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(fd)
    assert terminal(manager,bound.job_id)['status']=='cleanup_failed'
    for fd in (tx._runtime_view_fd,*tx._runtime_namespace_fds):os.close(fd)
    tx._runtime_view_fd=None;tx._runtime_namespace_fds=None;stopped(tx)
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recover_clone(old.registry,manager.state_dir,authority._config_dir,'repo',tx.directory)
    assert plan['consumed'] is True and plan['endpoint']=='before'
    assert recover_clone(old.registry,manager.state_dir,authority._config_dir,'repo',tx.directory,apply=True,expected_plan_sha256=plan['plan_sha256'])['status']=='recovered'
    assert not (root/'new-clone').exists()
    with sqlite3.connect(authority.verifier.ledger_path) as db:assert db.execute('SELECT expires_at FROM consumed').fetchall()==[(0,)]


def test_workspace_claim_rejects_forged_selected_identity_and_kind(tmp_path,monkeypatch):
    from agentporter.git_approvals import GitApprovalRequest
    root,old,key,manager,remote=backend(tmp_path,monkeypatch)
    authority=activate(old,operations=['fetch']);service=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    request=service.prepare('repo','origin','refs/heads/reviewed');data=request.to_payload();data['repository_inode']+=1
    with pytest.raises(PermissionError):claim(authority,GitApprovalRequest.from_payload(data))
    data=request.to_payload();data['operation']='push'
    with pytest.raises(PermissionError):claim(authority,GitApprovalRequest.from_payload(data))
    with sqlite3.connect(authority.verifier.ledger_path) as db:assert db.execute('SELECT count(*) FROM consumed').fetchone()[0]==0


def test_unsigned_up_to_date_fetch_repeats_without_changing_head_or_worktree(tmp_path,monkeypatch):
    root,old,key,manager,remote=backend(tmp_path,monkeypatch)
    authority=activate(old,operations=['fetch'])
    service=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
    before=git(root,'rev-parse','HEAD'),(root/'ordinary').read_bytes()
    assert service.fetch('repo','origin','refs/heads/reviewed')==remote['oid']
    assert service.fetch('repo','origin','refs/heads/reviewed')==remote['oid']
    assert (git(root,'rev-parse','HEAD'),(root/'ordinary').read_bytes())==before
    assert git(root,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
    with sqlite3.connect(authority.verifier.ledger_path) as db:
        assert db.execute('SELECT count(*) FROM consumed WHERE expires_at=0').fetchone()[0]==2
