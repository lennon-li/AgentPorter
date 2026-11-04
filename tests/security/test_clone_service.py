import json,time,os
from pathlib import Path
import pytest
from agentporter.git_clones import ApprovedGitClones
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_clone_authority import validate_clone_authorization
from agentporter.git_approvals import GitApprovalVerifier,issue_git_approval
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.agents.policy import ExecutionPolicy
from tests.security.test_nested_repository_scope import configured_nested,metadata
from tests.security.test_development_runtime import runtime_factory
from tests.security.test_worker_git_runtime import wait_output,terminal
from tests.security.test_clone_preparation import source_pack

WORKER='''import time,subprocess
from pathlib import Path
print('READY',flush=True)
p=Path('/workspace/new-clone')
for i in range(1000):
 if Path('/workspace/.clone-fixture-ready').exists():break
 time.sleep(.05)
else:raise RuntimeError('clone did not appear in actual merged view')
(p/'continued').write_text('continued clone edit\\n')
for args in (['add','continued'],['commit','-qm','continued clone commit']):
 subprocess.run(['/usr/bin/git','-C',str(p),'-c','safe.directory='+str(p),'-c','user.name=Worker','-c','user.email=worker@example.invalid']+args,check=True)
print('CONTINUED',flush=True)
'''
@pytest.mark.parametrize('algorithm',['sha1','sha256'])
@pytest.mark.parametrize('existing',[False,True])
@pytest.mark.parametrize('outer_git',[True,False])
def test_live_worker_sees_consumed_clone_then_commits_and_publishes(tmp_path,monkeypatch,runtime_factory,outer_git,algorithm,existing):
 original=WorkspaceTransaction.__init__
 def authorized(self,*a,**kw):kw['allow_git_birth']=True;return original(self,*a,**kw)
 monkeypatch.setattr(WorkspaceTransaction,'__init__',authorized)
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git)
 if existing:(root/'new-clone').mkdir()
 before=metadata(root/'.git') if outer_git else None;otherbefore=metadata(other)
 (tmp_path/'clone-source').mkdir()
 oid,pack,broker=source_pack(tmp_path/'clone-source',algorithm)
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
 wait_output(manager,job,'READY');tx=manager._job_transactions[job]
 assert tx._runtime_view_fd is not None
 db=manager._get_db()
 try:token=db.execute('SELECT token FROM job_admissions WHERE job_id=?',(job,)).fetchone()[0]
 finally:db.close()
 info=tx.directory.stat();context={'job_id':job,'agent':'codex_impl','admission_token':token,'transaction_directory':str(tx.directory),'transaction_device':info.st_dev,'transaction_inode':info.st_ino}
 policy_path=Path(service.authority._config_dir)/'git-remote-policy.json'
 raw=json.loads(policy_path.read_text());grant=dict(raw['grants'][0]);grant.update(repository='new-clone',ref='refs/heads/main',operations=['clone'],url='https://example.com/owner/repo.git');raw['grants'].append(grant)
 policy_path.write_text(json.dumps(raw))
 authority=load_owner_git_remotes(policy_path.parent,service.registry,service.sandbox.state_dir)
 backend=ApprovedGitClones(service.registry,service.sandbox,authority,manager)
 authorize=authority.authorize
 def offline(*args,**kwargs):
  grant,_=authorize(*args,**kwargs)
  return grant,broker
 monkeypatch.setattr(authority,'authorize',offline)
 bound=backend.bind_job('repo',job,'codex_impl',repository='new-clone')
 request=bound.prepare('origin','refs/heads/main')
 run=service.sandbox._run_command;proofs=[]
 def inspect(**options):
  assert options['network_access']is False
  result=run(**options)
  for line in result['stdout'].splitlines():
   if line.startswith('AP_RUNTIME_PROOF '):proofs.append(json.loads(line.removeprefix('AP_RUNTIME_PROOF ')))
  return result
 monkeypatch.setattr(service.sandbox,'_run_command',inspect)
 outcome=bound.execute(request.digest,issue_git_approval(key,request));assert outcome['candidate_status']=='cloned'
 ready=os.open('.clone-fixture-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(ready)
 assert len(proofs)==1
 proof=proofs[0]
 assert proof['pid']==1 and proof['NoNewPrivs']=='1' and proof['host_home_visible']is False
 assert set(proof['net_devices'])<= {'lo'}
 assert all(int(proof[name],16)==0 for name in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'))
 status=terminal(manager,job);assert status['status']=='completed',manager.get_output(job)
 assert (root/'new-clone/continued').read_text()=='continued clone edit\n'
 assert metadata(other)==otherbefore
 if outer_git:assert metadata(root/'.git')==before


def setup_clone(tmp_path,monkeypatch,runtime_factory,*,outer_git=True,algorithm="sha1",existing=False,worker=WORKER):
 original=WorkspaceTransaction.__init__
 def authorized(self,*a,**kw):kw['allow_git_birth']=True;return original(self,*a,**kw)
 monkeypatch.setattr(WorkspaceTransaction,'__init__',authorized)
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git)
 if existing:(root/'new-clone').mkdir()
 before=metadata(root/'.git') if outer_git else None;otherbefore=metadata(other)
 (tmp_path/'clone-source').mkdir()
 oid,pack,broker=source_pack(tmp_path/'clone-source',algorithm)
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
 wait_output(manager,job,'READY');tx=manager._job_transactions[job]
 assert tx._runtime_view_fd is not None
 db=manager._get_db()
 try:token=db.execute('SELECT token FROM job_admissions WHERE job_id=?',(job,)).fetchone()[0]
 finally:db.close()
 info=tx.directory.stat();context={'job_id':job,'agent':'codex_impl','admission_token':token,'transaction_directory':str(tx.directory),'transaction_device':info.st_dev,'transaction_inode':info.st_ino}
 policy_path=Path(service.authority._config_dir)/'git-remote-policy.json'
 raw=json.loads(policy_path.read_text());grant=dict(raw['grants'][0]);grant.update(repository='new-clone',ref='refs/heads/main',operations=['clone'],url='https://example.com/owner/repo.git');raw['grants'].append(grant)
 policy_path.write_text(json.dumps(raw))
 authority=load_owner_git_remotes(policy_path.parent,service.registry,service.sandbox.state_dir)
 backend=ApprovedGitClones(service.registry,service.sandbox,authority,manager)
 authorize=authority.authorize
 def offline(*args,**kwargs):
  grant,_=authorize(*args,**kwargs)
  return grant,broker
 monkeypatch.setattr(authority,'authorize',offline)
 bound=backend.bind_job('repo',job,'codex_impl',repository='new-clone')
 request=bound.prepare('origin','refs/heads/main')
 return root,service,key,manager,tx,bound,request


@pytest.mark.parametrize('bad',['expired','future','spent','invalid'])
def test_bad_preclaim_receipts_leave_no_guard_or_binding(tmp_path,monkeypatch,runtime_factory,bad):
 from agentporter.workspaces.leases import workspace_key
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 receipt=issue_git_approval(key,request,now=1) if bad=='expired' else issue_git_approval(key,request,now=int(time.time())+1000) if bad=='future' else issue_git_approval(key,request)
 if bad=='spent':bound.backend.verifier.verify_and_consume(receipt,request)
 if bad=='invalid':receipt=receipt.replace('"signature":"','"signature":"A',1)
 try:
  with pytest.raises(PermissionError):bound.execute(request.digest,receipt)
  assert not getattr(tx,'_private_clone_pending',False)
  assert not (tx.directory/'clone-intent.json').exists()
  assert not (tx.directory.parent/(workspace_key(root.stat())+'.git-pending.json')).exists()
  db=manager._get_db()
  try:assert db.execute('SELECT count(*) FROM git_admissions').fetchone()[0]==0
  finally:db.close()
 finally:manager.cancel(request.to_payload()['parameters']['job_context']['job_id'])


def test_consumed_private_failure_recovers_original_admission(tmp_path,monkeypatch,runtime_factory):
 import agentporter.git_clones as clones
 from agentporter.git_clone_recovery import recover_clone
 from agentporter.sandbox import workspace_recovery
 from agentporter.resources import ResourceCleanupError
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 original=clones.consume_clone
 def failed(*args,**kwargs):original(*args,**kwargs);raise RuntimeError('injected after private materialization')
 monkeypatch.setattr(clones,'consume_clone',failed)
 with pytest.raises(ResourceCleanupError):bound.execute(request.digest,issue_git_approval(key,request))
 job=request.to_payload()['parameters']['job_context']['job_id']
 marker=os.open('.clone-fixture-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(marker)
 assert terminal(manager,job)['status']=='cleanup_failed'
 tx.close()
 if getattr(manager,'_supervisor_lock',None) is not None:os.close(manager._supervisor_lock);manager._supervisor_lock=None
 monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
 plan=recover_clone(bound.backend.registry,manager.state_dir,bound.backend.authority._config_dir,'repo',tx.directory)
 assert plan['endpoint']=='before' and plan['consumed']is True
 result=recover_clone(bound.backend.registry,manager.state_dir,bound.backend.authority._config_dir,'repo',tx.directory,apply=True,expected_plan_sha256=plan['plan_sha256'])
 assert result['status']=='recovered' and not (root/'new-clone').exists()
 db=manager._get_db()
 try:
  assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0
  assert db.execute('SELECT status FROM git_admissions').fetchone()[0]=='resolved'
 finally:db.close()

@pytest.mark.parametrize('boundary',['prepared','intent','rename_after','guard_record','claim_before','claim_after'])
def test_claim_boundaries_preserve_exact_claim_and_parent_admission(tmp_path,monkeypatch,runtime_factory,boundary):
 import agentporter.git_clones as clones
 from agentporter.resources import ResourceCleanupError
 from agentporter.workspaces.leases import workspace_key
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 receipt=issue_git_approval(key,request);nonce=json.loads(receipt)['claims']['nonce']
 if boundary in {'prepared','intent','guard_record'}:
  write=clones._write_private
  target={'prepared':'clone-guard-prepared.json','intent':'clone-intent.json','guard_record':'clone-guard-record.json'}[boundary]
  def failed(path,data):
   write(path,data)
   if path.name==target:raise OSError('injected after durable '+target)
  monkeypatch.setattr(clones,'_write_private',failed)
 elif boundary=='rename_after':
  rename=clones._rename_noreplace
  def failed(*args):rename(*args);raise OSError('injected after guard rename')
  monkeypatch.setattr(clones,'_rename_noreplace',failed)
 else:
  verify=bound.backend.verifier.verify_and_consume
  def failed(*args,**kw):
   if boundary=='claim_after':verify(*args,**kw)
   raise PermissionError('injected at claim boundary')
  monkeypatch.setattr(bound.backend.verifier,'verify_and_consume',failed)
 try:
  with pytest.raises((PermissionError,ResourceCleanupError)):bound.execute(request.digest,receipt)
  consumed=boundary=='claim_after'
  assert bool(getattr(tx,'_private_clone_pending',False))==consumed
  guard=tx.directory.parent/(workspace_key(root.stat())+'.git-pending.json')
  assert guard.exists()==consumed
  assert not (root/'new-clone').exists()
  db=manager._get_db()
  try:
   assert db.execute('SELECT count(*) FROM job_admissions WHERE job_id=?',(bound.job_id,)).fetchone()[0]==1
   binding=db.execute('SELECT status FROM git_admissions').fetchone()
   if consumed:assert binding[0]=='active'
   elif binding is not None:assert binding[0]=='resolved'
  finally:db.close()
 finally:manager.cancel(bound.job_id)

@pytest.mark.parametrize('boundary',['guard_renamed','claimed','repository_published','outcome_durable','guard_captured','repository_published:owner','repository_published:equalbyte','repository_published:recoverydeath'])
def test_real_supervisor_death_recovers_exact_clone_outcome(tmp_path,monkeypatch,runtime_factory,boundary):
 from agentporter.git_clone_recovery import recover_clone
 from agentporter.workspaces.registry import WorkspaceRegistry
 from agentporter.sandbox import workspace_recovery
 import agentporter.git_clones as clones
 import agentporter.sandbox.workspace_directories as directories
 change=boundary.split(':',1)[1] if ':'in boundary else None
 boundary=boundary.split(':',1)[0]
 report_path=tmp_path/'death-report.json'
 child=os.fork()
 if child==0:
  try:
   root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory,existing=True)
   process=manager.active_processes[bound.job_id]
   report_path.write_text(json.dumps({'root':str(root),'state':str(manager.state_dir),'config':str(bound.backend.authority._config_dir),'transaction':str(tx.directory),'job':bound.job_id,'pid':process.pid}))
   receipt=issue_git_approval(key,request)
   if boundary=='guard_renamed':
    original=clones._rename_noreplace
    def die(*args):original(*args);os._exit(77)
    clones._rename_noreplace=die
   elif boundary=='claimed':
    original=bound.backend.verifier.verify_and_consume
    def die(*args,**kw):original(*args,**kw);os._exit(77)
    bound.backend.verifier.verify_and_consume=die
   elif boundary=='repository_published':
    original=directories.publish_directory
    def die(*args,**kw):original(*args,**kw);os._exit(77)
    directories.publish_directory=die
   elif boundary=='outcome_durable':
    def die(*args):os._exit(77)
    clones.ClonePublicationIntent.finish=die
   else:
    original=clones.capture_workspace_entry
    def die(*args,**kw):original(*args,**kw);os._exit(77)
    clones.capture_workspace_entry=die
   bound.execute(request.digest,receipt)
   ready=os.open('.clone-fixture-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(ready)
   terminal(manager,bound.job_id)
   os._exit(78)
  except BaseException:
   import traceback
   traceback.print_exc();os._exit(79)
 _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==77
 report=json.loads(report_path.read_text());root=Path(report['root']);state=Path(report['state'])
 # Kernel die-with-parent kills the real confined provider; do not inspect a
 # live overlay. A zombie is quiescent and may await container PID1 reaping.
 for _ in range(100):
  try:proc=Path('/proc/'+str(report['pid'])+'/stat').read_text();dead=proc.split(') ',1)[1].startswith('Z')
  except FileNotFoundError:dead=True
  if dead:break
  time.sleep(.05)
 assert dead,'owned confined process survived supervisor death'
 registry=WorkspaceRegistry({'repo':{'path':str(root),'writable':True,'allow_git':True}})
 import sqlite3
 with sqlite3.connect(state/'jobs.db') as db:db.execute("UPDATE jobs SET status='cleanup_failed' WHERE job_id=?",(report['job'],))
 monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
 plan=recover_clone(registry,state,report['config'],'repo',report['transaction'])
 assert plan['consumed']==(boundary!='guard_renamed')
 if change in {'owner','equalbyte'}:
  if change=='owner':
   owner=root/'new-clone/late-owner';owner.write_text('late owner content\n')
  else:
   owner=root/'new-clone/.git/HEAD';data=owner.read_bytes();replacement=tmp_path/'owner-head';replacement.write_bytes(data);os.replace(replacement,owner)
  before_owner=(owner.stat().st_ino,owner.read_bytes())
  changed=recover_clone(registry,state,report['config'],'repo',report['transaction'])
  with pytest.raises(PermissionError):recover_clone(registry,state,report['config'],'repo',report['transaction'],apply=True,expected_plan_sha256=changed['plan_sha256'])
  assert (owner.stat().st_ino,owner.read_bytes())==before_owner
  return
 if change=='recoverydeath':
  recovery_child=os.fork()
  if recovery_child==0:
   original=directories.rollback_directory
   def die(*args,**kw):original(*args,**kw);os._exit(88)
   directories.rollback_directory=die
   recover_clone(registry,state,report['config'],'repo',report['transaction'],apply=True,expected_plan_sha256=plan['plan_sha256'])
   os._exit(89)
  _,deadstatus=os.waitpid(recovery_child,0);assert os.waitstatus_to_exitcode(deadstatus)==88
  plan=recover_clone(registry,state,report['config'],'repo',report['transaction'])
 result=recover_clone(registry,state,report['config'],'repo',report['transaction'],apply=True,expected_plan_sha256=plan['plan_sha256'])
 assert result['status']=='recovered'
 assert (root/'new-clone').is_dir() and not list((root/'new-clone').iterdir())
 with sqlite3.connect(state/'jobs.db') as db:
  assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0
  assert db.execute('SELECT status FROM git_admissions').fetchone()[0]=='resolved'


def test_later_owner_row_refuses_recovery_before_raw_guard_retirement(tmp_path,monkeypatch,runtime_factory):
 import sqlite3
 import agentporter.git_clones as clones
 import agentporter.git_clone_recovery as recovery
 from agentporter.sandbox import workspace_recovery
 from agentporter.resources import ResourceCleanupError
 from agentporter.sandbox.recovery_guards import _guard_record
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 original=clones.consume_clone
 def failed(*args,**kw):original(*args,**kw);raise RuntimeError('injected after consumed private clone')
 monkeypatch.setattr(clones,'consume_clone',failed)
 with pytest.raises(ResourceCleanupError):bound.execute(request.digest,issue_git_approval(key,request))
 marker=os.open('.clone-fixture-ready',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=tx._runtime_view_fd);os.close(marker)
 assert terminal(manager,bound.job_id)['status']=='cleanup_failed';tx.close()
 monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
 state=manager.state_dir;config=bound.backend.authority._config_dir;registry=bound.backend.registry
 plan=recovery.recover_clone(registry,state,config,'repo',tx.directory)
 intent=json.loads((tx.directory/'clone-intent.json').read_text());guard=Path(intent['guard']);guard_before=_guard_record(guard)
 token=request.to_payload()['parameters']['job_context']['admission_token'];open_database=recovery._recovery_database
 class Connection:
  def __init__(self):self.db=open_database(state,write=True)
  def execute(self,sql,args=()):
   if sql=='BEGIN IMMEDIATE':
    with sqlite3.connect(state/'jobs.db') as owner:owner.execute("UPDATE jobs SET workspace_id='owner-other',agent='codex_review',status='cancelled' WHERE job_id=?",(bound.job_id,))
   return self.db.execute(sql,args)
  def rollback(self):self.db.rollback()
  def close(self):self.db.close()
 def connect(*args,**kw):return Connection() if kw.get('write') else open_database(*args,**kw)
 monkeypatch.setattr(recovery,'_recovery_database',connect)
 with pytest.raises(PermissionError):recovery.recover_clone(registry,state,config,'repo',tx.directory,apply=True,expected_plan_sha256=plan['plan_sha256'])
 assert _guard_record(guard)==guard_before
 with sqlite3.connect(state/'jobs.db') as db:
  assert db.execute('SELECT workspace_id,agent,status FROM jobs WHERE job_id=?',(bound.job_id,)).fetchone()==('owner-other','codex_review','cancelled')
  assert db.execute('SELECT job_id FROM job_admissions WHERE token=?',(token,)).fetchone()==(bound.job_id,)
  assert db.execute('SELECT status FROM git_admissions WHERE token=?',(token,)).fetchone()==('active',)
