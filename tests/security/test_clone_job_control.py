"""Actual typed worker/owner control and postbirth operations, no constructor bypass."""
import json,subprocess
from pathlib import Path
import pytest,yaml
from agentporter import git_remote_policy
from agentporter.git_approvals import GitApprovalRequest,issue_git_approval
from agentporter.git_clones import ApprovedGitClones
from agentporter.git_fetches import ApprovedGitFetches
from agentporter.git_pulls import ApprovedGitPulls
from agentporter.git_smart_http import Advertisement
from agentporter.agents.policy import ExecutionPolicy
from agentporter.tools.git import create_git_tools
from tests.security.test_nested_repository_scope import configured_nested,metadata,browser_receipt_proof
from tests.security.test_development_runtime import runtime_factory
from tests.security.test_worker_git_runtime import wait_output,terminal
from tests.security.test_clone_preparation import source_pack
from tests.security.test_approved_git_pull import git
from tests.security.test_git_admission import count


def configured_clone(tmp_path,monkeypatch,runtime_factory,*,outer_git=True,algorithm='sha1',existing=False):
 root,selected,other,old,key,manager,_=configured_nested(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git,algorithm=algorithm,dual=True)
 if existing:(root/'new-clone').mkdir()
 remote_base=tmp_path/'clone-source';remote_base.mkdir()
 oid,pack,_=source_pack(remote_base,algorithm)
 remote={'oid':oid,'pack':pack,'path':remote_base/'remote','algorithm':algorithm}
 class Broker:
  def __init__(self,*args,**kwargs):pass
  def discover(self,service):
   assert service=='git-upload-pack'
   return Advertisement({'refs/heads/main':remote['oid']},frozenset(),algorithm)
  def fetch_pack(self,ref,expected):
   assert (ref,expected)==('refs/heads/main',remote['oid'])
   return remote['pack']
 monkeypatch.setattr(git_remote_policy,'ScopedGitHTTP',Broker)
 policy_path=Path(old.authority._config_dir)/'git-remote-policy.json'
 policy=json.loads(policy_path.read_text())
 policy['grants'].append({**policy['grants'][0],'repository':'new-clone','ref':'refs/heads/main','operations':['clone','fetch','pull']})
 policy_path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(policy_path.parent,old.registry,old.sandbox.state_dir)
 pulls=ApprovedGitPulls(old.registry,old.sandbox,authority,manager)
 clones=ApprovedGitClones(old.registry,old.sandbox,authority,manager)
 fetches=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
 manager.approved_git_pulls=pulls;manager.approved_git_clones=clones
 return root,selected,other,pulls,key,manager,remote,fetches


CLONE_WORKER='''import json,subprocess
from pathlib import Path
client=['/usr/bin/python3','-I','-S','/opt/agentporter/worker-git.py']
scope={'repository':'new-clone','remote':'origin','ref':'refs/heads/main','branch':'refs/heads/main'}
def call(op,**extra):
 p=subprocess.run(client,input=json.dumps(dict(scope,op=op,**extra)),capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
p=call('clone_prepare');assert p['status']=='prepared',p
assert p['operation']=='clone' and p['request']['operation']=='clone'
print(json.dumps(p),flush=True)
r=call('wait_clone',request_sha256=p['request_sha256']);assert r['status']=='completed',r
assert r['operation']=='clone' and r['outcome']['candidate_status']=='cloned',r
root=Path('/workspace/new-clone');assert (root/'remote-file').read_text()=='remote approved fixture\\n'
(root/'continued').write_text('continued clone edit\\n')
for args in (['add','continued'],['commit','-qm','continued clone commit']):
 subprocess.run(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'-c','user.name=Worker','-c','user.email=worker@example.invalid']+args,check=True)
# Unpublished birth has no canonical lower/history; later operations use a new job.
payload={'repository':'new-clone','remote':'origin','ref':'refs/heads/main','mode':'ff-only','op':'prepare'}
p=subprocess.run(client,input=json.dumps(payload),capture_output=True,text=True)
assert p.returncode==0 and json.loads(p.stdout)['code']=='backend_refused',p.stdout+p.stderr
print('CLONE_CONTINUED',flush=True)
'''

PULL_WORKER='''import json,subprocess
from pathlib import Path
client=['/usr/bin/python3','-I','-S','/opt/agentporter/worker-git.py']
scope={'repository':'new-clone','remote':'origin','ref':'refs/heads/main','mode':'rebase'}
def call(op,**extra):
 p=subprocess.run(client,input=json.dumps(dict(scope,op=op,**extra)),capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
p=call('prepare');assert p['status']=='prepared',p
print(json.dumps(p),flush=True)
r=call('wait',request_sha256=p['request_sha256']);assert r['status']=='completed' and r['outcome']['candidate_status']=='integrated',r
root=Path('/workspace/new-clone')
assert (root/'remote-file').read_text()=='remote advanced\\n'
assert (root/'continued').read_text()=='continued clone edit\\n'
(root/'after-pull').write_text('postbirth pull edit\\n')
for args in (['add','after-pull'],['commit','-qm','postbirth pull commit']):
 subprocess.run(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'-c','user.name=Worker','-c','user.email=worker@example.invalid']+args,check=True)
print('PULL_CONTINUED',flush=True)
'''


@pytest.mark.parametrize('algorithm',['sha1','sha256'])
@pytest.mark.parametrize('outer_git',[True,False])
def test_actual_clone_control_then_new_job_fetch_pull_without_service_restart(tmp_path,monkeypatch,runtime_factory,algorithm,outer_git):
 root,selected,other,pulls,key,manager,remote,fetches=configured_clone(tmp_path,monkeypatch,runtime_factory,algorithm=algorithm,outer_git=outer_git,existing=not outer_git)
 owner=metadata(root/'.git') if outer_git else None;selected_before=metadata(selected);other_before=metadata(other)
 owner_bytes=(root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes()
 tools=create_git_tools(pulls.registry,pulls.sandbox,approved_pulls=pulls,approved_fetches=fetches,job_manager=manager)
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',CLONE_WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
 prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0]);request=GitApprovalRequest.from_payload(prepared['request'])
 tx=manager._job_transactions[job]
 assert tx._allow_git_birth is True and count(manager)==1
 assert request.to_payload()['repository_path']==str(root)
 assert request.to_payload()['parameters']['repository']=='new-clone'
 browser_receipt_proof(tmp_path,request)
 with pytest.raises(ValueError):tools.git_pull('repo',branch='refs/heads/main',job_id=job,operation='clone',mode='ff-only',prepare_only=True)
 with pytest.raises(ValueError):tools.git_pull('repo',branch='refs/heads/main',job_id=job,operation='pull',local_branch='refs/heads/main',prepare_only=True)
 owner_request=tools.git_pull('repo',branch='refs/heads/main',job_id=job,operation='clone',prepare_only=True)
 assert owner_request['request_sha256']==request.digest
 wrong=tools.git_pull('repo',branch='refs/heads/main',job_id=job,prepare_only=True)
 assert wrong['status']=='denied'
 completed=tools.git_pull('repo',branch='refs/heads/main',job_id=job,operation='clone',request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
 assert completed['status']=='completed' and completed['operation']=='clone',completed
 assert terminal(manager,job)['status']=='completed',manager.get_output(job)
 target=root/'new-clone'
 assert git(target,'show','-s','--format=%s')=='continued clone commit'
 assert git(target,'config','remote.origin.url')=='https://example.com/owner/repo.git'
 assert git(target,'rev-parse','refs/remotes/origin/main')==remote['oid']
 assert count(manager)==0 and tx._runtime_view_fd is None
 # Advance the offline remote, leaving the same manager/authority/service configuration.
 (remote['path']/'remote-file').write_text('remote advanced\n');git(remote['path'],'add','remote-file');git(remote['path'],'commit','-qm','remote advance')
 remote['oid']=git(remote['path'],'rev-parse','HEAD')
 remote['pack']=subprocess.run(['/usr/bin/git','pack-objects','--stdout','--revs'],cwd=remote['path'],input=(remote['oid']+'\n').encode(),capture_output=True,check=True).stdout
 fetch_request=GitApprovalRequest.from_payload(json.loads(tools.git_fetch('repo',branch='refs/heads/main',repository='new-clone',prepare_only=True))['request'])
 assert fetch_request.to_payload()['operation']=='fetch'
 assert tools.git_fetch('repo',branch='refs/heads/main',repository='new-clone',approval_receipt=issue_git_approval(key,fetch_request))==remote['oid']
 next_job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',PULL_WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
 prepared=json.loads(wait_output(manager,next_job,'"status": "prepared"')['stdout'].splitlines()[0]);pull_request=GitApprovalRequest.from_payload(prepared['request'])
 assert pull_request.to_payload()['operation']=='pull' and pull_request.to_payload()['repository_path']==str(target)
 result=tools.git_pull('repo',branch='refs/heads/main',mode='rebase',job_id=next_job,request_sha256=pull_request.digest,approval_receipt=issue_git_approval(key,pull_request))
 assert result['status']=='completed',result
 assert terminal(manager,next_job)['status']=='completed',manager.get_output(next_job)
 assert (target/'after-pull').read_text()=='postbirth pull edit\n'
 assert manager.approved_git_pulls is pulls and count(manager)==0
 assert metadata(selected)==selected_before and metadata(other)==other_before
 if outer_git:assert metadata(root/'.git')==owner
 assert ((root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes())==owner_bytes


def test_clone_actual_gateway_requires_both_permissions_and_typed_receipt(tmp_path,monkeypatch,runtime_factory,temp_config):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from starlette.testclient import TestClient
    from agentporter import server
    from agentporter.config import Config
    from agentporter.agents import production_relay
    root,selected,other,service,key,manager,remote,fetches=configured_clone(tmp_path,monkeypatch,runtime_factory,algorithm='sha256',existing=True)
    root_before=metadata(root/'.git');other_before=metadata(other)
    owner_before=(root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes()
    runtime=manager.development_runtime
    monkeypatch.setattr(runtime,'require_production_egress',lambda agent=None:frozenset({'codex_impl'}))
    token='r'*43
    for config_dir in (temp_config.config_dir,):
        (config_dir/'delegation-relay.key').write_text(token);(config_dir/'delegation-relay.key').chmod(0o600)
        for name in ('delegation-relay-scope.yaml','delegation-relay-write-scope.yaml'):
            path=config_dir/name;path.write_text(yaml.safe_dump({'version':1,'workspaces':{'repo':str(root)}}));path.chmod(0o600)
    temp_config.sandbox.workspace_transactions=True
    tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
    def dispatch(**arguments):
        job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
            cmd=['/usr/bin/python3','-c',CLONE_WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
        return {'job_id':job,'status':'running'}
    receiver_policy=SimpleNamespace(scopes={'repo':frozenset({'git_clone'})},internal_key=None)
    context={'client_policy':receiver_policy,'registry':service.registry,
        'agent_broker':SimpleNamespace(development_runtime=runtime),'delegation_relay_client':None,
        'job_manager':manager,'tools':{'dispatch_agent':dispatch,'git_pull':tools.git_pull,
            'job_status':manager.get_status,'job_output':manager.get_output,'job_result':manager.get_result}}
    original_build=server.build_mcp_server
    monkeypatch.setattr(server,'build_mcp_server',lambda config:(server.MCPServer('native-pull-worker'),context)
        if config is temp_config else original_build(config))
    worker_app=server.create_asgi_app(temp_config)
    gateway=Config(config_dir=tmp_path/'gateway-config',state_dir=tmp_path/'gateway-state',cache_dir=tmp_path/'gateway-cache')
    gateway.workspaces={'repo':{'path':str(root),'writable':True,'allow_agent_dispatch':True,'allow_execute':True,'allow_git':True}}
    gateway.security.allowed_hosts=['testserver']
    for name,data in (
        ('delegation-relay-write-scope.yaml',{'version':1,'workspaces':{'repo':str(root)}}),
        ('public-client-policy.yaml',{'version':1,'workspaces':{'repo':{'path':str(root),
            'operations':['read','write','dispatch','dispatch_write','git_pull','git_clone']}}})):
        path=gateway.config_dir/name;path.write_text(yaml.safe_dump(data));path.chmod(0o600)
    path=gateway.config_dir/'delegation-relay.key';path.write_text(token);path.chmod(0o600)
    monkeypatch.setattr(server,'relay_upstream_workspaces',lambda path:frozenset({'repo'}) if path==gateway.config_dir else frozenset())
    async def issue(body,headers):
        transport=httpx.ASGITransport(app=worker_app,client=('127.0.0.1',12345))
        async with httpx.AsyncClient(transport=transport,base_url='http://127.0.0.1:8876') as client:
            return await client.post('/internal/delegation/v1',headers=headers,content=body)
    class Connection:
        def __init__(self,host,port,timeout):assert host=='127.0.0.1' and port==8876
        def request(self,method,path,body,headers):self.body,self.headers=body,headers
        def getresponse(self):
            response=asyncio.run(issue(self.body,self.headers))
            return SimpleNamespace(status=response.status_code,read=lambda limit:response.content[:limit])
        def close(self):pass
    monkeypatch.setattr(production_relay.http.client,'HTTPConnection',Connection)
    with TestClient(server.create_asgi_app(gateway),client=('127.0.0.1',12345)) as client:
        headers={'X-AgentPorter-Key':gateway.api_key}
        response=client.post('/api/v1/workspaces/repo/agents/dispatch',headers=headers,
            json={'agent':'codex_impl','task':'native signed pull then edit and commit','read_only':False})
        assert response.status_code==200,response.text
        public=response.json()['job_id'];assert public.startswith('rjob_')
        ledger=production_relay.RelayLedger(gateway.state_dir)
        native=ledger.get_request(public.removeprefix('rjob_'))[0]
        prepared=json.loads(wait_output(manager,native,'"status": "prepared"')['stdout'].splitlines()[0])
        request=GitApprovalRequest.from_payload(prepared['request'])
        assert request.to_payload()['parameters']['job_context']['job_id']==native
        payload={'job_id':public,'remote':'origin','branch':'refs/heads/main','mode':None,'operation':'clone','local_branch':'refs/heads/main','prepare_only':True}
        browser_receipt_proof(tmp_path,request)
        receiver_policy.scopes={'repo':frozenset({'git_pull'})}
        refused=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
        assert refused.status_code==403,refused.text
        receiver_policy.scopes={'repo':frozenset({'git_clone'})}
        response=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
        assert response.status_code==200 and response.json()['request_sha256']==request.digest,response.text
        # A valid actual worker ID must not bypass the gateway's public alias ownership.
        denied=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json={**payload,'job_id':native})
        assert denied.status_code==403,denied.text
        payload.update(prepare_only=False,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
        crossed={**payload,'operation':'pull','mode':'ff-only'};crossed.pop('local_branch')
        refused=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=crossed)
        assert refused.status_code==200 and refused.json()['status']=='denied',refused.text
        response=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
        assert response.status_code==200 and response.json()['status']=='completed' and response.json()['operation']=='clone',response.text
        assert terminal(manager,native)['status']=='completed',manager.get_output(native)
        target=root/'new-clone'
        assert (target/'continued').read_text()=='continued clone edit\n'
        assert metadata(root/'.git')==root_before and metadata(other)==other_before
        assert ((root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes())==owner_before
        assert git(target,'rev-parse','HEAD^')==remote['oid']
        assert git(target,'rev-parse','refs/remotes/origin/main')==remote['oid']
        assert count(manager)==0

@pytest.mark.parametrize('outer_git',[True,False])
@pytest.mark.parametrize('allowed',[True,False])
def test_real_local_init_caller_uses_authoritative_workspace_git_birth_gate(tmp_path,monkeypatch,runtime_factory,outer_git,allowed):
 root,selected,other,service,key,manager,_=configured_nested(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git)
 service.registry.get('repo').allow_git=allowed
 if not allowed:manager.approved_git_pulls=None
 before=metadata(root)
 program='''import subprocess,time
from pathlib import Path
p=Path('/workspace/local-new')
subprocess.run(['/usr/bin/git','init','-q','--template=','--initial-branch=main',str(p)],check=True)
(p/'local-file').write_text('local authorized init\\n')
for args in (['add','local-file'],['commit','-qm','local init commit']):
 subprocess.run(['/usr/bin/git','-C',str(p),'-c','safe.directory='+str(p),'-c','user.name=Worker','-c','user.email=worker@example.invalid']+args,check=True)
print('LOCAL_INIT_PRIVATE',flush=True);time.sleep(.5)
'''
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_research',cmd=['/usr/bin/python3','-c',program],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=30)
 wait_output(manager,job,'LOCAL_INIT_PRIVATE');tx=manager._job_transactions[job]
 assert tx._allow_git_birth is allowed and not (root/'local-new').exists()
 status=terminal(manager,job)
 assert status['status']==('completed' if allowed else 'failed'),manager.get_output(job)
 after=metadata(root)
 assert all(after[name]==value for name,value in before.items())
 if allowed:
  assert git(root/'local-new','show','-s','--format=%s')=='local init commit'
  assert (root/'local-new/local-file').read_text()=='local authorized init\n'
  assert all(name.startswith('local-new/') for name in set(after)-set(before))
 else:assert after==before and not (root/'local-new').exists()
 assert count(manager)==0


def test_public_clone_permission_is_independent_from_pull(tmp_path,monkeypatch,runtime_factory):
 from agentporter.client_policy import PublicClientPolicy,PRINCIPAL
 root,_,_,service,_,manager,_,_=configured_clone(tmp_path,monkeypatch,runtime_factory)
 config=tmp_path/'explicit-public-config';config.mkdir(mode=0o700)
 path=config/'public-client-policy.yaml';path.write_text(yaml.safe_dump({'version':1,'workspaces':{'repo':{'path':str(root),'operations':['git_pull']}}}));path.chmod(0o600)
 policy=PublicClientPolicy(config,manager.state_dir,service.registry,required=True)
 token=PRINCIPAL.set('public')
 try:
  policy.check('git_pull',{'workspace_id':'repo','operation':'pull'})
  with pytest.raises(PermissionError):policy.check('git_pull',{'workspace_id':'repo','operation':'clone'})
 finally:PRINCIPAL.reset(token)


def test_native_workspace_rollback_reports_still_pending_clone_reconciliation(tmp_path,monkeypatch,runtime_factory):
 import agentporter.git_clone_recovery as recovery
 from tests.security.test_clone_service import test_real_supervisor_death_recovers_exact_clone_outcome
 original=recovery.recover_workspace;reports=[]
 def observe(*args,**kwargs):
  result=original(*args,**kwargs)
  if kwargs.get('apply'):reports.append(result)
  return result
 monkeypatch.setattr(recovery,'recover_workspace',observe)
 test_real_supervisor_death_recovers_exact_clone_outcome(tmp_path,monkeypatch,runtime_factory,'repository_published')
 assert len(reports)==1
 assert reports[0]['clone_recovery_required'] is True and reports[0]['guard_retained'] is True
 assert reports[0]['workspace_guard_retained'] is False
