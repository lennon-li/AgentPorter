"""Native parent-project job, exact preexisting nested fixture pull and continued commit."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
import pytest,yaml
import agentporter
_runtime_root = (Path(sys.prefix)/f'lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages'
                 if os.environ.get('AGENTPORTER_TEST_INSTALLED_PACKAGE') == '1'
                 else Path(__file__).resolve().parents[2]/'src')
assert Path(agentporter.__file__).resolve().is_relative_to(_runtime_root)
from agentporter import git_remote_policy
from agentporter.git_pulls import ApprovedGitPulls
from agentporter.git_approvals import GitApprovalRequest,issue_git_approval
from agentporter.agents.policy import ExecutionPolicy
from agentporter.tools.git import create_git_tools
from tests.security.test_approved_git_pull import backend,git
from tests.security.test_development_runtime import runtime_factory,no_probe
from tests.security.test_worker_git_runtime import wait_output,terminal
from tests.security.test_git_admission import count


def metadata(root):
 return {str(p.relative_to(root)): (p.stat().st_ino,p.stat().st_mode,p.read_bytes()) for p in root.rglob('*') if p.is_file()}


def configured_nested(tmp_path,monkeypatch,runtime_factory,*,outer_git=True,algorithm='sha1',divergent=False,mode='ff-only',dual=False):
 root,old,key,manager,remote=None,None,None,None,None
 root,base,key,manager,remote=backend(tmp_path,monkeypatch,algorithm)
 selected=root/'acceptance/selected';other=root/'acceptance/other'
 for dest in (selected,other):
  subprocess.run(['/usr/bin/git','clone','-q','--no-hardlinks',str(root),str(dest)],check=True)
  git(dest,'config','user.name','Fixture');git(dest,'config','user.email','fixture@example.invalid')
 if divergent:
  (selected/'local').write_text('local\n');git(selected,'add','local');git(selected,'commit','-qm','local')
 if outer_git:
  (root/'owner-staged').write_text('staged owner\n');git(root,'add','owner-staged')
  (root/'ordinary').write_text('unstaged owner\n')
 else:
  import shutil
  shutil.rmtree(root/'.git')
  (root/'owner-staged').write_text('owner\n')
 policy_path=Path(base.authority._config_dir)/'git-remote-policy.json'
 policy=json.loads(policy_path.read_text());policy['grants'][0]['repository']='acceptance/selected'
 if dual:policy['grants'].append({**policy['grants'][0],'repository':'.'})
 policy_path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(policy_path.parent,base.registry,base.sandbox.state_dir)
 service=ApprovedGitPulls(base.registry,base.sandbox,authority,manager)
 service.registry.get('repo').allow_agent_dispatch=True
 runtime,config,path,_,_=runtime_factory();config['allowed_workspace_roots']=[{'path':str(root),'writable':True}]
 path.write_text(yaml.safe_dump(config));runtime.workspace_registry=service.registry;runtime.state_dir=manager.state_dir;no_probe(monkeypatch,runtime)
 manager.development_runtime=runtime;manager.transactional_writes=True;manager.git_sandbox=service.sandbox;manager.approved_git_pulls=service
 return root,selected,other,service,key,manager,remote


def browser_receipt_proof(tmp_path,request):
 from tests.security.test_owner_approval_protocol import run,NODE
 from agentporter.git_approvals import GitApprovalVerifier
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
 assert NODE is not None,'Actual owner-device WebCrypto verification requires Node'
 reviewed=run(json.dumps({'request':request.to_payload(),'request_sha256':request.digest}))
 assert reviewed['ok'],reviewed
 assert reviewed['payload'].encode()==request.canonical_payload
 assert reviewed['privateExportDenied'] and reviewed['frozen']
 verifier=GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(reviewed['publicKey'])),tmp_path/'device-owner/claims.db')
 verifier.verify_and_consume(reviewed['receipt'],request,now=1002)


WORKER='''import json,os,subprocess
from pathlib import Path
client=['/usr/bin/python3','-I','-S','/opt/agentporter/worker-git.py']
original_mnt=os.readlink('/proc/self/ns/mnt')
Path('/tmp/agentporter-worker-view-test').write_text('worker private tmp')
scope={'remote':'origin','ref':'refs/heads/reviewed','mode':MODE,'repository':'acceptance/selected'}
def call(op,**extra):
 p=subprocess.run(client,input=json.dumps(dict(scope,op=op,**extra)),capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
assert call('push')['code']=='push_denied'
p=call('prepare');assert p['status']=='prepared',p
print(json.dumps(p),flush=True)
if len(json.loads(Path('/run/agentporter-git-context.json').read_bytes())['allowed_repositories'])>1:
 assert call('prepare',repository='.')['code']=='repository_bound_elsewhere'
r=call('wait',request_sha256=p['request_sha256']);assert r['status']=='completed',r
assert r['outcome']['candidate_status']=='integrated',r
assert os.readlink('/proc/self/ns/mnt')==original_mnt
assert Path('/tmp/agentporter-worker-view-test').read_text()=='worker private tmp'
root=Path('/workspace/acceptance/selected');assert (root/'ordinary').read_text()=='remote\\n',repr((root/'ordinary').read_bytes())
(root/'continued').write_text('continued edit\\n')
subprocess.run(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'-c','user.name=Worker','-c','user.email=worker@example.invalid','add','continued'],check=True)
subprocess.run(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'-c','user.name=Worker','-c','user.email=worker@example.invalid','commit','-qm','continued nested commit'],check=True)
print('CONTINUED',flush=True)
'''


@pytest.mark.parametrize('algorithm',['sha1','sha256'])
@pytest.mark.parametrize('mode',['ff-only','merge','rebase'])
@pytest.mark.parametrize('outer_git',[True,False])
def test_actual_parent_project_job_nested_pull_then_commit_preserves_other_histories(tmp_path,monkeypatch,runtime_factory,outer_git,algorithm,mode,dual=False):
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git,algorithm=algorithm,mode=mode,divergent=mode!='ff-only',dual=dual)
 parent_namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('user','mnt','net','pid','ipc','uts')}
 outer_before=metadata(root/'.git') if outer_git else None
 other_before=metadata(other)
 owner_before=(root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes()
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
  cmd=['/usr/bin/python3','-c',WORKER.replace('MODE',repr(mode))],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
 prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0])
 request=GitApprovalRequest.from_payload(prepared['request'])
 browser_receipt_proof(tmp_path,request)
 assert request.to_payload()['workspace_id']=='repo'
 assert request.to_payload()['repository_path']==str(selected)
 assert request.to_payload()['parameters']['workspace_identity']['path']==str(root)
 assert request.to_payload()['parameters']['job_context']['job_id']==job
 assert count(manager)==1
 transaction=manager._job_transactions[job]
 assert set(transaction.git_histories)==({'.git','acceptance/selected/.git','acceptance/other/.git'} if outer_git else {'acceptance/selected/.git','acceptance/other/.git'})
 assert transaction.git_histories['acceptance/selected/.git']._lease is not None
 tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
 reply=tools.git_pull('repo',branch='refs/heads/reviewed',mode=mode,job_id=job,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
 assert reply['status']=='completed',reply
 status=terminal(manager,job);assert status['status']=='completed',manager.get_output(job)
 assert git(selected,'show','-s','--format=%s')=='continued nested commit'
 assert git(selected,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
 assert (selected/'continued').read_text()=='continued edit\n'
 assert metadata(other)==other_before
 if outer_git:assert metadata(root/'.git')==outer_before
 assert ((root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes())==owner_before
 assert count(manager)==0
 assert transaction._runtime_view_fd is None and transaction._runtime_namespace_fds is None
 proof=service.engine.last_runtime_proof
 assert proof['pid']==1 and proof['NoNewPrivs']=='1'
 assert proof['worker_tmp_visible'] is False
 assert proof['host_home_visible'] is False and set(proof['net_devices'])<= {'lo'}
 assert all(int(proof[name],16)==0 for name in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'))
 assert {name:os.readlink('/proc/self/ns/'+name) for name in parent_namespaces}==parent_namespaces
 assert all(proof['namespaces'][name]!=parent_namespaces[name] for name in parent_namespaces)
 if mode!='ff-only':assert git(selected,'show','HEAD~1:local')=='local'
 assert not list((manager.state_dir/'workspace-transactions').glob('*.pending.json'))
 assert not list((manager.state_dir/'workspace-transactions').glob('*.git-pending.json'))

def test_owner_policy_nested_prepare_binds_actual_repository(tmp_path,monkeypatch,runtime_factory):
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 request=service.prepare('repo','origin','refs/heads/reviewed')
 assert request.to_payload()['repository_path']==str(selected)


@pytest.mark.parametrize('location',['../outside','/outside','acceptance/../other','acceptance//selected','./acceptance/selected','.git/objects','.venv/repo','acceptance\\selected','acceptance/new\nline'])
def test_owner_policy_rejects_unscoped_repository_locations(location):
 with pytest.raises(PermissionError):git_remote_policy.repository_relative(location)


def test_owner_selected_repository_refuses_symlink_and_later_inode_swap(tmp_path,monkeypatch,runtime_factory):
 root,selected,other,service,key,manager,_=configured_nested(tmp_path,monkeypatch,runtime_factory)
 renamed=selected.with_name('owner-retained');selected.rename(renamed);selected.symlink_to(other,target_is_directory=True)
 with pytest.raises((PermissionError,OSError)):service.authority.authorize('repo','origin','refs/heads/reviewed','pull')
 selected.unlink();selected.mkdir()
 # Replacement is a fresh operation scope, never authority to reuse a receipt.
 with pytest.raises(PermissionError):service.prepare('repo','origin','refs/heads/reviewed')

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
@pytest.mark.parametrize('outer_git',[True,False])
def test_signed_fetch_selects_nested_repo_preserving_parent_and_worktree(tmp_path,monkeypatch,runtime_factory,algorithm,outer_git):
 from agentporter.git_fetches import ApprovedGitFetches
 root,selected,other,pulls,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,algorithm=algorithm,outer_git=outer_git)
 policy_path=Path(pulls.authority._config_dir)/'git-remote-policy.json'
 policy=json.loads(policy_path.read_text());policy['grants'][0]['operations']=['fetch','pull'];policy_path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(policy_path.parent,pulls.registry,pulls.sandbox.state_dir)
 fetches=ApprovedGitFetches(pulls.registry,pulls.sandbox,authority,manager)
 outer=metadata(root/'.git') if outer_git else None;other_before=metadata(other)
 worktree={p.name:(p.stat().st_ino,p.read_bytes()) for p in selected.iterdir() if p.is_file()}
 head=git(selected,'rev-parse','HEAD');index=(selected/'.git/index').read_bytes()
 request=fetches.prepare('repo','origin','refs/heads/reviewed')
 browser_receipt_proof(tmp_path,request)
 payload=request.to_payload()
 assert payload['repository_path']==str(selected)
 assert payload['parameters']['workspace_identity']['path']==str(root)
 assert payload['parameters']['metadata_inode']==(selected/'.git').stat().st_ino
 assert fetches.fetch('repo','origin','refs/heads/reviewed',issue_git_approval(key,request))==remote['oid']
 assert git(selected,'rev-parse','HEAD')==head and (selected/'.git/index').read_bytes()==index
 assert {p.name:(p.stat().st_ino,p.read_bytes()) for p in selected.iterdir() if p.is_file()}==worktree
 assert metadata(other)==other_before
 if outer_git:assert metadata(root/'.git')==outer
 assert git(selected,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
 assert count(manager)==0

@pytest.mark.parametrize('substitution',['workspace','namespace','root','token'])
def test_fixed_bootstrap_rejects_substituted_capabilities_before_provider(tmp_path,monkeypatch,runtime_factory,substitution):
 import agentporter.worker_git_service as module
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 source=Path(module.__file__).read_text()
 if substitution=='workspace':source=source.replace("descriptor=os.open('/workspace'","descriptor=os.open('/tmp'",1)
 elif substitution=='namespace':source=source.replace("os.open('/proc/self/ns/user'","os.open('/proc/self/ns/mnt'",1)
 elif substitution=='root':source=source.replace("os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)","os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)",1)
 else:source=source.replace("'token':context['bootstrap_token']","'token':'0'*64",1)
 fixed=tmp_path/'bad-bootstrap.py';fixed.write_text(source);fixed.chmod(0o400)
 original=module.WorkerGitService.__init__
 def replaced(self,*args,**kwargs):
  original(self,*args,**kwargs);self.client_path=fixed
 monkeypatch.setattr(module.WorkerGitService,'__init__',replaced)
 before=metadata(root)
 namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('user','mnt','net','pid','ipc','uts')}
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
  cmd=['/usr/bin/python3','-c',"print('UNTRUSTED_ENTERED')"],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=30)
 status=terminal(manager,job)
 assert status['status']=='failed',manager.get_output(job)
 output=manager.get_output(job)
 assert 'UNTRUSTED_ENTERED' not in output['stdout']
 assert 'Trusted workspace bootstrap was refused' in output['stderr']
 assert metadata(root)==before
 assert namespaces=={name:os.readlink('/proc/self/ns/'+name) for name in namespaces}
 assert count(manager)==0
 assert not manager._job_transactions
 assert not list((manager.state_dir/'workspace-transactions').glob('*.pending.json'))


def test_nested_actual_gateway_relay_receipt_and_continued_commit(tmp_path,monkeypatch,runtime_factory,temp_config):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from starlette.testclient import TestClient
    from agentporter import server
    from agentporter.config import Config
    from agentporter.agents import production_relay
    root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
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
            cmd=['/usr/bin/python3','-c',WORKER.replace('MODE',repr('ff-only'))],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
        return {'job_id':job,'status':'running'}
    context={'client_policy':SimpleNamespace(scopes=None,internal_key=None),'registry':service.registry,
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
            'operations':['read','write','dispatch','dispatch_write','git_pull']}}})):
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
        payload={'job_id':public,'remote':'origin','branch':'refs/heads/reviewed','mode':'ff-only','prepare_only':True}
        response=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
        assert response.status_code==200 and response.json()['request_sha256']==request.digest,response.text
        # A valid actual worker ID must not bypass the gateway's public alias ownership.
        denied=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json={**payload,'job_id':native})
        assert denied.status_code==403,denied.text
        payload.update(prepare_only=False,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
        response=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
        assert response.status_code==200 and response.json()['status']=='completed',response.text
        assert terminal(manager,native)['status']=='completed',manager.get_output(native)
        assert (selected/'continued').read_text()=='continued edit\n'
        assert metadata(root/'.git')==root_before and metadata(other)==other_before
        assert ((root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes())==owner_before
        assert git(selected,'rev-parse','HEAD^')==remote['oid']
        assert git(selected,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
        assert count(manager)==0

@pytest.mark.parametrize('mutation',['retarget','foreign_alias','changed_oid'])
def test_worker_cannot_expand_signed_tracking_update_through_symbolic_refs(tmp_path,monkeypatch,runtime_factory,mutation):
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 before=metadata(root)
 commands={
  'retarget':"subprocess.run(['/usr/bin/git','-C',str(root),'symbolic-ref','refs/remotes/origin/HEAD','refs/heads/reviewed'],check=True)",
  'foreign_alias':"subprocess.run(['/usr/bin/git','-C',str(root),'symbolic-ref','refs/remotes/foreign/HEAD','refs/heads/reviewed'],check=True)",
  'changed_oid':"subprocess.run(['/usr/bin/git','-C',str(root),'update-ref','refs/remotes/origin/reviewed','HEAD'],check=True)",
 }
 worker=WORKER.replace('MODE',repr('ff-only')).replace("print('CONTINUED',flush=True)",commands[mutation]+"\nprint('CONTINUED',flush=True)")
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
 prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0]);request=GitApprovalRequest.from_payload(prepared['request'])
 tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
 result=tools.git_pull('repo',branch='refs/heads/reviewed',job_id=job,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
 assert result['status']=='completed'
 status=terminal(manager,job)
 assert status['status']=='cleanup_failed',manager.get_output(job)
 assert 'CONTINUED' in manager.get_output(job)['stdout']
 assert metadata(root)==before
 assert count(manager)==1
 assert list((manager.state_dir/'workspace-transactions').glob('*.git-pending.json'))

@pytest.mark.parametrize('stage',['refs_prepared','refs_committed'])
def test_nested_signed_symbolic_tracking_interruption_has_exact_original_recovery(tmp_path,monkeypatch,runtime_factory,stage):
 from agentporter.sandbox import workspace_git,workspace_recovery
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 before=metadata(root)
 marker="publication_event('"+stage+"')"
 assert workspace_git._IMPORT.count(marker)==1
 monkeypatch.setattr(workspace_git,'_IMPORT',workspace_git._IMPORT.replace(marker,marker+'; os._exit(73)'))
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',WORKER.replace('MODE',repr('ff-only'))],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
 prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0]);request=GitApprovalRequest.from_payload(prepared['request'])
 transaction=manager._job_transactions[job]
 tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
 result=tools.git_pull('repo',branch='refs/heads/reviewed',job_id=job,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
 assert result['status']=='completed'
 assert terminal(manager,job)['status']=='cleanup_failed'
 # Model this isolated service process exiting after all native children stop;
 # no real host service is stopped or reconfigured by this fixture.
 from tests.security.custody.test_integration import stopped
 assert not manager.active_processes
 if getattr(manager,'_supervisor_lock',None) is not None:
  os.close(manager._supervisor_lock);manager._supervisor_lock=None
 for fd in (transaction._runtime_view_fd,*transaction._runtime_namespace_fds):os.close(fd)
 transaction._runtime_view_fd=None;transaction._runtime_namespace_fds=None
 stopped(transaction)
 monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
 plan=workspace_recovery.recover_workspace(manager.state_dir,root,pull_registry=service.registry,pull_owner_config_dir=service.authority._config_dir)
 assert all(item['inspection']['apply_supported'] for item in plan['git']),plan
 selected_inspection=next(item['inspection'] for item in plan['git'] if item['repository']=='acceptance/selected')
 history=transaction.git_histories['acceptance/selected/.git']
 bound={'path':history.guard,'inspection':selected_inspection}
 connection=manager._get_db()
 try:
  with pytest.raises(PermissionError,match='parent differs'):
   workspace_recovery._pull_admission(connection,bound,parent_workspace=other)
  original=connection.execute('SELECT guard_path FROM git_admissions').fetchone()[0]
  after_crash=metadata(root)
  for wrong in (str(history.guard),str(history.guard.with_name('sibling.git-pending.json')),str(tmp_path/'foreign-state'/Path(original).name)):
   with connection:connection.execute('UPDATE git_admissions SET guard_path=?',(wrong,))
   with pytest.raises(PermissionError,match='exact consumed Git admission'):
    workspace_recovery.recover_workspace(manager.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'],pull_registry=service.registry,pull_owner_config_dir=service.authority._config_dir)
   assert metadata(root)==after_crash
  with connection:connection.execute('UPDATE git_admissions SET guard_path=?',(original,))
 finally:connection.close()
 from agentporter.git_pulls import validate_pull_authorization
 tampered=json.loads(json.dumps(selected_inspection['approved_pull']['authorization']))
 tampered['verification_context']['ledger_path']=str(tmp_path/'foreign-ledger.db')
 with pytest.raises(PermissionError):validate_pull_authorization(tampered,registry=service.registry,state_dir=manager.state_dir,owner_config_dir=service.authority._config_dir)
 recovered=workspace_recovery.recover_workspace(manager.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'],pull_registry=service.registry,pull_owner_config_dir=service.authority._config_dir)
 assert recovered['status']=='recovered'
 connection=manager._get_db()
 try:assert connection.execute('SELECT status FROM git_admissions').fetchall()[0][0]=='resolved'
 finally:connection.close()
 after=metadata(root)
 assert all(after[name]==value for name,value in before.items())
 assert all(name.startswith('acceptance/selected/.git/objects/') for name in set(after)-set(before))
 from agentporter.sandbox.workspace_git_recovery import verify_git_baseline
 history=transaction.git_histories['acceptance/selected/.git']
 verify_git_baseline(selected,history.raw_baseline_directory,history.raw_baseline['sha256'])
 assert count(manager)==0
 assert not transaction._pending.exists()
 assert not list((manager.state_dir/'workspace-transactions').glob('*.git-pending.json'))
 transaction.close()
 assert transaction._runtime_view_fd is None and transaction._runtime_namespace_fds is None


def test_actual_root_and_nested_owner_grants_coexist_with_one_irrevocable_job_selection(tmp_path,monkeypatch,runtime_factory):
 test_actual_parent_project_job_nested_pull_then_commit_preserves_other_histories(tmp_path,monkeypatch,runtime_factory,True,'sha256','rebase',dual=True)


def test_actual_fetch_rest_selects_child_among_root_and_child_grants(tmp_path,monkeypatch,runtime_factory):
 from fastapi import FastAPI
 from starlette.testclient import TestClient
 from agentporter.rest.routers.git import router
 from agentporter.git_fetches import ApprovedGitFetches
 root,selected,other,pulls,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,dual=True)
 policy_path=Path(pulls.authority._config_dir)/'git-remote-policy.json'
 policy=json.loads(policy_path.read_text())
 for grant in policy['grants']:grant['operations']=['fetch','pull']
 policy_path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(policy_path.parent,pulls.registry,pulls.sandbox.state_dir)
 fetches=ApprovedGitFetches(pulls.registry,pulls.sandbox,authority,manager)
 tools=create_git_tools(pulls.registry,pulls.sandbox,approved_fetches=fetches)
 app=FastAPI();app.include_router(router,prefix='/api/v1');app.state.tools={'git_fetch':tools.git_fetch}
 before=metadata(root/'.git');other_before=metadata(other);head=git(selected,'rev-parse','HEAD')
 with TestClient(app) as client:
  default=fetches.prepare('repo','origin','refs/heads/reviewed')
  assert default.to_payload()['repository_path']==str(root)
  payload={'remote':'origin','branch':'refs/heads/reviewed','repository':'acceptance/selected','prepare_only':True}
  response=client.post('/api/v1/workspaces/repo/git/fetch',json=payload)
  assert response.status_code==200,response.text
  prepared=json.loads(response.json());request=GitApprovalRequest.from_payload(prepared['request'])
  assert request.to_payload()['repository_path']==str(selected)
  denied=client.post('/api/v1/workspaces/repo/git/fetch',json={**payload,'repository':'acceptance/other'})
  assert denied.status_code==403,denied.text
  response=client.post('/api/v1/workspaces/repo/git/fetch',json={**payload,'prepare_only':False,'approval_receipt':issue_git_approval(key,request)})
  assert response.status_code==200 and response.json()==remote['oid'],response.text
 assert git(selected,'rev-parse','HEAD')==head
 assert metadata(root/'.git')==before and metadata(other)==other_before
 assert count(manager)==0


def test_clone_target_policy_remains_exact_across_birth_and_policy_reload(tmp_path,monkeypatch,runtime_factory):
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 policy_path=Path(service.authority._config_dir)/'git-remote-policy.json'
 policy=json.loads(policy_path.read_text());grant=policy['grants'][0]
 grant['repository']='acceptance/new-clone';grant['operations']=['clone','fetch','pull']
 policy['grants'].append({**grant,'repository':'.','operations':['pull']})
 policy_path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(policy_path.parent,service.registry,service.sandbox.state_dir)
 authority.authorize('repo','origin','refs/heads/reviewed','clone',repository='acceptance/new-clone')
 with pytest.raises(FileNotFoundError):authority.authorize('repo','origin','refs/heads/reviewed','pull',repository='acceptance/new-clone')
 target=root/'acceptance/new-clone';target.mkdir()
 authority.authorize('repo','origin','refs/heads/reviewed','clone',repository='acceptance/new-clone')
 subprocess.run(['/usr/bin/git','clone','-q','--no-hardlinks',str(selected),str(target)],check=True)
 with pytest.raises(PermissionError,match='absent or empty'):authority.authorize('repo','origin','refs/heads/reviewed','clone',repository='acceptance/new-clone')
 assert authority.authorize('repo','origin','refs/heads/reviewed','pull',repository='acceptance/new-clone')[0].repository_relative=='acceptance/new-clone'
 reloaded=git_remote_policy.load_owner_git_remotes(policy_path.parent,service.registry,service.sandbox.state_dir)
 reloaded.authorize('repo','origin','refs/heads/reviewed','pull',repository='acceptance/new-clone')
 with pytest.raises(PermissionError):reloaded.authorize('repo','origin','refs/heads/reviewed','pull',repository='acceptance/other')


@pytest.mark.parametrize('assume_unchanged',[False,True])
def test_private_index_stat_refresh_does_not_hide_actual_nested_owner_dirt(tmp_path,monkeypatch,runtime_factory,assume_unchanged):
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,divergent=True)
 (selected/'ordinary').write_text('real owner dirty bytes\n')
 if assume_unchanged:git(selected,'update-index','--assume-unchanged','ordinary')
 before=metadata(root)
 request=service.prepare('repo','origin','refs/heads/reviewed','rebase')
 result=service.pull('repo','origin','refs/heads/reviewed',issue_git_approval(key,request),'rebase')
 assert result['candidate_status']=='refused',result
 saved=json.loads((Path(result['candidate_directory'])/'pull-private-result.json').read_text())['result']
 assert saved['reason']=='dirty_worktree'
 assert saved['after']['tree']==saved['before']['tree']==request.to_payload()['expected_tree']
 assert metadata(root)==before
 assert count(manager)==1

@pytest.mark.parametrize('stage',['before_supervisor_arm','before_child_arm','after_child_arm','supervisor_after_fork'])
def test_native_fixed_helper_parent_death_races_leave_no_privileged_survivor(tmp_path,monkeypatch,runtime_factory,stage):
 import select,signal,sys,time
 from agentporter.git_pull_integration import _RUNTIME_EXECUTOR
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 before=metadata(root);namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('user','mnt','pid','net','ipc','uts')}
 job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',"import time;print('VIEW_READY',flush=True);time.sleep(30)"],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=40)
 wait_output(manager,job,'VIEW_READY');transaction=manager._job_transactions[job]
 read_end,write_end=os.pipe();handles=[];harness=None
 # This test-only fixed barrier instruments trusted setup; no production API
 # accepts a program, barrier, PID, namespace, or descriptor from worker input.
 barrier="os.write(1,b'BARRIER\\n');os.read("+str(read_end)+",1)\n"
 program=_RUNTIME_EXECUTOR.replace('if child:\n os.close(parent_handle)',"if child:\n os.write(1,('NATIVE_CHILD '+str(child)+'\\n').encode())\n os.close(parent_handle)")
 if stage=='before_supervisor_arm':program=program.replace('arm_supervisor()\nchecked(libc.setns(user',barrier+'arm_supervisor()\nchecked(libc.setns(user',1)
 elif stage=='before_child_arm':program=program.replace("checked(libc.prctl(1,signal.SIGKILL,0,0,0),'helper parent death signal')",barrier+"checked(libc.prctl(1,signal.SIGKILL,0,0,0),'helper parent death signal')",1)
 else:program=program.replace("os.close(parent_handle)\nchecked(libc.mount(b'proc'", "os.close(parent_handle)\n"+barrier+"checked(libc.mount(b'proc'",1)
 harness_program="""import json,os,subprocess,sys
fds=json.loads(sys.argv[1]);program=sys.stdin.read()
p=subprocess.Popen(['/usr/bin/python3','-I','-S','-c',program,*map(str,fds[:3]),'{}',str(os.getpid())],pass_fds=tuple(fds))
print('EXECUTOR '+str(p.pid),flush=True)
sys.exit(p.wait())
"""
 capabilities=[*transaction._runtime_namespace_fds,read_end]
 try:
  harness=subprocess.Popen([sys.executable,'-I','-S','-c',harness_program,json.dumps(capabilities)],pass_fds=tuple(capabilities),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  harness.stdin.write(program);harness.stdin.close()
  executor=None;child=None;at_barrier=False;deadline=time.monotonic()+5;pending=''
  while time.monotonic()<deadline:
   ready,_,_=select.select([harness.stdout],[],[],max(0,deadline-time.monotonic()))
   if not ready:break
   chunk=os.read(harness.stdout.fileno(),4096).decode()
   if not chunk:break
   pending+=chunk
   while '\n' in pending:
    line,pending=pending.split('\n',1)
    if line.startswith('EXECUTOR '):executor=int(line.split()[1])
    elif line.startswith('NATIVE_CHILD '):child=int(line.split()[1])
    elif line=='BARRIER':at_barrier=True
   if executor and at_barrier and (stage=='before_supervisor_arm' or child):break
  assert executor and at_barrier and (stage=='before_supervisor_arm' or child), (executor,child,at_barrier)
  for pid in (executor,child):
   if pid is not None:handles.append(os.pidfd_open(pid))
  target=os.pidfd_open(harness.pid) if stage in ('before_supervisor_arm','supervisor_after_fork') else handles[0]
  if target not in handles:handles.append(target)
  signal.pidfd_send_signal(target,signal.SIGKILL)
  try:os.write(write_end,b'x')
  except BrokenPipeError:pass
  for handle in handles:
   poll=select.poll();poll.register(handle,select.POLLIN)
   assert poll.poll(3000),'An owned privileged helper survived parent death'
  harness.wait(timeout=3)
 finally:
  for handle in handles:
   try:signal.pidfd_send_signal(handle,signal.SIGKILL)
   except ProcessLookupError:pass
   os.close(handle)
  if harness is not None:
   if harness.poll() is None:harness.kill()
   harness.wait(timeout=3)
   for stream in (harness.stdout,harness.stderr):stream.close()
  os.close(read_end);os.close(write_end)
  manager.cancel(job);terminal(manager,job)
 assert namespaces=={name:os.readlink('/proc/self/ns/'+name) for name in namespaces}
 assert metadata(root)==before and count(manager)==0
 assert transaction._runtime_view_fd is None and transaction._runtime_namespace_fds is None
