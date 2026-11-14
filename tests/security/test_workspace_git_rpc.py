"""Direct protected Git authority: RPC, public API and real offline worker clients."""
import json
import threading
from pathlib import Path

import pytest

from agentporter.git_approvals import GitApprovalRequest
from agentporter.worker_git_rpc import WorkerGitGrant,WorkerGitRPC
from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.agents.policy import ExecutionPolicy
from agentporter.git_authorizations import workspace_policy_document
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_fetches import ApprovedGitFetches
from agentporter.git_pulls import ApprovedGitPulls
from agentporter.git_clones import ApprovedGitClones
from agentporter.tools.git import create_git_tools
from tests.security.test_development_runtime import runtime_factory
from tests.security.test_worker_git_runtime import configured,terminal
from tests.security.test_git_admission import count
from tests.security.test_git_approval_state import git

JOB='job_'+'1'*24
REF='refs/heads/reviewed'


class PolicyBackend:
    requires_receipt=False
    def __init__(self,agent='codex_impl'):
        self.agent=agent;self.calls=[];self.claimed=set()
    def request(self,operation,workspace,remote,ref,mode=None):
        params={'remote_id':remote,'remote_ref':ref,'job_context':{'job_id':JOB,'agent':self.agent}}
        if mode is not None:params['mode']=mode
        return GitApprovalRequest.from_payload({'operation':operation,'workspace_id':workspace,
            'repository_path':'/srv/project','repository_device':1,'repository_inode':2,
            'expected_head':'a'*40,'expected_tree':'b'*40,'branch':'refs/heads/main','parameters':params})
    def prepare(self,workspace,remote,ref,mode):
        self.calls.append('prepare');return self.request('pull',workspace,remote,ref,mode)
    def pull(self,workspace,remote,ref,receipt,mode):
        assert receipt=='';self.calls.append('pull');return {'candidate_status':'integrated'}
    def prepare_fetch_repository(self,workspace,repository,remote,ref):
        self.calls.append('prepare_fetch');return self.request('fetch',workspace,remote,ref)
    def fetch_repository(self,workspace,repository,remote,ref,receipt):
        assert receipt=='';self.calls.append('fetch');return {'candidate_status':'fetched'}


def policy_rpc(agent='codex_impl',**changes):
    backend=PolicyBackend(agent)
    rpc=WorkerGitRPC(backend,lambda *args:True,clock=lambda:100)
    values=dict(job_id=JOB,agent=agent,workspace_id='project',repository='.',repository_path='/srv/project',
        capabilities=frozenset({'read','write'}),allowed=frozenset({('origin',REF,'ff-only')}),
        fetch_allowed=frozenset({('origin',REF)}),expires_at=1000)
    values.update(changes);rpc.issue_grant(WorkerGitGrant(**values))
    return backend,rpc,rpc.channel(JOB)


def payload(op='pull',agent='codex_impl',**changes):
    data={'version':1,'op':op,'job_id':JOB,'agent':agent,'workspace_id':'project',
        'repository':'.','remote':'origin','ref':REF}
    if op!='fetch':data['mode']='ff-only'
    data.update(changes);return json.dumps(data)


@pytest.mark.parametrize('agent',sorted(PUBLIC_AGENT_IDS))
@pytest.mark.parametrize('operation',['fetch','pull'])
def test_all_named_agents_execute_without_caller_receipt_or_digest(agent,operation):
    backend,rpc,channel=policy_rpc(agent)
    result=channel.handle(payload(operation,agent))
    assert result['ok'] and result['status']=='completed',result
    assert backend.calls==(['prepare_fetch','fetch'] if operation=='fetch' else ['prepare','pull'])
    assert channel.handle(payload(operation,agent))['code']=='replay'
    assert backend.calls.count(operation)==1
    assert channel.handle(payload('push',agent,approval_receipt='old-signed-receipt'))['code']=='push_denied'


@pytest.mark.parametrize('changes,code',[
    ({'remote':'other'},'scope_denied'),({'ref':'refs/heads/other'},'scope_denied'),
    ({'job_id':'job_'+'2'*24},'job_mismatch'),({'workspace_id':'outside'},'workspace_mismatch'),
    ({'repository':'other'},'repository_mismatch'),({'agent':'copilot_agent'},'agent_mismatch'),
    ({'url':'https://example.invalid'},'forbidden_field'),({'env':{}},'forbidden_field'),
    ({'authorization_mode':'workspace'},'invalid_request'),({'approval_receipt':'signed-legacy'},'receipt_not_supported'),
    ({'request_sha256':None},'invalid_request')])
def test_direct_execution_does_not_accept_caller_authority_or_scope(changes,code):
    backend,rpc,channel=policy_rpc()
    assert channel.handle(payload(**changes))['code']==code
    assert backend.calls==[]


def test_readonly_and_revoked_or_dead_job_cannot_use_direct_authority():
    backend,rpc,channel=policy_rpc(capabilities=frozenset({'read'}))
    assert channel.handle(payload())['code']=='read_only' and not backend.calls
    backend,rpc,channel=policy_rpc();rpc._is_live=lambda *args:False
    assert channel.handle(payload())['code']=='job_not_live' and not backend.calls
    backend,rpc,channel=policy_rpc();rpc.revoke(JOB)
    assert channel.handle(payload())['code']=='grant_revoked' and not backend.calls


def activate(service,manager,*,operations=None):
    path=Path(service.authority._config_dir)/'git-remote-policy.json';raw=path.read_bytes();data=json.loads(raw)
    if operations is not None:
        for grant in data['grants']:grant['operations']=operations
    path.write_text(json.dumps(workspace_policy_document(data,previous_raw=raw)))
    authority=load_owner_git_remotes(path.parent,service.registry,service.sandbox.state_dir)
    pulls=ApprovedGitPulls(service.registry,service.sandbox,authority,manager)
    fetches=ApprovedGitFetches(service.registry,service.sandbox,authority,manager)
    clones=ApprovedGitClones(service.registry,service.sandbox,authority,manager)
    manager.approved_git_pulls=pulls;manager.approved_git_fetches=fetches;manager.approved_git_clones=clones
    return pulls,fetches,clones


DIRECT_WORKER='''import json,subprocess
from pathlib import Path
client=['/usr/bin/python3','-I','-S','/opt/agentporter/worker-git.py']
scope=SCOPE
push=dict(scope,op='push',mode='ff-only');push.pop('branch',None)
p=subprocess.run(client,input=json.dumps(push),capture_output=True,text=True,check=True)
assert json.loads(p.stdout)['code']=='push_denied'
p=subprocess.run(client,input=json.dumps(dict(scope,op=OPERATION)),capture_output=True,text=True,check=True)
result=json.loads(p.stdout);assert result['status']=='completed',result
root=Path('/workspace')/REPOSITORY
if OPERATION=='fetch':
 assert (root/'ordinary').read_text()=='tracked\\n'
 assert subprocess.check_output(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'rev-parse','refs/remotes/origin/reviewed'],text=True).strip()==EXPECTED_REMOTE
if OPERATION=='pull':assert (root/'ordinary').read_text()=='remote\\n'
(root/'continued').write_text('direct operation continued\\n')
print('DIRECT_DONE',flush=True)
'''


@pytest.mark.parametrize('operation',['fetch','pull'])
@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_native_worker_direct_operation_keeps_commit_owner_only(tmp_path,monkeypatch,runtime_factory,operation,algorithm):
    from tests.security.test_approved_git_pull import backend
    from tests.security.test_worker_git_runtime import configured as configure_runtime
    # The ordinary native runtime fixture installs only synthetic offline credentials.
    root,old,key,manager,remote=configure_runtime(tmp_path,monkeypatch,runtime_factory)
    if algorithm=='sha256':
        # Reuse the established SHA256 fixture instead of changing Git metadata in place.
        other=tmp_path/'sha256';other.mkdir()
        root,old,key,manager,remote=backend(other,monkeypatch,algorithm)
        from tests.security.test_development_runtime import no_probe
        import yaml
        runtime,config,path,_,_=runtime_factory();config['allowed_workspace_roots']=[{'path':str(root),'writable':True}]
        path.write_text(yaml.safe_dump(config));runtime.workspace_registry=old.registry;runtime.state_dir=manager.state_dir;no_probe(monkeypatch,runtime)
        old.registry.get('repo').allow_agent_dispatch=True
        manager.development_runtime=runtime;manager.transactional_writes=True;manager.git_sandbox=old.sandbox
    pulls,fetches,clones=activate(old,manager,operations=['fetch'] if operation=='fetch' else ['fetch','pull'])
    original=git(root,'rev-parse','HEAD');before=(root/'ordinary').read_text()
    worker=DIRECT_WORKER.replace('SCOPE',repr({'remote':'origin','ref':REF,**({'mode':'ff-only'} if operation=='pull' else {})})).replace('OPERATION',repr(operation)).replace('REPOSITORY',repr('.')).replace('EXPECTED_REMOTE',repr(remote['oid']))
    # Pin the fixture's baseline rather than assuming its tracked content spelling.
    worker=worker.replace("=='tracked\\n'",'=='+repr(before))
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
    result=terminal(manager,job)
    assert result['status']=='completed',manager.get_output(job)
    assert 'DIRECT_DONE' in manager.get_output(job)['stdout']
    assert (root/'continued').read_text()=='direct operation continued\n'
    assert git(root,'rev-parse','HEAD')==(original if operation=='fetch' else remote['oid'])
    assert git(root,'status','--short')=='?? continued'
    assert git(root,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
    assert count(manager)==0 and job not in manager._worker_git_services


def test_native_worker_raw_commit_is_rejected_without_publication(tmp_path,monkeypatch,runtime_factory,caplog):
    from tests.security.test_worker_git_runtime import configured as configure_runtime
    root,old,key,manager,remote=configure_runtime(tmp_path,monkeypatch,runtime_factory)
    head=git(root,'rev-parse','HEAD');index=(root/'.git/index').read_bytes()
    worker="""from pathlib import Path
import subprocess
root=Path('/workspace')
(root/'unapproved').write_text('unapproved worker commit\\n')
for args in (['add','unapproved'],['commit','-qm','unapproved worker commit']):
 subprocess.run(['/usr/bin/git','-C',str(root),'-c','safe.directory='+str(root),'-c','user.name=Worker','-c','user.email=worker@example.invalid']+args,check=True)
print('RAW_COMMIT_CREATED',flush=True)
"""
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
    result=terminal(manager,job)
    output=manager.get_output(job)
    assert result['status']=='failed',output
    assert 'Worker Git history change requires independent owner approval' in caplog.text
    assert 'RAW_COMMIT_CREATED' in output['stdout']
    assert git(root,'rev-parse','HEAD')==head
    assert git(root,'rev-parse','refs/heads/reviewed')==head
    assert (root/'.git/index').read_bytes()==index
    assert not (root/'unapproved').exists()
    assert count(manager)==0


def test_native_clone_client_executes_without_prepare_wait_or_phone(tmp_path,monkeypatch,runtime_factory):
    from tests.security.test_clone_job_control import configured_clone
    root,selected,other,old,key,manager,remote,_=configured_clone(tmp_path,monkeypatch,runtime_factory,algorithm='sha256',outer_git=False,existing=True)
    activate(old,manager)
    scope={'repository':'new-clone','remote':'origin','ref':'refs/heads/main','branch':'refs/heads/main'}
    worker=DIRECT_WORKER.replace('SCOPE',repr(scope)).replace('OPERATION',repr('clone')).replace('REPOSITORY',repr('new-clone')).replace('EXPECTED_REMOTE',repr(remote['oid']))
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_research',
        cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
    assert terminal(manager,job)['status']=='completed',manager.get_output(job)
    assert (root/'new-clone/continued').read_text()=='direct operation continued\n'
    assert git(root/'new-clone','rev-parse','HEAD')==remote['oid'] and count(manager)==0


def public_server_config(temp_config,service,manager,monkeypatch,operations):
    from agentporter import server
    import yaml
    temp_config.config_dir=Path(service.authority._config_dir);temp_config.state_dir=manager.state_dir
    temp_config.workspaces={'repo':{'path':service.registry.get('repo').path,'writable':True,'allow_git':True,'allow_agent_dispatch':True}}
    temp_config.sandbox.workspace_transactions=True;temp_config.security.allowed_hosts=['testserver']
    policy=temp_config.config_dir/'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version':1,'workspaces':{'repo':{'path':service.registry.get('repo').path,'operations':operations}}}));policy.chmod(0o600)
    monkeypatch.setattr(server,'BubblewrapSandbox',lambda *args,**kwargs:service.sandbox)
    monkeypatch.setattr(server,'JobManager',lambda *args,**kwargs:manager)
    return temp_config


def test_real_rest_fetch_mcp_pull_owner_commit_and_push_denial(temp_config,tmp_path,monkeypatch,runtime_factory):
    from agentporter import server
    from fastapi.testclient import TestClient
    from tests.security.test_closeout_client_policy import rpc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from agentporter.git_approvals import GitApprovalRequest,GitApprovalVerifier,issue_git_approval
    root,old,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
    pulls,fetches,clones=activate(old,manager,operations=['fetch','pull'])
    owner_key=Ed25519PrivateKey.generate()
    ledger=tmp_path/'owner-commit'/'claims.db'
    GitApprovalVerifier(owner_key.public_key(),ledger)
    policy=Path(old.authority._config_dir)/'git-commit-policy.json'
    policy.write_text(json.dumps({'version':1,'author_name':'Synthetic Owner','author_email':'owner@example.invalid',
        'verification_key':owner_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
        'ledger_path':str(ledger),'workspaces':['repo']}));policy.chmod(0o600)
    config=public_server_config(temp_config,pulls,manager,monkeypatch,['read','write','git_read','git_write','git_fetch','git_pull','git_clone','git_commit'])
    with TestClient(server.create_asgi_app(config)) as client:
        headers={'X-AgentPorter-Key':config.api_key};endpoint='/api/v1/workspaces/repo/git/'
        response=client.post(endpoint+'fetch',headers=headers,json={'branch':REF})
        assert response.status_code==200,response.text
        assert response.json()==remote['oid']
        result=rpc(client,config.api_key,'git_pull',{'workspace_id':'repo','branch':REF})
        assert not result['result'].get('isError'),result
        assert git(root,'rev-parse','HEAD')==remote['oid']
        (root/'api-commit').write_text('owner reviewed commit\n')
        git(root,'add','api-commit')
        message='synthetic owner approved MCP commit'
        denied=rpc(client,config.api_key,'git_commit',{'workspace_id':'repo','message':message})
        assert denied['result']['isError'],denied
        prepared=rpc(client,config.api_key,'git_commit',{'workspace_id':'repo','message':message,'prepare_only':True})
        proposal=json.loads(prepared['result']['content'][0]['text'])
        request=GitApprovalRequest.from_payload(proposal['request'])
        timestamp=request.to_payload()['parameters']['timestamp']
        result=rpc(client,config.api_key,'git_commit',{'workspace_id':'repo','message':message,
            'approval_timestamp':timestamp,'approval_receipt':issue_git_approval(owner_key,request)})
        assert not result['result'].get('isError'),result
        assert git(root,'show','-s','--format=%s')==message
        (root/'api-rest-commit').write_text('owner reviewed REST commit\n')
        git(root,'add','api-rest-commit')
        rest_message='synthetic owner approved REST commit'
        denied=client.post(endpoint+'commit',headers=headers,json={'message':rest_message})
        assert denied.status_code==403,denied.text
        prepared=client.post(endpoint+'commit',headers=headers,json={'message':rest_message,'prepare_only':True})
        assert prepared.status_code==200,prepared.text
        proposal=json.loads(prepared.json())
        request=GitApprovalRequest.from_payload(proposal['request'])
        timestamp=request.to_payload()['parameters']['timestamp']
        result=client.post(endpoint+'commit',headers=headers,json={'message':rest_message,
            'approval_timestamp':timestamp,'approval_receipt':issue_git_approval(owner_key,request)})
        assert result.status_code==200,result.text
        assert git(root,'show','-s','--format=%s')==rest_message
        assert client.post(endpoint+'push',headers=headers,json={'branch':REF,'approval_receipt':'old-signed-receipt'}).status_code==403
        denied=rpc(client,config.api_key,'git_push',{'workspace_id':'repo','branch':REF,'approval_receipt':'old-signed-receipt'})
        denial=json.loads(denied['result']['content'][0]['text'])
        assert denial=={'status':'denied','executed':False,'error':
            {'code':'POLICY_DENIED','action':'git_push','mode':'LOCKED','reason':'action_locked'}},denied
        assert client.post(endpoint+'fetch',headers=headers,json={'branch':REF,'authorization_mode':'workspace'}).status_code==422
        caps=rpc(client,config.api_key,'get_capabilities',{})
        content=json.loads(caps['result']['content'][0]['text'])
        for name in ('git_fetch','git_pull'):
            assert content['git_operations'][name]['available'] is None
            assert content['git_operations'][name]['requires_receipt'] is False
        assert content['git_operations']['git_clone']['reason']=='scope_unavailable'
        assert content['git_operations']['git_push']['available'] is False


@pytest.mark.parametrize('operation',['pull','clone'])
def test_actual_public_live_job_operation_needs_no_digest_or_receipt(temp_config,tmp_path,monkeypatch,runtime_factory,operation):
    import os,time
    from agentporter import server
    from agentporter.agents.broker import AgentBroker
    from fastapi.testclient import TestClient
    if operation=='clone':
        from tests.security.test_clone_job_control import configured_clone
        root,_,_,old,key,manager,remote,_=configured_clone(tmp_path,monkeypatch,runtime_factory,outer_git=False,algorithm='sha256',existing=True)
        repository='new-clone';ref='refs/heads/main'
    else:
        root,old,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory);repository='.';ref=REF
    pulls,fetches,clones=activate(old,manager)
    worker="import time;from pathlib import Path;print('API_READY',flush=True)\nfor _ in range(500):\n if Path('/workspace/.api-done').exists():break\n time.sleep(.02)\nelse:raise RuntimeError('API never completed')\nprint('API_DONE',flush=True)"
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
    from tests.security.test_worker_git_runtime import wait_output
    wait_output(manager,job,'API_READY')
    config=public_server_config(temp_config,pulls,manager,monkeypatch,['read','write','git_pull','git_clone','dispatch','dispatch_write'])
    monkeypatch.setattr(AgentBroker,'dispatch_agent',lambda self,**kwargs:{'job_id':job,'status':'running'})
    monkeypatch.setattr(AgentBroker,'list_agents',lambda self:[{'agent':'codex_impl','worker_cli':'codex','available':True,'delegatable':True,'runtime_dispatch_workspaces':['repo'],'runtime_writable_dispatch_workspaces':['repo']}])
    try:
        with TestClient(server.create_asgi_app(config)) as client:
            headers={'X-AgentPorter-Key':config.api_key}
            dispatch=client.post('/api/v1/workspaces/repo/agents/dispatch',headers=headers,json={'agent':'codex_impl','task':'Existing synthetic live worker','read_only':False})
            assert dispatch.status_code==200,dispatch.text
            result=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json={'operation':operation,'branch':ref,'job_id':job,'repository':repository})
            assert result.status_code==200,result.text
            assert result.json()['status']=='completed',result.json()
            if operation=='clone':assert result.json()['outcome']['candidate_status']=='cloned'
            with manager.lock:tx=manager._job_transactions[job]
            fd=os.open('.api-done',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=tx._runtime_view_fd);os.close(fd)
            assert terminal(manager,job)['status']=='completed',manager.get_output(job)
            assert git(root/repository,'rev-parse','HEAD')==remote['oid']
            assert count(manager)==0
    finally:
        if job in manager.active_processes:manager.cancel(job)


@pytest.mark.parametrize('kind',['read','write','upstream'])
def test_explicit_relay_catalog_represents_512_and_rejects_513_or_oversize(tmp_path,kind):
    import yaml
    from agentporter.agents.production_relay import read_relay_scope,relay_upstream_workspaces
    config=tmp_path/'config';config.mkdir(mode=0o700)
    names=['project_'+str(i) for i in range(512)]
    path=config/('delegation-upstream.yaml' if kind=='upstream' else 'delegation-relay-write-scope.yaml' if kind=='write' else 'delegation-relay-scope.yaml')
    def document(values):
        return {'version':1,'host':'127.0.0.1','port':8876,'workspaces':values} if kind=='upstream' else {'version':1,'workspaces':{name:'/projects/'+name for name in values}}
    def load():return relay_upstream_workspaces(config) if kind=='upstream' else read_relay_scope(config,writable=kind=='write')
    path.write_text(yaml.safe_dump(document(names)));path.chmod(0o600)
    assert len(load())==512
    path.write_text(yaml.safe_dump(document(names+['project_513'])))
    with pytest.raises((PermissionError,ValueError)):load()
    path.write_text(yaml.safe_dump(document(names))+' '*262145)
    with pytest.raises((PermissionError,ValueError)):load()


def test_real_public_relay_clone_without_phone_keeps_exact_job_and_repository(temp_config,tmp_path,monkeypatch,runtime_factory):
    import os,yaml
    from tests.security.test_clone_job_control import configured_clone
    from tests.security.test_nested_repository_scope import metadata
    from tests.security.test_worker_git_runtime import wait_output
    worker_program="import time;from pathlib import Path;print('RELAY_READY',flush=True)\nfor _ in range(500):\n if Path('/workspace/.api-done').exists():break\n time.sleep(.02)\nelse:raise RuntimeError('API never completed')\nassert Path('/workspace/new-clone/remote-file').is_file()"
    import asyncio
    from types import SimpleNamespace
    import httpx
    from starlette.testclient import TestClient
    from agentporter import server
    from agentporter.config import Config
    from agentporter.agents import production_relay
    root,selected,other,service,key,manager,remote,fetches=configured_clone(tmp_path,monkeypatch,runtime_factory,algorithm='sha256',existing=True)
    service,fetches,clones=activate(service,manager)
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
            cmd=['/usr/bin/python3','-c',worker_program],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
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
        dispatch=client.post('/api/v1/workspaces/repo/agents/dispatch',headers=headers,json={'agent':'codex_impl','task':'direct scoped clone','read_only':False})
        assert dispatch.status_code==200,dispatch.text
        public=dispatch.json()['job_id'];ledger=production_relay.RelayLedger(gateway.state_dir)
        native=ledger.get_request(public.removeprefix('rjob_'))[0]
        wait_output(manager,native,'RELAY_READY')
        payload={'job_id':public,'remote':'origin','branch':'refs/heads/main','operation':'clone','repository':'new-clone'}
        try:
            receiver_policy.scopes={'repo':frozenset({'git_pull'})}
            assert client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload).status_code==403
            receiver_policy.scopes={'repo':frozenset({'git_clone'})}
            assert client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json={**payload,'job_id':native}).status_code==403
            response=client.post('/api/v1/workspaces/repo/git/pull',headers=headers,json=payload)
            assert response.status_code==200,response.text
            assert response.json()['status']=='completed' and response.json()['operation']=='clone',response.json()
            with manager.lock:tx=manager._job_transactions[native]
            fd=os.open('.api-done',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=tx._runtime_view_fd);os.close(fd)
            assert terminal(manager,native)['status']=='completed',manager.get_output(native)
            assert git(root/'new-clone','rev-parse','HEAD')==remote['oid']
            assert metadata(root/'.git')==root_before and metadata(other)==other_before
            assert ((root/'ordinary').read_bytes(),(root/'owner-staged').read_bytes())==owner_before
            assert count(manager)==0
        finally:
            if native in manager.active_processes:manager.cancel(native)
