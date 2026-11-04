"""Real offline delegated worker -> owner receipt -> continued edit/commit."""
import json
from pathlib import Path
import time

import pytest
import yaml

from agentporter.agents.policy import ExecutionPolicy
from agentporter.git_approvals import GitApprovalRequest, issue_git_approval
from agentporter.tools.git import create_git_tools
from tests.security.test_approved_git_pull import backend, git
from tests.security.test_development_runtime import runtime_factory, no_probe
from tests.security.test_git_admission import count
from tests.security.test_closeout_client_policy import scoped_config, rpc


def configured(tmp_path,monkeypatch,runtime_factory):
    root,service,key,manager,remote = backend(tmp_path,monkeypatch)
    service.registry.get('repo').allow_agent_dispatch = True
    runtime,config,path,_,_ = runtime_factory()
    config['allowed_workspace_roots'] = [{'path':str(root),'writable':True}]
    path.write_text(yaml.safe_dump(config))
    runtime.workspace_registry = service.registry
    runtime.state_dir = manager.state_dir
    no_probe(monkeypatch,runtime)
    manager.development_runtime = runtime
    manager.transactional_writes = True
    manager.git_sandbox = service.sandbox
    manager.approved_git_pulls = service
    return root,service,key,manager,remote


def wait_output(manager,job_id,needle):
    deadline = time.monotonic()+12
    while time.monotonic()<deadline:
        output=manager.get_output(job_id)
        if needle in output['stdout']:
            return output
        if output['status'] not in {'running','launching','finalizing'}:
            raise AssertionError(output)
        time.sleep(.01)
    raise AssertionError(manager.get_output(job_id))


def terminal(manager,job_id):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        status=manager.get_status(job_id)
        if status['status'] not in {'running','launching','cancelling','finalizing'}:
            return status
        time.sleep(.01)
    raise AssertionError(manager.get_output(job_id))


WORKER = '''import json,subprocess,sys
from pathlib import Path
client=['/usr/bin/python3','-I','-S','/opt/agentporter/worker-git.py']
scope={'remote':'origin','ref':'refs/heads/reviewed','mode':'ff-only'}
def call(op,**extra):
 p=subprocess.run(client,input=json.dumps(dict(scope,op=op,**extra)),capture_output=True,text=True)
 if p.returncode: raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
assert call('push')['code']=='push_denied'
prepared=call('prepare')
assert prepared['status']=='prepared',prepared
print(json.dumps(prepared),flush=True)
reply=call('wait',request_sha256=prepared['request_sha256'])
assert reply['status']=='completed',reply
assert reply['outcome']['candidate_status']=='integrated',reply
assert Path('/workspace/ordinary').read_text()=='remote\\n'
Path('/workspace/after-pull').write_text('worker continued edit\\n')
subprocess.run(['/usr/bin/git','-c','user.name=Worker','-c','user.email=worker@example.invalid','add','after-pull'],check=True)
subprocess.run(['/usr/bin/git','-c','user.name=Worker','-c','user.email=worker@example.invalid','commit','-qm','post pull edit'],check=True)
print('CONTINUED_COMMIT',flush=True)
'''


def test_native_job_pull_owner_receipt_then_edit_commit_publishes_coherently(tmp_path,monkeypatch,runtime_factory):
    root,service,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
    original=git(root,'rev-parse','HEAD')
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
    output=wait_output(manager,job,'"status": "prepared"')
    prepared=json.loads(output['stdout'].splitlines()[0])
    request=GitApprovalRequest.from_payload(prepared['request'])
    assert request.to_payload()['parameters']['job_context']['job_id']==job
    assert count(manager)==1 and git(root,'rev-parse','HEAD')==original
    tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
    result=tools.git_pull('repo',branch='refs/heads/reviewed',job_id=job,
        request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
    assert result['status']=='completed',result
    status=terminal(manager,job)
    assert status['status']=='completed',manager.get_output(job)
    assert (root/'after-pull').read_text()=='worker continued edit\n'
    assert git(root,'rev-parse','HEAD^')==remote['oid']
    assert git(root,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
    assert git(root,'status','--porcelain')==''
    assert count(manager)==0
    assert job not in manager._worker_git_services


def test_cancel_waiting_worker_revokes_service_without_canonical_writes(tmp_path,monkeypatch,runtime_factory):
    root,service,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
    original=git(root,'rev-parse','HEAD')
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
    wait_output(manager,job,'"status": "prepared"')
    manager.cancel(job)
    status=terminal(manager,job)
    assert status['status']=='cancelled',manager.get_output(job)
    assert git(root,'rev-parse','HEAD')==original
    assert not (root/'after-pull').exists()
    assert count(manager)==0 and job not in manager._worker_git_services


def test_read_only_worker_does_not_receive_socket_or_helper(tmp_path,monkeypatch,runtime_factory):
    root,service,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
    script="from pathlib import Path; assert not Path('/run/agentporter-git.sock').exists(); assert not Path('/opt/agentporter/worker-git.py').exists()"
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',script],policy=ExecutionPolicy.for_workspace(writable=False))
    assert terminal(manager,job)['status']=='completed',manager.get_output(job)
    assert count(manager)==0


@pytest.mark.parametrize('options',[
    {'request_sha256':'a'*64},
    {'job_id':'job_'+'a'*24,'prepare_only':True,'request_sha256':'a'*64},
    {'job_id':'job_'+'a'*24,'approval_receipt':'{}'},
])
def test_public_job_pull_union_rejects_ambiguous_bindings(tmp_path,monkeypatch,options):
    _,service,_,manager,_=backend(tmp_path,monkeypatch)
    tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
    with pytest.raises(ValueError):tools.git_pull('repo',branch='refs/heads/reviewed',**options)


def test_real_mcp_and_rest_job_pull_require_public_ownership_of_valid_job(scoped_config,monkeypatch):
    from starlette.testclient import TestClient
    from agentporter import server
    from agentporter.client_policy import PRINCIPAL,PublicClientPolicy
    from agentporter.workspaces.registry import WorkspaceRegistry
    from agentporter.tools.jobs import JobManager
    path=scoped_config.config_dir/'public-client-policy.yaml'
    document=yaml.safe_load(path.read_text())
    document['workspaces']['allowed']['operations']=['read','git_pull','dispatch']
    path.write_text(yaml.safe_dump(document))
    owned='job_'+'1'*24;other='job_'+'2'*24
    manager=JobManager(scoped_config.state_dir)
    database=manager._get_db()
    try:
        with database:
            for job in (owned,other):
                database.execute('INSERT INTO jobs (job_id,workspace_id,agent,status) VALUES (?,?,?,?)',
                    (job,'allowed','codex_impl','running'))
    finally:database.close()
    policy=PublicClientPolicy(scoped_config.config_dir,scoped_config.state_dir,WorkspaceRegistry(scoped_config.workspaces))
    token=PRINCIPAL.set('public')
    try:policy.result('dispatch_agent',{'workspace_id':'allowed'},{'job_id':owned})
    finally:PRINCIPAL.reset(token)
    factory=server.create_git_tools;seen=[]
    def tools(*args,**kwargs):
        result=factory(*args,**kwargs)
        def controlled(workspace_id,**parameters):
            seen.append(parameters['job_id'])
            return {'status':'prepared'}
        result.git_pull=controlled
        return result
    monkeypatch.setattr(server,'create_git_tools',tools)
    with TestClient(server.create_asgi_app(scoped_config),client=('127.0.0.1',12345)) as client:
        payload={'workspace_id':'allowed','job_id':owned,'branch':'refs/heads/reviewed','prepare_only':True}
        assert not rpc(client,scoped_config.api_key,'git_pull',payload)['result'].get('isError')
        response=client.post('/api/v1/workspaces/allowed/git/pull',json={k:v for k,v in payload.items() if k!='workspace_id'},
            headers={'X-AgentPorter-Key':scoped_config.api_key})
        assert response.status_code==200,response.text
        payload['job_id']=other
        assert rpc(client,scoped_config.api_key,'git_pull',payload)['result'].get('isError')
        response=client.post('/api/v1/workspaces/allowed/git/pull',json={k:v for k,v in payload.items() if k!='workspace_id'},
            headers={'X-AgentPorter-Key':scoped_config.api_key})
        assert response.status_code==403,response.text
    assert seen==[owned,owned]


def test_consumed_pull_cancellation_retains_candidate_and_admission(tmp_path,monkeypatch,runtime_factory):
    root,service,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
    original=git(root,'rev-parse','HEAD')
    script=WORKER.replace("assert Path('/workspace/ordinary').read_text()=='remote\\n'", "assert Path('/workspace/ordinary').read_text()=='remote\\n'")
    script=script[:script.index("Path('/workspace/after-pull')")]+"print('INTEGRATED_WAITING',flush=True)\nimport time; time.sleep(60)\n"
    job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',
        cmd=['/usr/bin/python3','-c',script],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
    prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0])
    request=GitApprovalRequest.from_payload(prepared['request'])
    tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
    result=tools.git_pull('repo',branch='refs/heads/reviewed',job_id=job,
        request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
    assert result['status']=='completed',result
    wait_output(manager,job,'INTEGRATED_WAITING')
    manager.cancel(job)
    status=terminal(manager,job)
    assert status['status']=='cleanup_failed',manager.get_output(job)
    assert git(root,'rev-parse','HEAD')==original and count(manager)==1
    assert job in manager._job_transactions and job not in manager._worker_git_services
    assert list((manager.state_dir/'workspace-transactions').glob('*.git-pending.json'))


def test_push_remains_denied_in_actual_mcp_and_rest(temp_config,tmp_path):
    from starlette.testclient import TestClient
    from agentporter.server import create_asgi_app
    root=tmp_path/'project';root.mkdir()
    temp_config.workspaces={'repo':{'path':str(root),'writable':True,'allow_git':True}}
    temp_config.security.allowed_hosts=['testserver']
    path=temp_config.config_dir/'public-client-policy.yaml'
    path.write_text(yaml.safe_dump({'version':1,'workspaces':{'repo':{'path':str(root),'operations':['git_push']}}}))
    path.chmod(0o600)
    with TestClient(create_asgi_app(temp_config)) as client:
        payload={'workspace_id':'repo','branch':'refs/heads/main','approval_receipt':'previous-receipt'}
        result=rpc(client,temp_config.api_key,'git_push',payload)
        assert result['result'].get('isError'),result
        response=client.post('/api/v1/workspaces/repo/git/push',json={k:v for k,v in payload.items() if k!='workspace_id'},
            headers={'X-AgentPorter-Key':temp_config.api_key})
        assert response.status_code==403,response.text


def test_gateway_actions_deliver_receipt_to_exact_relay_job_and_worker_commit(tmp_path,monkeypatch,runtime_factory,temp_config):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from starlette.testclient import TestClient
    from agentporter import server
    from agentporter.config import Config
    from agentporter.agents import production_relay
    root,service,key,manager,remote=configured(tmp_path,monkeypatch,runtime_factory)
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
            cmd=['/usr/bin/python3','-c',WORKER],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=60)
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
        assert (root/'after-pull').read_text()=='worker continued edit\n'
        assert git(root,'rev-parse','HEAD^')==remote['oid']
        assert git(root,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
        assert count(manager)==0


@pytest.mark.parametrize('change',[
    {'job_id':'rjob_'+'a'*32}, {'mode':'--exec=bad'}, {'remote':'https://example.invalid'},
    {'branch':'refs/heads/*'}, {'prepare_only':1}, {'request_sha256':'x'},
    {'backend':'substitute'}, {'approval_receipt':'unsigned','prepare_only':True},
])
def test_narrow_relay_pull_request_rejects_scope_or_authority_injection(change):
    from agentporter.agents.production_relay import validate_pull_request
    payload={'workspace_id':'repo','job_id':'job_'+'a'*24,'remote':'origin','branch':'refs/heads/main',
        'mode':'ff-only','prepare_only':True,'request_sha256':'','approval_receipt':''}
    with pytest.raises(PermissionError):validate_pull_request({**payload,**change})


def test_cancellation_winning_finalization_cas_keeps_consumed_pull_admission(tmp_path,monkeypatch):
    from tests.security.test_approved_git_pull import live_job
    root,service,key,manager,_=backend(tmp_path,monkeypatch)
    adapter,transaction=live_job(service)
    try:
        request=adapter.prepare('origin','refs/heads/reviewed','ff-only')
        adapter.pull('origin','refs/heads/reviewed',issue_git_approval(key,request),'ff-only')
        database=manager._get_db()
        try:
            with database:database.execute("UPDATE jobs SET status='cancelling' WHERE job_id=?",(adapter.job_id,))
        finally:database.close()
        stderr=tmp_path/'stderr.log';stderr.write_bytes(b'')
        observed=manager._finalize_workspace_edits(adapter.job_id,'completed',0,True,str(stderr))
        assert observed==('cleanup_failed',1,False)
        assert manager._job_transactions[adapter.job_id] is transaction and not transaction._closed
        assert count(manager)==1
        assert list((manager.state_dir/'workspace-transactions').glob('*.git-pending.json'))
        assert (root/'ordinary').read_text()!='remote\n'
    finally:transaction.close()
