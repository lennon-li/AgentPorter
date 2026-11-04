"""Late receiver refusal: real authenticated local HTTP, no provider or worker launch."""
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient

from agentporter import server
from agentporter.agents import production_relay as relay
from agentporter.config import Config
from agentporter.workspaces.registry import WorkspaceRegistry
from tests.security.relay_fixture import inputs, plan


def read_state(ledger,key):
    # Existing schema observation also lets the original implementation reproduce
    # the actual public status failure before the proposed helper exists.
    with ledger._db() as db:
        return db.execute('SELECT remote_id,workspace_id,agent,active FROM jobs WHERE request_id=?',(key,)).fetchone()


@pytest.fixture
def receiving(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir();other=tmp_path/'other';other.mkdir()
    monkeypatch.setattr(plan,'FIXTURE',str(root))
    w,g=inputs()
    w['workspaces.yaml']['workspaces']={};w['public-client-policy.yaml']['workspaces']={}
    w['development-runtime.yaml']['allowed_workspace_roots']=[{'path':str(other),'writable':False}]
    g['workspaces.yaml']['workspaces']={};g['public-client-policy.yaml']['workspaces']={}
    w,g=plan.prepare(w,g,agents=['copilot_agent'])
    configs={}
    for name,docs in [('worker',w),('gateway',g)]:
        config=tmp_path/(name+'-config');config.mkdir(mode=0o700)
        for filename,value in docs.items():
            path=config/filename;path.write_text(yaml.safe_dump(value));path.chmod(0o600)
        key=config/'delegation-relay.key';key.write_text('r'*43);key.chmod(0o600)
        state=tmp_path/(name+'-state');state.mkdir(mode=0o700)
        configs[name]=Config(config_dir=config,state_dir=state,cache_dir=tmp_path/(name+'-cache'))
    entered=threading.Event();release=threading.Event();calls=[]
    refusal=[PermissionError('SYNTHETIC-PRIVATE-POLICY-DETAIL')]
    def dispatch(**args):
        calls.append(args);entered.set()
        assert release.wait(5),'Synthetic rejection was not released'
        raise refusal[0]
    registry=WorkspaceRegistry(w['workspaces.yaml']['workspaces'])
    runtime=SimpleNamespace(require_production_egress=lambda agent=None:frozenset({'copilot_agent'}))
    context={'client_policy':SimpleNamespace(scopes={},internal_key=None),'registry':registry,
        'agent_broker':SimpleNamespace(development_runtime=runtime),'delegation_relay_client':None,
        'job_manager':SimpleNamespace(resources=object(),active_processes={}),
        'tools':{'dispatch_agent':dispatch}}
    original=server.build_mcp_server
    monkeypatch.setattr(server,'build_mcp_server',lambda _:(server.MCPServer('synthetic-receiver'),context))
    worker=server.create_asgi_app(configs['worker'])
    monkeypatch.setattr(server,'build_mcp_server',original)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(16)
    port=listener.getsockname()[1]
    service=uvicorn.Server(uvicorn.Config(worker,log_level='error',lifespan='off'))
    thread=threading.Thread(target=service.run,kwargs={'sockets':[listener]},daemon=True);thread.start()
    until=time.monotonic()+5
    while not service.started and thread.is_alive() and time.monotonic()<until:time.sleep(.005)
    assert service.started
    original_connection=relay.http.client.HTTPConnection
    def connection(host,requested_port,timeout):
        assert (host,requested_port)==('127.0.0.1',8876)
        assert timeout in (8,60,300)
        inner=original_connection(host,port,timeout=2)
        class Adapter:
            def request(self,method,path,body,headers):
                self.operation=json.loads(body)['operation']
                inner.timeout=.03 if self.operation=='dispatch_agent' else 2
                inner.request(method,path,body=body,headers=headers)
            def getresponse(self):return inner.getresponse()
            def close(self):inner.close()
        return Adapter()
    monkeypatch.setattr(relay.http.client,'HTTPConnection',connection)
    def raw(operation,args):
        client=original_connection('127.0.0.1',port,timeout=2)
        try:
            client.request('POST','/internal/delegation/v1',body=json.dumps({'operation':operation,'args':args}),headers={'Authorization':'Bearer '+'r'*43,'Content-Type':'application/json'})
            response=client.getresponse();return response.status,json.loads(response.read())
        finally:client.close()
    gateway=configs['gateway'];gateway.security.allowed_hosts.append('testserver')
    yield SimpleNamespace(config=gateway,worker=configs['worker'],raw=raw,entered=entered,release=release,calls=calls,root=root,refusal=refusal)
    release.set();service.should_exit=True;thread.join(5);listener.close();assert not thread.is_alive()


def test_actual_gateway_timeout_then_late_receiver_rejection_is_terminal_and_durable(receiving):
    f=receiving
    with TestClient(server.create_asgi_app(f.config)) as gateway:
        headers={'X-AgentPorter-Key':f.config.api_key}
        response=gateway.post('/api/v1/workspaces/'+plan.FIXTURE_ID+'/agents/dispatch',headers=headers,json={'agent':'copilot_agent','task':'Synthetic rejection','read_only':True})
        assert response.status_code==200,response.text
        initial=response.json();assert initial['status']=='delivery_uncertain'
        public=initial['job_id'];request_id=public.removeprefix('rjob_')
        assert f.entered.is_set() and len(f.calls)==1
        ledger=relay.RelayLedger(f.worker.state_dir)
        assert read_state(ledger,request_id)==(None,plan.FIXTURE_ID,'copilot_agent',1)
        f.release.set()
        until=time.monotonic()+3
        while read_state(ledger,request_id)[3]!=0 and time.monotonic()<until:time.sleep(.005)
        assert read_state(ledger,request_id)==(None,plan.FIXTURE_ID,'copilot_agent',0)
        status=gateway.get('/api/v1/jobs/'+public+'/status',headers=headers)
        assert status.status_code==200,status.text
        assert status.json()['status']=='failed' and status.json()['launched'] is False
        assert status.json()['launch_status']=='not_launched' and status.json()['exit_code'] is None
        for endpoint in ('output','result'):
            response=gateway.post('/api/v1/jobs/'+public+'/'+endpoint,headers=headers,json={})
            assert response.status_code==200,response.text
            result=response.json();assert result['job_id']==public and result['status']=='failed'
            assert result['launched'] is False and result['launch_status']=='not_launched'
            assert result['stdout']=='' and result['exit_code'] is None and result['eof'] is True
            assert 'SYNTHETIC-PRIVATE' not in json.dumps(result)
        receiver_reopened=relay.RelayLedger(f.worker.state_dir)
        assert receiver_reopened.reserve(request_id,plan.FIXTURE_ID,'copilot_agent')==(None,plan.FIXTURE_ID,'copilot_agent')
        code,_=f.raw('dispatch_agent',{**f.calls[0],'request_id':request_id})
        assert code==403 and len(f.calls)==1
    # Gateway restart can report its exact cached outcome without contacting the receiver.
    reopened=relay.ProductionDelegationClient('r'*43,{plan.FIXTURE_ID:str(f.root)},f.config.state_dir)
    assert read_state(reopened.ledger,request_id)==(None,plan.FIXTURE_ID,'copilot_agent',0)
    for operation in ('job_status','job_output','job_result'):
        result=reopened.call(operation,{'job_id':public})
        assert result['status']=='failed' and result['job_id']==public and result['launched'] is False
    assert len(f.calls)==1


@pytest.mark.parametrize('state',['pending','unknown','known','rejected'])
def test_receiver_only_exact_durable_no_launch_is_terminal(receiving,state):
    f=receiving;f.release.set();key='a'*32;ledger=relay.RelayLedger(f.worker.state_dir)
    if state!='unknown':ledger.reserve(key,plan.FIXTURE_ID,'copilot_agent')
    if state=='known':ledger.register(key,'job_'+'b'*24,plan.FIXTURE_ID,'copilot_agent');ledger.mark_terminal('job_'+'b'*24)
    if state=='rejected':ledger.mark_no_launch(key)
    code,result=f.raw('lookup_dispatch',{'request_id':key});assert code==200
    expected={'pending':'delivery_uncertain','unknown':'delivery_uncertain','known':'known','rejected':'not_launched'}
    assert result['status']==expected[state]
    if state=='known':assert result['job_id']=='job_'+'b'*24
    if state=='rejected':assert result=={'job_id':None,'status':'not_launched','workspace_id':plan.FIXTURE_ID,'agent':'copilot_agent'}


def test_receiver_denies_malformed_or_outside_scope_lookup(receiving):
    f=receiving;f.release.set();ledger=relay.RelayLedger(f.worker.state_dir)
    ledger.reserve('a'*32,'outside','copilot_agent');ledger.mark_no_launch('a'*32)
    for args in ({'request_id':'not-canonical'},{'request_id':'a'*32},{'request_id':'b'*32,'workspace_id':'outside'}):
        assert f.raw('lookup_dispatch',args)[0]==403


@pytest.mark.parametrize('remote_scope',[('other','copilot_agent'),('workspace','agy_agent')])
def test_client_does_not_accept_rejection_for_another_scope(tmp_path,monkeypatch,remote_scope):
    client=relay.ProductionDelegationClient('synthetic',{'workspace':'/synthetic'},tmp_path)
    client.ledger.reserve('a'*32,'workspace','copilot_agent')
    class Reply:
        status=200
        def read(self,_):return json.dumps({'job_id':None,'status':'not_launched','workspace_id':remote_scope[0],'agent':remote_scope[1]}).encode()
    class Connection:
        def __init__(self,*args,**kw):pass
        def request(self,*args,**kw):pass
        def getresponse(self):return Reply()
        def close(self):pass
    monkeypatch.setattr(relay.http.client,'HTTPConnection',Connection)
    with pytest.raises(PermissionError,match='ownership differs'):client.call('job_status',{'job_id':'rjob_'+'a'*32})
    assert client.ledger.get_request_state('a'*32)==(None,'workspace','copilot_agent',1)
    with pytest.raises(PermissionError):client.call('lookup_dispatch',{'request_id':'b'*32})


def test_rejected_output_bounds_and_original_tuple_contract(tmp_path):
    client=relay.ProductionDelegationClient('synthetic',{'workspace':'/synthetic'},tmp_path)
    client.ledger.reserve('a'*32,'workspace','copilot_agent');client.ledger.mark_no_launch('a'*32)
    assert client.ledger.get_request('a'*32)==(None,'workspace','copilot_agent')
    bounded=client.call('job_result',{'job_id':'rjob_'+'a'*32,'max_bytes':1,'cursor':3})
    assert bounded['stdout']=='' and bounded['stderr']=='D' and bounded['next_cursor']==3 and bounded['eof'] is True
    for bad in ({'cursor':-1},{'cursor':True},{'max_bytes':0},{'extra':'denied'}):
        with pytest.raises(PermissionError):client.call('job_result',{'job_id':'rjob_'+'a'*32,**bad})


@pytest.mark.parametrize('worker_state',['pending','unknown'])
def test_client_pending_and_unknown_receiver_outcomes_stay_uncertain(receiving,worker_state):
    f=receiving;f.release.set();key='a'*32
    client=relay.ProductionDelegationClient('r'*43,{plan.FIXTURE_ID:str(f.root)},f.config.state_dir)
    client.ledger.reserve(key,plan.FIXTURE_ID,'copilot_agent')
    if worker_state=='pending':relay.RelayLedger(f.worker.state_dir).reserve(key,plan.FIXTURE_ID,'copilot_agent')
    for operation in ('job_status','job_output','job_result'):
        result=client.call(operation,{'job_id':'rjob_'+key})
        assert result['status']=='delivery_uncertain' and result['job_id']=='rjob_'+key
    assert client.ledger.get_request_state(key)[3]==1 and f.calls==[]


def test_cleanup_failure_is_not_a_verified_no_launch(receiving):
    from agentporter.resources import ResourceCleanupError
    f=receiving;f.refusal[0]=ResourceCleanupError('synthetic cleanup not verified');f.release.set()
    client=relay.ProductionDelegationClient('r'*43,{plan.FIXTURE_ID:str(f.root)},f.config.state_dir)
    result=client.call('dispatch_agent',{'agent':'copilot_agent','workspace_id':plan.FIXTURE_ID,'task':'synthetic cleanup refusal','read_only':True})
    assert result['status']=='delivery_uncertain'
    key=result['job_id'].removeprefix('rjob_')
    assert relay.RelayLedger(f.worker.state_dir).get_request_state(key)==(None,plan.FIXTURE_ID,'copilot_agent',1)
    assert client.call('job_status',{'job_id':result['job_id']})['status']=='delivery_uncertain'
    assert len(f.calls)==1


def test_cached_rejection_cannot_bypass_removed_gateway_scope(tmp_path):
    client=relay.ProductionDelegationClient('synthetic',{'workspace':'/synthetic'},tmp_path)
    client.ledger.reserve('a'*32,'workspace','copilot_agent');client.ledger.mark_no_launch('a'*32)
    narrowed=relay.ProductionDelegationClient('synthetic',{},tmp_path)
    with pytest.raises(PermissionError,match='outside current workspace scope'):
        narrowed.call('job_status',{'job_id':'rjob_'+'a'*32})
