"""Owned native relay cancellation; synthetic auth and local HTTP only."""
import json
import time
import pytest
from agentporter.agents import production_relay as relay
from tests.security.test_development_runtime import runtime_factory
from tests.security.relay_fixture import inputs, plan
from tests.security.test_relay_no_launch_recovery import receiving


def test_real_gateway_receiver_cancel_native_job_and_reuse_admission(tmp_path,monkeypatch,runtime_factory,request):
    import socket
    import threading
    import time
    from types import SimpleNamespace
    import uvicorn
    import yaml
    from fastapi.testclient import TestClient
    from agentporter import server
    from agentporter.agents import production_relay
    from agentporter.agents.policy import ExecutionPolicy
    from agentporter.config import Config
    from agentporter.tools.jobs import JobManager
    from agentporter.workspaces.registry import WorkspaceRegistry
    from tests.security.test_async_workspace_transactions import wait
    from tests.security.test_development_runtime import no_probe
    from tests.security.test_workspace_transactions import RecordingResources

    runtime, _, _, fixture, unrelated = runtime_factory()
    no_probe(monkeypatch, runtime)
    monkeypatch.setattr(runtime, 'require_production_egress', lambda agent=None: frozenset({'codex_impl'}))
    monkeypatch.setattr(plan, 'FIXTURE', str(fixture))
    worker, gateway = inputs()
    other = tmp_path / 'other'; other.mkdir(exist_ok=True)
    worker['workspaces.yaml']['workspaces'] = {}
    worker['public-client-policy.yaml']['workspaces'] = {}
    worker['development-runtime.yaml']['allowed_workspace_roots'] = [{'path': str(other), 'writable': False}]
    gateway['workspaces.yaml']['workspaces'] = {}
    gateway['public-client-policy.yaml']['workspaces'] = {}
    worker, gateway = plan.prepare(worker, gateway, agents=['codex_impl'])
    def save_docs(root, docs):
        root.mkdir()
        for name, value in docs.items():
            path = root / name
            path.write_text(yaml.safe_dump(value)); path.chmod(0o600)
        key = root / 'delegation-relay.key'; key.write_text('r' * 43); key.chmod(0o600)
    worker_config = tmp_path / 'worker-config'; save_docs(worker_config, worker)
    gateway_config = tmp_path / 'gateway-config'; save_docs(gateway_config, gateway)
    worker_state = tmp_path / 'worker-state'; worker_state.mkdir()
    wconfig = Config(config_dir=worker_config, state_dir=worker_state, cache_dir=tmp_path / 'worker-cache')
    manager = JobManager(runtime.state_dir, transactional_writes=True)
    manager.development_runtime = runtime
    from tests.security.test_workspace_transactions import RecordingLease
    class FreshResources:
        def __init__(self):self.leases=[]
        def create(self):
            lease=RecordingLease();self.leases.append(lease);return lease
    manager.resources = FreshResources()
    def stop_jobs():
        for job in list(manager.active_processes):manager.cancel(job)
    request.addfinalizer(stop_jobs)
    registry = WorkspaceRegistry(worker['workspaces.yaml']['workspaces'])
    # Every supervised job now holds a private workspace transaction, including
    # read-only jobs. Keep the unrelated process on its own registered fixture
    # so this cancellation test does not bypass same-workspace serialization.
    registry.register('unrelated',str(unrelated),writable=False,allow_agent_dispatch=True)
    # Match AgentBroker construction: the launcher and receiving API share the
    # authoritative registry, including the planner's canonical fixture ID.
    runtime.workspace_registry = registry
    def dispatch(**args):
        assert args['read_only'] is False
        script = ("from pathlib import Path; import time; Path('/workspace/source.txt').write_text('PRIVATE_CANCEL_EDIT'); print('CANCEL_READY',flush=True); time.sleep(60)"
                  if args['task']=='wait' else "print('CLEAN_AFTER_CANCEL',flush=True)")
        job = manager.start_confined_agent_job(agent='codex_impl', workspace_id=plan.FIXTURE_ID,
            workspace_path=str(fixture), cmd=['/usr/bin/python3', '-c', script],
            policy=ExecutionPolicy.for_workspace(writable=True))
        return {'job_id': job, 'status': 'running'}
    context = {'client_policy': SimpleNamespace(scopes=None, internal_key=None), 'registry': registry,
        'agent_broker': SimpleNamespace(development_runtime=runtime), 'delegation_relay_client': None,
        'job_manager': manager, 'tools': {'dispatch_agent': dispatch,
            'job_status': lambda job_id: manager.get_status(job_id),
            'job_output': lambda **args: manager.get_output(**args),
            'job_result': lambda **args: manager.get_result(**args)}}
    original_build = server.build_mcp_server
    monkeypatch.setattr(server, 'build_mcp_server', lambda _: (server.MCPServer('worker-fixture'), context))
    worker_app = server.create_asgi_app(wconfig)
    monkeypatch.setattr(server, 'build_mcp_server', original_build)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0)); listener.listen(16)
    port = listener.getsockname()[1]
    worker_server = uvicorn.Server(uvicorn.Config(worker_app, log_level='error', lifespan='off'))
    thread = threading.Thread(target=worker_server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    def stop_worker():
        worker_server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), 'Fixture worker failed to stop'
    request.addfinalizer(stop_worker)
    deadline = time.monotonic() + 10
    while not worker_server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker_server.started, 'Fixture worker failed to start'
    original_connection = production_relay.http.client.HTTPConnection
    probe = original_connection('127.0.0.1', port, timeout=3)
    probe.request('POST', '/internal/delegation/v1', body='{}', headers={'Content-Type': 'application/json'})
    assert probe.getresponse().status == 401
    probe.close()
    def connection(host, requested_port, timeout):
        assert (host, requested_port, timeout) == ('127.0.0.1', 8876, 8)
        return original_connection(host, port, timeout=timeout)
    monkeypatch.setattr(production_relay.http.client, 'HTTPConnection', connection)
    gconfig = Config(config_dir=gateway_config, state_dir=tmp_path / 'gateway-state', cache_dir=tmp_path / 'gateway-cache')
    gconfig.security.allowed_hosts.append('testserver')
    app = server.create_asgi_app(gconfig)
    with TestClient(app) as client:
        headers={'X-AgentPorter-Key':gconfig.api_key}
        endpoint=f'/api/v1/workspaces/{plan.FIXTURE_ID}/agents/dispatch'
        response=client.post(endpoint,headers=headers,json={'agent':'codex_impl','task':'wait','read_only':False})
        assert response.status_code==200,response.text
        public=response.json()['job_id'];gateway_ledger=relay.RelayLedger(gconfig.state_dir)
        jid=gateway_ledger.get_request(public.removeprefix('rjob_'))[0]
        until=time.monotonic()+5
        while 'CANCEL_READY' not in manager.get_output(jid)['stdout'] and time.monotonic()<until:time.sleep(.01)
        assert 'CANCEL_READY' in manager.get_output(jid)['stdout']
        assert manager.get_status(jid)['status']=='running'
        assert (fixture/'source.txt').read_text()=='source'
        receiver_ledger=relay.RelayLedger(worker_state)
        with receiver_ledger._db() as db:db.execute('UPDATE jobs SET workspace_id=? WHERE remote_id=?',('outside',jid))
        denied=client.post(f'/api/v1/jobs/{public}/cancel',headers=headers)
        assert denied.status_code==403 and manager.get_status(jid)['status']=='running'
        with receiver_ledger._db() as db:db.execute('UPDATE jobs SET workspace_id=? WHERE remote_id=?',(plan.FIXTURE_ID,jid))
        # The original public rjob is valid, but mismatched protected receiver
        # ownership must reject before the owned process is signalled.
        with receiver_ledger._db() as db:db.execute('UPDATE jobs SET agent=? WHERE remote_id=?',('copilot_agent',jid))
        denied=client.post(f'/api/v1/jobs/{public}/cancel',headers=headers)
        assert denied.status_code==403,denied.text
        assert manager.get_status(jid)['status']=='running'
        with receiver_ledger._db() as db:db.execute('UPDATE jobs SET agent=? WHERE remote_id=?',('codex_impl',jid))
        # A well-formed remote ID without a relay reservation is never authority.
        # A distinct synthetic account also preserves the exclusive credential
        # lease held by the cancellable job; neither admission boundary should
        # be disabled merely to create the unrelated cancellation target.
        unowned=manager.start_confined_agent_job(agent='codex_review',workspace_id='unrelated',workspace_path=str(unrelated),
            cmd=['/usr/bin/python3','-c',"import time;print('UNRELATED_READY',flush=True);time.sleep(60)"],
            policy=ExecutionPolicy.for_workspace(writable=False))
        def raw_cancel(arguments):
            connection=original_connection('127.0.0.1',port,timeout=3)
            try:
                connection.request('POST','/internal/delegation/v1',body=json.dumps({'operation':'job_cancel','args':arguments}),headers={'Authorization':'Bearer '+'r'*43,'Content-Type':'application/json'})
                response=connection.getresponse();response.read();return response.status
            finally:connection.close()
        assert raw_cancel({'job_id':unowned})==403
        assert manager.get_status(unowned)['status']=='running'
        for extra in ({'pid':123},{'workspace_id':'outside'},{'cursor':0},{'max_bytes':1}):
            assert raw_cancel({'job_id':jid,**extra})==403
        assert client.post('/api/v1/jobs/rjob_'+'a'*32+'/cancel',headers=headers).status_code==403
        assert client.post(f'/api/v1/jobs/{jid}/cancel',headers=headers).status_code==403
        cancelled=client.post(f'/api/v1/jobs/{public}/cancel',headers=headers)
        assert cancelled.status_code==200,cancelled.text
        assert cancelled.json()['job_id']==public and cancelled.json()['status'] in {'cancelling','cancelled'}
        assert wait(manager,jid)['status']=='cancelled'
        assert (fixture/'source.txt').read_text()=='source'
        status=client.get(f'/api/v1/jobs/{public}/status',headers=headers)
        assert status.status_code==200 and status.json()['status']=='cancelled'
        again=client.post(f'/api/v1/jobs/{public}/cancel',headers=headers)
        assert again.status_code==200 and again.json()['job_id']==public and again.json()['status']=='cancelled'
        manager.cancel(unowned);assert wait(manager,unowned)['status']=='cancelled'
        next_job=client.post(endpoint,headers=headers,json={'agent':'codex_impl','task':'clean','read_only':False})
        assert next_job.status_code==200,next_job.text
        next_public=next_job.json()['job_id'];next_jid=gateway_ledger.get_request(next_public.removeprefix('rjob_'))[0]
        assert wait(manager,next_jid)['status']=='completed'
        assert 'CLEAN_AFTER_CANCEL' in manager.get_output(next_jid)['stdout']
        assert (fixture/'source.txt').read_text()=='source'
        with manager._get_db() as db:assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0
        assert len(manager.resources.leases)==3 and all(lease.closed for lease in manager.resources.leases)


def test_cancel_of_durable_rejection_is_idempotent_and_has_original_public_id(receiving):
    from agentporter import server
    from fastapi.testclient import TestClient
    f=receiving
    with TestClient(server.create_asgi_app(f.config)) as client:
        headers={'X-AgentPorter-Key':f.config.api_key}
        dispatch=client.post('/api/v1/workspaces/'+plan.FIXTURE_ID+'/agents/dispatch',headers=headers,
            json={'agent':'copilot_agent','task':'Synthetic no child','read_only':True})
        assert dispatch.status_code==200,dispatch.text
        assert dispatch.json()['status']=='delivery_uncertain'
        public=dispatch.json()['job_id'];key=public.removeprefix('rjob_');f.release.set()
        worker=relay.RelayLedger(f.worker.state_dir)
        until=time.monotonic()+3
        while worker.get_request_state(key)[3]!=0 and time.monotonic()<until:time.sleep(.005)
        assert worker.get_request_state(key)[0] is None and worker.get_request_state(key)[3]==0
        for _ in range(2):
            response=client.post(f'/api/v1/jobs/{public}/cancel',headers=headers)
            assert response.status_code==200,response.text
            result=response.json()
            assert result['job_id']==public and result['status']=='failed' and result['launched'] is False
            assert result['launch_status']=='not_launched'
    assert len(f.calls)==1


@pytest.mark.parametrize('extra',[{'pid':1},{'cursor':0},{'max_bytes':1},{'workspace_id':'workspace'}])
def test_client_cancel_args_are_closed(tmp_path,extra):
    client=relay.ProductionDelegationClient('synthetic',{'workspace':'/synthetic'},tmp_path)
    client.ledger.reserve('a'*32,'workspace','codex_impl');client.ledger.mark_no_launch('a'*32)
    with pytest.raises(PermissionError,match='only an issued relay job'):
        client.call('job_cancel',{'job_id':'rjob_'+'a'*32,**extra})


def test_pending_cancellation_does_not_invent_a_child_or_terminal_outcome(receiving):
    f=receiving;f.release.set();key='a'*32
    client=relay.ProductionDelegationClient('r'*43,{plan.FIXTURE_ID:str(f.root)},f.config.state_dir)
    client.ledger.reserve(key,plan.FIXTURE_ID,'copilot_agent')
    worker=relay.RelayLedger(f.worker.state_dir);worker.reserve(key,plan.FIXTURE_ID,'copilot_agent')
    result=client.call('job_cancel',{'job_id':'rjob_'+key})
    assert result['status']=='delivery_uncertain' and result['job_id']=='rjob_'+key
    assert worker.get_request_state(key)[3]==1 and f.calls==[]
