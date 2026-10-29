"""Fixture-only relay planning must preserve existing grants and require isolation."""
import copy
import importlib.util
from pathlib import Path
import pytest
from tests.security.test_development_runtime import runtime_factory

path = Path(__file__).resolve().parents[2] / 'scripts/prepare-bcc-canonical-relay-fixture.py'
spec = importlib.util.spec_from_file_location('bcc_canonical_relay_plan', path)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def inputs():
    worker = {'config.yaml': {'sandbox': {'workspace_transactions': True}},
              'workspaces.yaml': {'workspaces': {'existing': {'path': '/existing'}}},
              'public-client-policy.yaml': {'version': 1, 'workspaces': {'existing': {'path': '/existing', 'operations': ['read']}}},
              'development-runtime.yaml': {'enabled': True, 'profile': 'development', 'network_enabled': True,
                  'egress_policy': 'provider_origin', 'public_client_policy_required': True,
                  'job_resources': {'memory_bytes': 2147483648, 'pids': 128,
                                    'cpu_quota_us': 200000, 'cpu_period_us': 100000},
                  'allowed_workspace_roots': [{'path': '/existing', 'writable': False}]}}
    gateway = {'workspaces.yaml': {'workspaces': {'other': {'path': '/other'}}},
               'public-client-policy.yaml': {'version': 1, 'workspaces': {'other': {'path': '/other', 'operations': ['read']}}}}
    return worker, gateway


def test_plan_keeps_baseline_and_scopes_fixture_only():
    worker, gateway = inputs(); baseline = copy.deepcopy((worker, gateway))
    w, g = plan.prepare(worker, gateway, agents=['phil'])
    assert (worker, gateway) == baseline
    assert w['workspaces.yaml']['workspaces']['existing'] == worker['workspaces.yaml']['workspaces']['existing']
    assert g['public-client-policy.yaml']['workspaces']['other'] == gateway['public-client-policy.yaml']['workspaces']['other']
    assert plan.FIXTURE_ID not in w['public-client-policy.yaml']['workspaces']
    assert g['public-client-policy.yaml']['workspaces'][plan.FIXTURE_ID]['operations'] == ['read', 'write', 'dispatch', 'dispatch_write']
    assert w['delegation-relay-scope.yaml']['workspaces'] == g['delegation-relay-write-scope.yaml']['workspaces'] == {plan.FIXTURE_ID: plan.FIXTURE}
    assert w['development-runtime.yaml']['production_relay_agents'] == ['phil']


@pytest.mark.parametrize('mutation', ['transactions', 'network', 'public_policy', 'bad_budget', 'existing_relay', 'existing_admissions', 'collision', 'duplicate_agent'])
def test_plan_refuses_unsafe_or_ambiguous_baseline(mutation):
    w, g = inputs(); agents = ['phil']
    if mutation == 'transactions': w['config.yaml']['sandbox']['workspace_transactions'] = False
    if mutation == 'network': w['development-runtime.yaml']['network_enabled'] = False
    if mutation == 'public_policy': w['development-runtime.yaml']['public_client_policy_required'] = False
    if mutation == 'bad_budget': w['development-runtime.yaml']['job_resources']['pids'] = 999999
    if mutation == 'existing_relay': g['delegation-upstream.yaml'] = {}
    if mutation == 'existing_admissions': w['development-runtime.yaml']['production_relay_agents'] = ['liz']
    if mutation == 'collision': w['workspaces.yaml']['workspaces']['other'] = {'path': plan.FIXTURE}
    if mutation == 'duplicate_agent': agents = ['phil', 'phil']
    with pytest.raises((ValueError, PermissionError)):
        plan.prepare(w, g, agents=agents)


def test_generated_policies_load_and_public_worker_write_is_denied(tmp_path, monkeypatch):
    import yaml
    from agentporter.agents.development import DevelopmentRuntime
    from agentporter.agents.production_relay import read_relay_scope, relay_upstream_workspaces
    from agentporter.client_policy import PRINCIPAL, PublicClientPolicy
    from agentporter.workspaces.registry import WorkspaceRegistry

    fixture = tmp_path / 'fixture'; fixture.mkdir()
    existing = tmp_path / 'existing'; existing.mkdir()
    other = tmp_path / 'other'; other.mkdir()
    monkeypatch.setattr(plan, 'FIXTURE', str(fixture))
    worker, gateway = inputs()
    for document in ('workspaces.yaml', 'public-client-policy.yaml'):
        worker[document]['workspaces']['existing']['path'] = str(existing)
        gateway[document]['workspaces']['other']['path'] = str(other)
    worker['development-runtime.yaml']['allowed_workspace_roots'][0]['path'] = str(existing)
    w, g = plan.prepare(worker, gateway, agents=['phil'])
    for label, docs in [('worker', w), ('gateway', g)]:
        root = tmp_path / label; root.mkdir()
        config = root / 'config'; config.mkdir()
        state = root / 'state'; state.mkdir()
        for name, document in docs.items():
            file = config / name
            file.write_text(yaml.safe_dump(document))
            file.chmod(0o600)
        registry = WorkspaceRegistry(docs['workspaces.yaml']['workspaces'])
        policy = PublicClientPolicy(config, state, registry)
        token = PRINCIPAL.set('public')
        try:
            request = {'workspace_id': plan.FIXTURE_ID, 'agent': 'phil', 'task': 'fixture', 'read_only': False}
            if label == 'worker':
                with pytest.raises(PermissionError):
                    policy.check('dispatch_agent', request)
                assert read_relay_scope(config) == {plan.FIXTURE_ID: str(fixture)}
                assert DevelopmentRuntime._allowed_workspace_roots(docs['development-runtime.yaml'])[fixture] is True
            else:
                policy.check('dispatch_agent', request)
                assert relay_upstream_workspaces(config) == frozenset({plan.FIXTURE_ID})
            assert read_relay_scope(config, writable=True) == {plan.FIXTURE_ID: str(fixture)}
        finally:
            PRINCIPAL.reset(token)


@pytest.mark.parametrize('fail', [False, True])
def test_planned_public_gateway_reaches_transactional_relay_worker(tmp_path, monkeypatch, runtime_factory, fail, request):
    """REST policy, relay handshake and real sandboxed transaction share one fixture."""
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

    runtime, _, _, fixture, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    monkeypatch.setattr(runtime, 'require_production_egress', lambda agent=None: frozenset({'liz'}))
    monkeypatch.setattr(plan, 'FIXTURE', str(fixture))
    worker, gateway = inputs()
    other = tmp_path / 'other'; other.mkdir(exist_ok=True)
    worker['workspaces.yaml']['workspaces'] = {}
    worker['public-client-policy.yaml']['workspaces'] = {}
    worker['development-runtime.yaml']['allowed_workspace_roots'] = [{'path': str(other), 'writable': False}]
    gateway['workspaces.yaml']['workspaces'] = {}
    gateway['public-client-policy.yaml']['workspaces'] = {}
    worker, gateway = plan.prepare(worker, gateway, agents=['liz'])
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
    manager.development_runtime = runtime; manager.resources = RecordingResources()
    registry = WorkspaceRegistry(worker['workspaces.yaml']['workspaces'])
    def dispatch(**args):
        assert args['read_only'] is False
        script = "from pathlib import Path; Path('/workspace/source.txt').write_text('through-relay'); print('RELAY_FIXTURE_LOG', flush=True)"
        if fail:
            script += '; raise SystemExit(7)'
        job = manager.start_confined_agent_job(agent='liz', workspace_id=plan.FIXTURE_ID,
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
        endpoint = f'/api/v1/workspaces/{plan.FIXTURE_ID}/agents/dispatch'
        dispatch_request = {'agent': 'liz', 'task': 'fixture edit', 'read_only': False}
        assert client.post(endpoint, json=dispatch_request).status_code == 401
        denied = client.post(endpoint, headers={'X-AgentPorter-Key': gconfig.api_key},
                             json={**dispatch_request, 'allow_push': True})
        assert denied.status_code == 403
        assert (fixture / 'source.txt').read_text() == 'source'
        response = client.post(endpoint,
            headers={'X-AgentPorter-Key': gconfig.api_key},
            json=dispatch_request)
        assert response.status_code == 200, response.text
        public_id = response.json()['job_id']
        remote_id = production_relay.RelayLedger(gconfig.state_dir).get_request(public_id.removeprefix('rjob_'))[0]
        result = wait(manager, remote_id)
        expected_status = 'failed' if fail else 'completed'
        assert result['status'] == expected_status, result
        assert (fixture / 'source.txt').read_text() == ('source' if fail else 'through-relay')
        headers = {'X-AgentPorter-Key': gconfig.api_key}
        status = client.get(f'/api/v1/jobs/{public_id}/status', headers=headers)
        assert status.status_code == 200 and status.json()['status'] == expected_status
        output = client.post(f'/api/v1/jobs/{public_id}/output', headers=headers, json={})
        assert output.status_code == 200 and 'RELAY_FIXTURE_LOG' in output.json()['stdout']
