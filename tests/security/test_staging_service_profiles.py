"""Only synthetic cgroups/configs and mocked HTTP; never starts a service."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from agentporter import resource_supervisor as supervisor, resources, server
from agentporter.agents import production_relay as relay
from agentporter.config import Config

PROD_G = 'agentporter-gateway.service'
PROD_W = 'agentporter-worker.service'
STAGE_G = 'agentporter-staging-gateway.service'
STAGE_W = 'agentporter-staging-worker.service'
BUDGET = {'memory_bytes': 2 * 1024**3, 'pids': 128, 'cpu_quota_us': 200000, 'cpu_period_us': 100000}


@pytest.fixture(autouse=True)
def synthetic_identities(tmp_path, monkeypatch):
    for field in ('CONFIG', 'STATE', 'CACHE'):
        monkeypatch.setenv('AGENTPORTER_' + field + '_DIR', str(tmp_path / field.lower()))


def membership(monkeypatch, unit):
    original = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/proc/self/cgroup':
            return '0::/system.slice/' + unit + '/supervisor\n'
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)


@pytest.mark.parametrize('unit,role,port,peer', [
    (PROD_G, 'gateway', 8765, 8876), (PROD_W, 'worker', 8876, None),
    (STAGE_G, 'gateway', 18765, 18876), (STAGE_W, 'worker', 18876, None),
    ('agentporter-development.service', 'worker', 8876, None),
])
def test_exact_service_mapping(unit, role, port, peer):
    assert hasattr(supervisor, 'service_profile'), 'Missing bounded staging profile'
    assert supervisor.service_profile(unit) == (role, port, peer)


@pytest.mark.parametrize('unit', ['other.service', '../' + STAGE_G, STAGE_G + '/child', '', None])
def test_arbitrary_service_profile_refused(unit):
    assert hasattr(supervisor, 'service_profile')
    with pytest.raises(PermissionError):
        supervisor.service_profile(unit)


@pytest.mark.parametrize('unit,port', [(PROD_G,8765),(PROD_W,8876),(STAGE_G,18765),(STAGE_W,18876)])
def test_supervisor_exec_uses_fixed_role_port(monkeypatch, unit, port):
    monkeypatch.setattr(supervisor, 'enter_supervisor', lambda: Path('/sys/fs/cgroup/system.slice') / unit)
    monkeypatch.setattr(sys, 'argv', ['supervisor', '--config-dir', '/synthetic/config'])
    calls = []
    monkeypatch.setattr(supervisor.os, 'execv', lambda executable, argv: calls.append(argv))
    supervisor.main()
    argv = calls[0]
    assert argv[argv.index('--host') + 1] == '127.0.0.1'
    assert argv[argv.index('--port') + 1] == str(port)


def fake_cgroup(tmp_path, monkeypatch, unit):
    mount = tmp_path / 'cgroup'
    root = mount / 'system.slice' / unit
    root.mkdir(parents=True)
    (root / 'cgroup.controllers').write_text('cpu memory pids')
    (root / 'cgroup.subtree_control').write_text('')
    member = tmp_path / 'membership'
    member.write_text('0::/system.slice/' + unit + '/supervisor\n')
    original = Path
    def fake_path(value):
        if str(value) == '/proc/self/cgroup':
            return member
        if str(value) == '/sys/fs/cgroup':
            return mount
        return original(value)
    monkeypatch.setattr(resources, 'Path', fake_path)
    return root


@pytest.mark.parametrize('unit', [STAGE_G, STAGE_W])
def test_staging_resources_exact_service(tmp_path, monkeypatch, unit):
    root = fake_cgroup(tmp_path, monkeypatch, unit)
    item = resources.JobResources(BUDGET, expected_service=unit)
    assert item.root == root
    assert (root / 'cgroup.subtree_control').read_text() == '+cpu +memory +pids'


@pytest.mark.parametrize('actual,expected', [(STAGE_G,STAGE_W),(STAGE_W,STAGE_G),
    (STAGE_G,PROD_G),(PROD_G,STAGE_G),(STAGE_W,None),(STAGE_G,None),(STAGE_G,'arbitrary.service')])
def test_resource_cross_role_and_missing_selection_refused(tmp_path, monkeypatch, actual, expected):
    root = fake_cgroup(tmp_path, monkeypatch, actual)
    with pytest.raises(PermissionError):
        resources.JobResources(BUDGET, expected_service=expected)
    assert (root / 'cgroup.subtree_control').read_text() == ''


@pytest.mark.parametrize('unit', [STAGE_G,STAGE_W])
def test_staging_supervisor_retains_exclusive_cgroup_checks(tmp_path, unit):
    mount = tmp_path / 'cgroup'
    root = mount / 'system.slice' / unit
    root.mkdir(parents=True)
    (root / 'cgroup.controllers').write_text('cpu memory pids')
    (root / 'cgroup.procs').write_text('')
    (root / 'supervisor').mkdir(mode=0o700)
    (root / 'supervisor/cgroup.procs').write_text(str(os.getpid()))
    member = tmp_path / 'membership'
    member.write_text('0::/system.slice/' + unit + '/supervisor')
    assert supervisor.enter_supervisor(cgroup_mount=mount, membership_file=member) == root
    (root / 'supervisor/cgroup.procs').write_text('99999')
    with pytest.raises(PermissionError, match='exclusive'):
        supervisor.enter_supervisor(cgroup_mount=mount, membership_file=member)


def config_doc(tmp_path, port):
    cfg = Config(config_dir=tmp_path / 'config', state_dir=tmp_path / 'state', cache_dir=tmp_path / 'cache')
    cfg.server.port = port
    policy = cfg.config_dir / 'public-client-policy.yaml'
    policy.write_text('version: 1\nworkspaces: {}\n')
    policy.chmod(0o600)
    return cfg


class ReachedResources(RuntimeError):
    pass


@pytest.mark.parametrize('role,port,unit', [('gateway',8765,PROD_G),('gateway',18765,STAGE_G),('worker',18876,STAGE_W)])
def test_server_selects_exact_resource_profile(tmp_path, monkeypatch, role, port, unit):
    cfg = config_doc(tmp_path, port)
    monkeypatch.setattr(resources, 'load_gateway_job_resources', lambda _: BUDGET if role == 'gateway' else None)
    if role == 'worker':
        original = server.AgentBroker
        def broker(*args, **kwargs):
            item = original(*args, **kwargs)
            item.development_runtime = SimpleNamespace(_config=lambda: {'job_resources': BUDGET})
            return item
        monkeypatch.setattr(server, 'AgentBroker', broker)
    def resource(settings, *, expected_service):
        assert expected_service == unit
        raise ReachedResources()
    monkeypatch.setattr(server, 'JobResources', resource)
    with pytest.raises(ReachedResources):
        server.build_mcp_server(cfg)


@pytest.mark.parametrize('role,port', [('gateway',18876),('gateway',12345),('worker',18765),('worker',12345)])
def test_server_rejects_cross_role_port_config(tmp_path, monkeypatch, role, port):
    cfg = config_doc(tmp_path, port)
    monkeypatch.setattr(resources, 'load_gateway_job_resources', lambda _: BUDGET if role == 'gateway' else None)
    if role == 'worker':
        original = server.AgentBroker
        def broker(*args, **kwargs):
            item = original(*args, **kwargs)
            item.development_runtime = SimpleNamespace(_config=lambda: {'job_resources': BUDGET})
            return item
        monkeypatch.setattr(server, 'AgentBroker', broker)
    monkeypatch.setattr(server, 'JobResources', lambda *args, **kwargs: pytest.fail('Invalid profile reached resources'))
    with pytest.raises(PermissionError):
        server.build_mcp_server(cfg)


@pytest.mark.parametrize('service,port', [(PROD_G,8876),(STAGE_G,18876)])
def test_upstream_config_matches_exact_gateway_service(tmp_path, service, port):
    cfg = tmp_path / 'config'
    cfg.mkdir(mode=0o700)
    file = cfg / 'delegation-upstream.yaml'
    file.write_text(json.dumps({'version':1,'host':'127.0.0.1','port':port,'workspaces':['agentporter']}))
    file.chmod(0o600)
    assert relay.relay_upstream_workspaces(cfg, service_unit=service) == frozenset({'agentporter'})


@pytest.mark.parametrize('service,port', [(STAGE_G,8876),(PROD_G,18876),(STAGE_W,18876),(STAGE_G,1)])
def test_upstream_cross_role_or_port_refused(tmp_path, service, port):
    cfg = tmp_path / 'config'
    cfg.mkdir(mode=0o700)
    file = cfg / 'delegation-upstream.yaml'
    file.write_text(json.dumps({'version':1,'host':'127.0.0.1','port':port,'workspaces':['agentporter']}))
    file.chmod(0o600)
    with pytest.raises(PermissionError):
        relay.relay_upstream_workspaces(cfg, service_unit=service)


@pytest.mark.parametrize('unit,port', [(STAGE_G,18876),(PROD_G,8876)])
def test_client_requests_exact_mapped_loopback_port(tmp_path, monkeypatch, unit, port):
    membership(monkeypatch, unit)
    calls = []
    class Connection:
        def __init__(self, host, selected_port, timeout):
            calls.append((host, selected_port))
        def request(self, *args, **kwargs): pass
        def close(self): pass
        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda _: b'[]')
    monkeypatch.setattr(relay.http.client, 'HTTPConnection', Connection)
    client = relay.ProductionDelegationClient('synthetic', {'p':'/approved'}, tmp_path, port=port, service_unit=unit)
    assert client.call('list_agents') == []
    assert calls == [('127.0.0.1', port)]


@pytest.mark.parametrize('actual,selected,port', [(PROD_G,STAGE_G,18876),(STAGE_W,STAGE_G,18876),
    (STAGE_G,STAGE_G,8876),(STAGE_G,PROD_G,18876),(STAGE_G,'arbitrary.service',18876),
    (STAGE_G,None,18876),(STAGE_G,None,8876),(STAGE_G,PROD_G,8876),
    (STAGE_G + '/apj_00000000000000000000000000000000',None,8876)])
def test_staging_client_refuses_cgroup_service_port_mismatch(tmp_path, monkeypatch, actual, selected, port):
    membership(monkeypatch, actual)
    with pytest.raises(PermissionError):
        relay.ProductionDelegationClient('synthetic', {'p':'/approved'}, tmp_path, port=port, service_unit=selected)


@pytest.mark.parametrize('port,host', [(18765,'0.0.0.0'), (18876,'::'), (18765,'127.0.0.1')])
def test_staging_refuses_missing_or_nonloopback_resource_profile(tmp_path, monkeypatch, port, host):
    cfg = config_doc(tmp_path, port)
    cfg.server.host = host
    monkeypatch.setattr(resources, 'load_gateway_job_resources', lambda _: None)
    with pytest.raises(PermissionError, match='Staging requires'):
        server.build_mcp_server(cfg)


def test_staging_server_passes_profile_to_config_reader_and_client(tmp_path, monkeypatch):
    cfg = config_doc(tmp_path, 18765)
    root = tmp_path / 'workspace'
    root.mkdir()
    cfg.workspaces = {'p': {'path': str(root), 'writable': True, 'allow_agent_dispatch': True}}
    policy = cfg.config_dir / 'public-client-policy.yaml'
    policy.write_text(json.dumps({'version': 1, 'workspaces': {
        'p': {'path': str(root), 'operations': ['read','write','dispatch','dispatch_write']}}}))
    monkeypatch.setattr(resources, 'load_gateway_job_resources', lambda _: BUDGET)
    class FakeResources:
        def __init__(self, settings, *, expected_service):
            assert expected_service == STAGE_G
        def recover(self): pass
    monkeypatch.setattr(server, 'JobResources', FakeResources)
    observed = []
    def upstream(config_dir, *, service_unit):
        observed.append(('reader', service_unit))
        return frozenset({'p'})
    monkeypatch.setattr(server, 'relay_upstream_workspaces', upstream)
    monkeypatch.setattr(server, 'read_relay_key', lambda _: 'synthetic-relay-credential')
    monkeypatch.setattr(server, 'read_relay_scope', lambda *args, **kwargs: {'p': str(root)})
    class FakeClient:
        def __init__(self, token, paths, state_dir, *, write_workspace_paths, port, service_unit):
            observed.append(('client', service_unit, port))
            assert paths == write_workspace_paths == {'p': str(root)}
        def call(self, *args, **kwargs): return []
    monkeypatch.setattr(server, 'ProductionDelegationClient', FakeClient)
    _, context = server.build_mcp_server(cfg)
    assert isinstance(context['delegation_relay_client'], FakeClient)
    assert observed == [('reader', STAGE_G), ('client', STAGE_G, 18876)]
