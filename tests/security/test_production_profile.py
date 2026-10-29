"""Explicit production startup controls with real private-file validation."""
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from starlette.testclient import TestClient

from agentporter.production_profile import load_production_profile
from agentporter.resources import JobResources
from agentporter.server import build_mcp_server, create_asgi_app

BUDGET = {'memory_bytes': 4 * 1024**3, 'pids': 128,
          'cpu_quota_us': 200000, 'cpu_period_us': 100000}
PROFILE = {'version': 1, 'profile': 'production', 'public_client_policy_required': True,
           'service_unit': 'agentporter.service', 'job_resources': BUDGET}
REQUIRED = ('production-runtime.yaml', 'config.yaml', 'workspaces.yaml',
            'public-client-policy.yaml', 'action-policy.yaml')


def write(config, name, value):
    path = config.config_dir / name
    path.write_text(yaml.safe_dump(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def production(temp_config, tmp_path, monkeypatch):
    leaf = tmp_path / 'leaf'
    protected = tmp_path / 'umbrella'
    leaf.mkdir()
    protected.mkdir()
    (leaf / 'sample.txt').write_text('first\nsecond\n')
    (protected / 'sample.txt').write_text('protected\n')
    temp_config.workspaces = {
        'leaf': {'path': str(leaf), 'writable': True, 'allow_execute': True,
                 'allow_agent_dispatch': False, 'auto_discover': False},
        'repos': {'path': str(protected), 'writable': False, 'allow_execute': False,
                  'allow_agent_dispatch': False, 'auto_discover': False}}
    write(temp_config, 'production-runtime.yaml', PROFILE)
    write(temp_config, 'config.yaml', {'sandbox': {'network': False}})
    write(temp_config, 'workspaces.yaml', {'workspaces': temp_config.workspaces})
    write(temp_config, 'public-client-policy.yaml', {'version': 1, 'workspaces': {
        'leaf': {'path': str(leaf), 'operations': ['read', 'git_read', 'write', 'exec']},
        'repos': {'path': str(protected), 'operations': ['read', 'git_read']}}})
    write(temp_config, 'action-policy.yaml', {'version': 1, 'action_modes': {'dispatch_agent': 'LOCKED'}})
    monkeypatch.setenv('AGENTPORTER_PROFILE', 'production')
    temp_config.security.allowed_hosts = ['testserver']
    return temp_config


def test_absent_selector_preserves_legacy_and_unknown_selector_rejects(temp_config, monkeypatch):
    monkeypatch.delenv('AGENTPORTER_PROFILE', raising=False)
    assert load_production_profile(temp_config) is None
    monkeypatch.setenv('AGENTPORTER_PROFILE', 'unexpected-private-value')
    with pytest.raises(PermissionError, match='^Unknown AgentPorter profile selector$'):
        load_production_profile(temp_config)


@pytest.mark.parametrize('name', REQUIRED)
def test_production_requires_every_private_control(production, name):
    (production.config_dir / name).unlink()
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        load_production_profile(production)


@pytest.mark.parametrize('name', REQUIRED)
@pytest.mark.parametrize('unsafe', ['public', 'symlink', 'hardlink'])
def test_production_rejects_unsafe_control_metadata(production, tmp_path, name, unsafe):
    path = production.config_dir / name
    if unsafe == 'public':
        path.chmod(0o644)
    elif unsafe == 'symlink':
        other = tmp_path / 'private-control-target'
        path.rename(other)
        path.symlink_to(other)
    else:
        os.link(path, tmp_path / 'control-alias')
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        load_production_profile(production)


@pytest.mark.parametrize('unsafe', ['oversize', 'fifo', 'malformed', 'duplicate', 'alias'])
def test_profile_bad_content_is_bounded_and_sanitized(production, unsafe):
    path = production.config_dir / 'production-runtime.yaml'
    if unsafe == 'fifo':
        path.unlink()
        os.mkfifo(path, 0o600)
    else:
        payload = {'oversize': 'x' * 65537, 'malformed': 'private-marker: [',
                   'duplicate': 'private-marker: one\nprivate-marker: two\n',
                   'alias': 'private-marker: &x one\nalias: *x\n'}[unsafe]
        path.write_text(payload)
    with pytest.raises(PermissionError) as error:
        load_production_profile(production)
    assert str(error.value) == 'Production profile controls are unavailable or invalid'
    assert error.value.__suppress_context__ is True


@pytest.mark.parametrize('field,value', [
    ('version', True), ('profile', 'development'), ('public_client_policy_required', False),
    ('service_unit', 'agentporter-development.service'), ('workers', {}),
    ('credentials', {}), ('relay', {}), ('job_resources', {**BUDGET, 'pids': True}),
    ('job_resources', {**BUDGET, 'memory_bytes': 1}),
])
def test_profile_rejects_unknown_fields_and_invalid_values(production, field, value):
    profile = copy.deepcopy(PROFILE)
    profile[field] = value
    write(production, 'production-runtime.yaml', profile)
    with pytest.raises(PermissionError):
        load_production_profile(production)


@pytest.mark.parametrize('name', ['development-runtime.yaml', 'internal-client.key',
    'delegation-upstream.yaml', 'delegation-relay-scope.yaml', 'relay-secrets.env', 'public-https.yaml'])
def test_production_refuses_existing_worker_bypass_or_network_controls(production, name, monkeypatch):
    from agentporter.agents.development import DevelopmentRuntime
    monkeypatch.setattr(DevelopmentRuntime, '__init__', lambda *a, **kw: pytest.fail('Created development workers'))
    write(production, name, {'private-marker': 'never consumed'})
    with pytest.raises(PermissionError):
        build_mcp_server(production)


def test_production_rejects_directory_symlink_and_writable_ancestor(production, tmp_path):
    actual = production.config_dir
    alias = tmp_path / 'config-alias'
    alias.symlink_to(actual, target_is_directory=True)
    production.config_dir = alias
    with pytest.raises(PermissionError):
        load_production_profile(production)
    production.config_dir = actual
    mode = tmp_path.stat().st_mode & 0o777
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(PermissionError):
            load_production_profile(production)
    finally:
        tmp_path.chmod(mode)


@pytest.mark.parametrize('failure', ['protected_write', 'discovery', 'dispatch', 'overlap', 'action_unlock', 'scope_dispatch'])
def test_production_enforces_protected_roots_and_no_authority_expansion(production, failure):
    if failure in ('protected_write', 'discovery', 'dispatch', 'overlap'):
        row = production.workspaces['repos' if failure == 'protected_write' else 'leaf']
        if failure == 'protected_write': row['writable'] = True
        elif failure == 'discovery': row['auto_discover'] = True
        elif failure == 'dispatch': row['allow_agent_dispatch'] = True
        else: row['path'] = str(production.config_dir)
        write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
        if failure == 'overlap':
            p = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
            p['workspaces']['leaf']['path'] = str(production.config_dir)
            write(production, 'public-client-policy.yaml', p)
    elif failure == 'action_unlock':
        write(production, 'action-policy.yaml', {'version': 1, 'action_modes': {'dispatch_agent': 'ALLOW'}})
    else:
        p = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
        p['workspaces']['leaf']['operations'].append('dispatch')
        write(production, 'public-client-policy.yaml', p)
    with pytest.raises(PermissionError):
        load_production_profile(production)


class SyntheticResources:
    """Replace only native cgroup allocation; retain real gateway/policy checks."""
    calls = []
    def __init__(self, settings, *, expected_unit):
        self.calls.append((dict(settings), expected_unit))
    leases = []
    def recover(self):
        pass
    def create(self):
        lease = SimpleNamespace(closed=False)
        lease.command = lambda command: command
        lease.close = lambda: setattr(lease, 'closed', True)
        lease.terminate = lambda: setattr(lease, 'terminated', True)
        self.leases.append(lease)
        return lease


def test_production_build_requires_no_internal_key_or_worker_runtime(production, monkeypatch):
    from agentporter.agents.development import DevelopmentRuntime
    import agentporter.server as server
    monkeypatch.setattr(DevelopmentRuntime, '__init__', lambda *a, **kw: pytest.fail('Created workers'))
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    _, context = build_mcp_server(production)
    assert context['agent_broker'].development_runtime is None
    assert context['client_policy'].scopes is not None
    assert context['client_policy'].internal_key is None
    assert SyntheticResources.calls[-1] == (BUDGET, 'agentporter.service')
    assert context['job_manager'].resources is not None
    assert not (production.config_dir / 'internal-client.key').exists()
    assert not (production.config_dir / 'development-runtime.yaml').exists()


def test_production_actual_rest_preserves_leaf_and_protected_boundaries(production, monkeypatch):
    import agentporter.server as server
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    app = create_asgi_app(production)
    with TestClient(app, client=('127.0.0.1', 12345), raise_server_exceptions=False) as client:
        headers = {'X-AgentPorter-Key': production.api_key}
        r = client.post('/api/v1/workspaces/leaf/files/read', json={'path': 'sample.txt'}, headers=headers)
        assert r.status_code == 200 and r.json()['content'] == 'first\nsecond\n'
        assert client.post('/api/v1/workspaces/leaf/files/read', json={'path': 'sample.txt'}).status_code == 401
        r = client.post('/api/v1/workspaces/leaf/files/write', json={'path': 'new.txt', 'content': 'leaf'}, headers=headers)
        assert r.status_code == 200
        r = client.post('/api/v1/workspaces/repos/files/write', json={'path': 'new.txt', 'content': 'denied'}, headers=headers)
        assert r.status_code == 403
        for endpoint, body in [('exec/run', {'argv': ['/usr/bin/true']}),
                               ('agents/dispatch', {'agent': 'jax', 'task': 'must deny'})]:
            r = client.post('/api/v1/workspaces/repos/' + endpoint, json=body, headers=headers)
            assert r.status_code == 403
        assert not (Path(production.workspaces['repos']['path']) / 'new.txt').exists()


@pytest.mark.parametrize('expected,actual', [
    ('agentporter.service', 'agentporter-development.service'),
    ('agentporter-development.service', 'agentporter.service'),
    ('unreviewed.service', 'unreviewed.service'),
])
def test_resource_unit_identity_cannot_be_inferred_or_arbitrary(monkeypatch, expected, actual):
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **kw:
                        '0::/user.slice/' + actual + '/supervisor\n'
                        if str(path) == '/proc/self/cgroup' else original(path, *a, **kw))
    with pytest.raises(PermissionError):
        JobResources(BUDGET, expected_unit=expected)


@pytest.mark.parametrize('controllers', ['cpu memory pids', 'memory pids'])
def test_production_resource_identity_accepts_only_verified_controllers(tmp_path, monkeypatch, controllers):
    unit = '/sys/fs/cgroup/user.slice/agentporter.service'
    native_read, native_write, native_stat = Path.read_text, Path.write_text, Path.stat
    writes = []
    def read(path, *args, **kwargs):
        if str(path) == '/proc/self/cgroup':
            return '0::/user.slice/agentporter.service/supervisor\n'
        if str(path) == unit + '/cgroup.controllers':
            return controllers
        return native_read(path, *args, **kwargs)
    def metadata(path, *args, **kwargs):
        return native_stat(tmp_path) if str(path) == unit else native_stat(path, *args, **kwargs)
    def write(path, value, *args, **kwargs):
        if str(path) == unit + '/cgroup.subtree_control':
            writes.append(value)
            return len(value)
        return native_write(path, value, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(Path, 'write_text', write)
    monkeypatch.setattr(Path, 'stat', metadata)
    if controllers.startswith('cpu'):
        resources = JobResources(BUDGET, expected_unit='agentporter.service')
        assert str(resources.root) == unit
        assert writes == ['+cpu +memory +pids']
    else:
        with pytest.raises(PermissionError, match='controllers must be delegated'):
            JobResources(BUDGET, expected_unit='agentporter.service')
        assert writes == []


def test_production_direct_sync_async_execution_uses_same_admission_and_resources(production, monkeypatch):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:
        pytest.skip('Native Bubblewrap unavailable')
    import agentporter.server as server
    import time
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    SyntheticResources.leases.clear()
    app = create_asgi_app(production)
    headers = {'X-AgentPorter-Key': production.api_key}
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        body = {'argv': ['python3', '-I', '-c', 'print("bounded fixture")'], 'timeout_seconds': 3}
        result = client.post('/api/v1/workspaces/leaf/exec/run', json=body, headers=headers)
        assert result.status_code == 200 and result.json()['exit_code'] == 0
        assert result.json()['stdout'] == 'bounded fixture\n'
        result = client.post('/api/v1/workspaces/leaf/exec/start', json=body, headers=headers)
        assert result.status_code == 200
        job = result.json()['job_id']
        deadline = time.monotonic() + 5
        while True:
            status = client.get('/api/v1/jobs/' + job + '/status', headers=headers).json()
            if status['status'] != 'running' or time.monotonic() >= deadline:
                break
            time.sleep(.02)
        assert status['status'] == 'completed' and status['exit_code'] == 0
        assert len(SyntheticResources.leases) == 2
        assert all(lease.closed for lease in SyntheticResources.leases)
        body['network_access'] = True
        assert client.post('/api/v1/workspaces/leaf/exec/run', json=body, headers=headers).status_code == 403
    import sqlite3
    with sqlite3.connect(production.state_dir / 'jobs.db') as db:
        assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0


def test_development_profile_still_requires_its_internal_key(production, monkeypatch):
    from agentporter.agents.development import DevelopmentRuntime
    monkeypatch.delenv('AGENTPORTER_PROFILE')
    write(production, 'development-runtime.yaml', {})
    monkeypatch.setattr(DevelopmentRuntime, '_config', lambda self: {'public_client_policy_required': True})
    with pytest.raises(PermissionError, match='Hardened development startup requires'):
        build_mcp_server(production)



def test_foreign_profile_owner_is_rejected_without_relaxing_other_metadata(production, monkeypatch):
    import agentporter.production_profile as profile
    native = os.fstat
    target = production.config_dir / 'production-runtime.yaml'
    def metadata(fd):
        info = native(fd)
        if os.readlink('/proc/self/fd/' + str(fd)) == str(target):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1,
                                   st_nlink=info.st_nlink, st_size=info.st_size)
        return info
    monkeypatch.setattr(profile.os, 'fstat', metadata)
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        load_production_profile(production)


def test_invalid_private_action_id_is_sanitized_before_policy_construction(production):
    write(production, 'action-policy.yaml', {'version': 1, 'action_modes': {
        'dispatch_agent': 'LOCKED', 'PRIVATE-MARKER': 'ALLOW'}})
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        build_mcp_server(production)


@pytest.mark.parametrize('unsafe', ['missing', 'public', 'symlink', 'hardlink', 'empty', 'fifo'])
def test_retained_file_key_requires_private_native_metadata(production, tmp_path, unsafe):
    path = production.config_dir / 'secrets.env'
    if unsafe in ('missing', 'fifo'):
        path.unlink()
        if unsafe == 'fifo': os.mkfifo(path, 0o600)
    elif unsafe == 'public': path.chmod(0o644)
    elif unsafe == 'empty': path.write_bytes(b'')
    elif unsafe == 'hardlink': os.link(path, tmp_path / 'key-alias')
    else:
        target = tmp_path / 'key-target'
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        load_production_profile(production)


def test_retained_key_is_never_yaml_parsed_and_environment_key_refuses(production, monkeypatch):
    path = production.config_dir / 'secrets.env'
    path.write_text('AGENTPORTER_API_KEY="[not-a-yaml-document"\n')
    before = path.read_bytes()
    assert load_production_profile(production)['profile'] == 'production'
    assert path.read_bytes() == before
    monkeypatch.setenv('AGENTPORTER_API_KEY', 'fixture-inherited-key')
    with pytest.raises(PermissionError, match='^Production profile controls are unavailable or invalid$'):
        load_production_profile(production)


def mcp_call(client, key, name, arguments):
    response = client.post('/mcp', headers={'X-AgentPorter-Key': key,
        'Accept': 'application/json, text/event-stream'}, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {'name': name, 'arguments': arguments}})
    assert response.status_code == 200
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        data = json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))
    else: data = response.json()
    return data['result']


@pytest.mark.parametrize('transport', ['REST', 'MCP'])
def test_production_owned_cancel_uses_live_handle_and_resource_cleanup(production, monkeypatch, transport):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE: pytest.skip('Native Bubblewrap unavailable')
    import agentporter.server as server
    import time
    original_manager = server.JobManager
    managers = []
    def manager(*args, **kwargs):
        result = original_manager(*args, **kwargs)
        managers.append(result)
        return result
    monkeypatch.setattr(server, 'JobManager', manager)
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    app = create_asgi_app(production)
    headers = {'X-AgentPorter-Key': production.api_key}
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        response = client.post('/api/v1/workspaces/leaf/exec/start', headers=headers,
            json={'argv': ['python3', '-I', '-c', 'import time;time.sleep(10)'], 'timeout_seconds': 15})
        assert response.status_code == 200
        job = response.json()['job_id']
        proc = managers[0].active_processes[job]
        assert proc._agentporter_pidfd is not None
        monkeypatch.setattr('agentporter.tools.jobs.os.killpg',
                            lambda *args: pytest.fail('Cancellation used unowned numeric PGID'))
        try:
            if transport == 'REST':
                response = client.post('/api/v1/jobs/' + job + '/cancel', headers=headers)
                assert response.status_code == 200
            else:
                response = mcp_call(client, production.api_key, 'job_cancel', {'job_id': job})
                assert response.get('isError', False) is False
            deadline = time.monotonic() + 5
            while managers[0].get_status(job)['status'] == 'cancelling' and time.monotonic() < deadline:
                time.sleep(.02)
            assert managers[0].get_status(job)['status'] == 'cancelled'
            assert managers[0]._resource_leases.get(proc) is None
            with managers[0]._get_db() as db:
                assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0
        finally:
            if managers[0].get_status(job)['status'] == 'running':
                managers[0].cancel(job)


@pytest.mark.parametrize('reason', ['missing', 'foreign', 'readonly_scope', 'execute_disabled'])
def test_owned_cancel_denies_nonexecutable_or_unbound_jobs(production, monkeypatch, reason):
    import agentporter.server as server
    import sqlite3
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    if reason == 'execute_disabled':
        production.workspaces['leaf']['allow_execute'] = False
        write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    app = create_asgi_app(production)
    if reason != 'missing':
        with sqlite3.connect(production.state_dir / 'public-client-jobs.db') as db:
            workspace = 'unregistered' if reason == 'foreign' else 'repos' if reason == 'readonly_scope' else 'leaf'
            db.execute('INSERT INTO public_jobs VALUES (?,?)', ('job_fixture', workspace))
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        headers = {'X-AgentPorter-Key': production.api_key}
        assert client.post('/api/v1/jobs/job_fixture/cancel', headers=headers).status_code == 403
        result = mcp_call(client, production.api_key, 'job_cancel', {'job_id': 'job_fixture'})
        assert result['isError'] is True and 'structuredContent' not in result


def test_compatibility_flags_are_boolean_and_default_policy_still_denies_cancel(production):
    from agentporter.client_policy import PublicClientPolicy, PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    registry = WorkspaceRegistry(production.workspaces)
    for name in ('allow_owned_job_cancel', 'allow_production_scinet'):
        with pytest.raises(ValueError, match='compatibility flags must be boolean'):
            PublicClientPolicy(production.config_dir, production.state_dir, registry, **{name: 'true'})
    policy = PublicClientPolicy(production.config_dir, production.state_dir, registry)
    with policy._db() as db: db.execute('INSERT INTO public_jobs VALUES (?,?)', ('owned_fixture', 'leaf'))
    token = PRINCIPAL.set('public')
    try:
        with pytest.raises(PermissionError): policy.check('job_cancel', {'job_id': 'owned_fixture'})
    finally: PRINCIPAL.reset(token)


def install_cranary_scopes(config, tmp_path):
    root = tmp_path / 'cranary'
    root.mkdir()
    config.workspaces['cranary'] = {'path': str(root), 'writable': True,
        'allow_execute': True, 'allow_agent_dispatch': False, 'auto_discover': False,
        'allow_scinet_diagnostic': True, 'allow_scinet_training': True}
    write(config, 'workspaces.yaml', {'workspaces': config.workspaces})
    public = yaml.safe_load((config.config_dir / 'public-client-policy.yaml').read_text())
    public['workspaces']['cranary'] = {'path': str(root), 'operations': [
        'read', 'git_read', 'write', 'exec', 'scinet_diagnostic', 'scinet_training']}
    write(config, 'public-client-policy.yaml', public)


@pytest.mark.parametrize('failure', ['wrong_root', 'no_diagnostic_flag', 'no_training_flag', 'no_execute', 'new_scope'])
def test_scinet_profile_scope_is_only_explicit_authorized_cranary(production, tmp_path, failure):
    install_cranary_scopes(production, tmp_path)
    public = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
    if failure == 'wrong_root':
        production.workspaces['leaf'].update(allow_scinet_diagnostic=True, allow_scinet_training=True)
        public['workspaces']['leaf']['operations'].append('scinet_diagnostic')
    elif failure == 'new_scope': public['workspaces']['cranary']['operations'].append('scinet_unreviewed')
    elif failure == 'no_execute': production.workspaces['cranary']['allow_execute'] = False
    else: production.workspaces['cranary']['allow_scinet_' + ('diagnostic' if failure == 'no_diagnostic_flag' else 'training')] = False
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    write(production, 'public-client-policy.yaml', public)
    with pytest.raises(PermissionError): load_production_profile(production)


def test_production_scinet_reaches_existing_backend_only_for_cranary(production, tmp_path, monkeypatch):
    import agentporter.server as server
    install_cranary_scopes(production, tmp_path)
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    calls = []
    def diagnostic(**kwargs):
        calls.append(kwargs)
        return {'success': True, 'fixture': 'no network or Duo request'}
    monkeypatch.setattr(server, 'create_scinet_tool', lambda *a, **kw: diagnostic)
    login_calls = []
    def login(**kwargs):
        login_calls.append(kwargs)
        return {'state': 'synthetic-status-only', 'success': False}
    monkeypatch.setattr(server, 'create_scinet_login_tool', lambda *a, **kw: login)
    # Observe the real signature checker; a deliberately invalid fixture cannot
    # create a stage/approval or reach a remote broker.
    from agentporter.config import ScinetSettings
    production.scinet = ScinetSettings()
    native_inference = server.create_scinet_inference_tools
    approval_calls = []
    def inference(*args, **kwargs):
        tools = native_inference(*args, **kwargs)
        native_approve = tools['scinet_inference_approve']
        def approve(**arguments):
            approval_calls.append(arguments)
            return native_approve(**arguments)
        tools['scinet_inference_approve'] = approve
        return tools
    monkeypatch.setattr(server, 'create_scinet_inference_tools', inference)
    app = create_asgi_app(production)
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        headers = {'X-AgentPorter-Key': production.api_key}
        for workspace, expected in [('cranary', 200), ('leaf', 403)]:
            response = client.post('/api/v1/workspaces/' + workspace + '/scinet/diagnostic',
                                   json={'command': 'connection_status'}, headers=headers)
            assert response.status_code == expected
        assert len(calls) == 1 and calls[0]['workspace_id'] == 'cranary'
        result = mcp_call(client, production.api_key, 'scinet_diagnostic', {'workspace_id': 'cranary', 'command': 'connection_status'})
        assert not result.get('isError', False)
        result = mcp_call(client, production.api_key, 'scinet_diagnostic', {'workspace_id': 'leaf', 'command': 'connection_status'})
        assert result['isError'] is True
        assert len(calls) == 2
        for workspace, expected in [('cranary', 200), ('leaf', 403)]:
            response = client.post('/api/v1/workspaces/' + workspace + '/scinet/setup',
                                   json={'action': 'login_status'}, headers=headers)
            assert response.status_code == expected
        result = mcp_call(client, production.api_key, 'scinet_login',
                          {'workspace_id': 'cranary', 'action': 'status'})
        assert not result.get('isError', False) and len(login_calls) == 2
        result = mcp_call(client, production.api_key, 'scinet_login',
                          {'workspace_id': 'leaf', 'action': 'status'})
        assert result['isError'] is True and len(login_calls) == 2
        # A known action still reaches its real approval checker and refuses a
        # nonexistent/unsigned stage before any remote connection is possible.
        result = mcp_call(client, production.api_key, 'scinet_inference_submit', {
            'workspace_id': 'cranary', 'stage_id': 'a' * 32})
        assert result['isError'] is True
        arguments = {'workspace_id': 'cranary', 'stage_id': 'a' * 32,
                     'reviewer': 'fixture-not-an-approval', 'signature': 'A' * 88}
        result = mcp_call(client, production.api_key, 'scinet_inference_approve', arguments)
        assert result['isError'] is True
        assert len(approval_calls) == 1 and approval_calls[0]['workspace_id'] == 'cranary'
        result = mcp_call(client, production.api_key, 'scinet_inference_approve',
                          {**arguments, 'workspace_id': 'leaf'})
        assert result['isError'] is True and len(approval_calls) == 1
        response = client.post('/api/v1/workspaces/cranary/scinet/setup', headers=headers,
            json={'action': 'inference_approve', **{k: v for k, v in arguments.items() if k != 'workspace_id'}})
        assert response.status_code == 400
        assert len(approval_calls) == 2


def test_scinet_catalog_is_exact_and_default_development_policy_unchanged(production):
    from agentporter.client_policy import PublicClientPolicy, PRINCIPAL, PRODUCTION_SCINET_OPERATIONS, SCOPES
    from agentporter.action_policy import DEFAULT_ACTION_MODES
    from agentporter.workspaces.registry import WorkspaceRegistry
    assert set(PRODUCTION_SCINET_OPERATIONS) == {name for name in DEFAULT_ACTION_MODES if name.startswith('scinet_')}
    assert len(PRODUCTION_SCINET_OPERATIONS) == 17
    assert not {'scinet_diagnostic', 'scinet_training'} & SCOPES
    policy = PublicClientPolicy(production.config_dir, production.state_dir, WorkspaceRegistry(production.workspaces))
    token = PRINCIPAL.set('public')
    try:
        for action in PRODUCTION_SCINET_OPERATIONS:
            with pytest.raises(PermissionError): policy.check(action, {'workspace_id': 'leaf'})
    finally: PRINCIPAL.reset(token)



def test_production_discovery_never_executes_host_adapter_detection(production, monkeypatch):
    import agentporter.server as server
    from agentporter.agents.broker import AgentBroker
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    native = AgentBroker.__init__
    def construct(self, *args, **kwargs):
        native(self, *args, **kwargs)
        for adapter in self.adapters.values():
            monkeypatch.setattr(adapter, 'detect', lambda: pytest.fail('Host worker detection executed'))
    monkeypatch.setattr(AgentBroker, '__init__', construct)
    app = create_asgi_app(production)
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        response = client.get('/api/v1/workspaces/leaf/agents/list',
                              headers={'X-AgentPorter-Key': production.api_key})
        assert response.status_code == 200
        rows = response.json()
        assert len(rows) == 7
        assert all(not row['available'] for row in rows)
        result = mcp_call(client, production.api_key, 'list_agents', {'workspace_id': 'leaf'})
        assert not result.get('isError', False)
        rows = result.get('structuredContent')
        if rows is None: rows = json.loads(result['content'][0]['text'])
        if isinstance(rows, dict) and set(rows) == {'result'}: rows = rows['result']
        assert len(rows) == 7
        assert all(row['registered'] and not row['available'] and not row['delegatable'] for row in rows)
        assert all(row['configured_model'] == 'unknown' for row in rows)


def test_default_broker_discovery_behavior_is_unchanged_and_flag_is_boolean(production, monkeypatch):
    from agentporter.agents.broker import AgentBroker
    from agentporter.workspaces.registry import WorkspaceRegistry
    registry = WorkspaceRegistry(production.workspaces)
    with pytest.raises(ValueError, match='discovery flag must be boolean'):
        AgentBroker(registry, None, config_dir=production.config_dir, production_no_host_detection='true')
    broker = AgentBroker(registry, None, config_dir=production.config_dir)
    calls = []
    monkeypatch.setattr(broker.adapters['jax'], 'detect', lambda: calls.append(True) or {'is_installed': True})
    assert broker._detection('jax', broker.adapters['jax'])['is_installed'] is True
    assert calls == [True]


def test_production_permits_scoped_git_write_only_on_writable_git_workspace(production):
    production.workspaces['leaf']['allow_git'] = True
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    policy = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
    policy['workspaces']['leaf']['operations'].append('git_write')
    write(production, 'public-client-policy.yaml', policy)
    assert load_production_profile(production)['profile'] == 'production'
    production.workspaces['leaf']['writable'] = False
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    with pytest.raises(PermissionError):
        load_production_profile(production)
    production.workspaces['leaf']['writable'] = True
    production.workspaces['leaf']['allow_git'] = False
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    with pytest.raises(PermissionError):
        load_production_profile(production)


def test_production_accepts_explicit_read_only_delegation_relay(production):
    from agentporter.agents.production_relay import relay_upstream_workspaces
    production.workspaces['leaf']['allow_agent_dispatch'] = True
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    policy = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
    policy['workspaces']['leaf']['operations'].append('dispatch')
    write(production, 'public-client-policy.yaml', policy)
    write(production, 'action-policy.yaml', {'version': 1, 'action_modes': {'dispatch_agent': 'SCOPE'}})
    write(production, 'delegation-upstream.yaml', {'version': 1, 'host': '127.0.0.1', 'port': 8876, 'workspaces': ['leaf']})
    key = production.config_dir / 'delegation-relay.key'
    key.write_text('A' * 43 + '\n')
    key.chmod(0o600)
    assert load_production_profile(production)['profile'] == 'production'
    assert relay_upstream_workspaces(production.config_dir) == {'leaf'}
    key.unlink()
    with pytest.raises(PermissionError):
        load_production_profile(production)


@pytest.mark.parametrize('failure', ['missing_key', 'unknown_workspace', 'missing_scope',
                                     'missing_registry_grant', 'protected_scope', 'writable_dispatch',
                                     'untrusted_key', 'unlocked_policy'])
def test_relay_profile_rejects_incomplete_or_unsafe_grants(production, failure):
    production.workspaces['leaf']['allow_agent_dispatch'] = True
    policy = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
    policy['workspaces']['leaf']['operations'].append('dispatch')
    relay = {'version': 1, 'host': '127.0.0.1', 'port': 8876, 'workspaces': ['leaf']}
    action = {'version': 1, 'action_modes': {'dispatch_agent': 'SCOPE'}}
    key = production.config_dir / 'delegation-relay.key'
    key.write_text('A' * 43 + '\n')
    key.chmod(0o600)
    if failure == 'missing_key': key.unlink()
    elif failure == 'unknown_workspace': relay['workspaces'] = ['unknown']
    elif failure == 'missing_scope': policy['workspaces']['leaf']['operations'].remove('dispatch')
    elif failure == 'missing_registry_grant': production.workspaces['leaf']['allow_agent_dispatch'] = False
    elif failure == 'protected_scope':
        relay['workspaces'] = ['repos']
        production.workspaces['leaf']['allow_agent_dispatch'] = False
        production.workspaces['repos']['allow_agent_dispatch'] = True
        policy['workspaces']['leaf']['operations'].remove('dispatch')
        policy['workspaces']['repos']['operations'].append('dispatch')
    elif failure == 'writable_dispatch': policy['workspaces']['leaf']['operations'].append('dispatch_write')
    elif failure == 'untrusted_key': key.chmod(0o644)
    else: action['action_modes']['dispatch_agent'] = 'ALLOW'
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    write(production, 'public-client-policy.yaml', policy)
    write(production, 'action-policy.yaml', action)
    write(production, 'delegation-upstream.yaml', relay)
    with pytest.raises(PermissionError): load_production_profile(production)


def test_production_relay_dispatch_is_scoped_and_read_only(production, monkeypatch):
    from agentporter.agents.production_relay import validate_dispatch
    from agentporter.client_policy import PRINCIPAL
    import agentporter.server as server
    production.workspaces['leaf']['allow_agent_dispatch'] = True
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    policy = yaml.safe_load((production.config_dir / 'public-client-policy.yaml').read_text())
    policy['workspaces']['leaf']['operations'].append('dispatch')
    write(production, 'public-client-policy.yaml', policy)
    write(production, 'action-policy.yaml', {'version': 1, 'action_modes': {'dispatch_agent': 'SCOPE'}})
    write(production, 'delegation-upstream.yaml', {'version': 1, 'host': '127.0.0.1', 'port': 8876, 'workspaces': ['leaf']})
    key = production.config_dir / 'delegation-relay.key'
    key.write_text('A' * 43 + '\n'); key.chmod(0o600)
    observed = []
    class FakeRelay:
        def __init__(self, token, paths, state_dir): self.paths = paths
        def call(self, operation, args=None):
            observed.append((operation, args))
            return {'job_id': 'rjob_' + 'a' * 32, 'request': validate_dispatch(args, set(self.paths))}
    monkeypatch.setattr(server, 'ProductionDelegationClient', FakeRelay)
    monkeypatch.setattr(server, 'JobResources', SyntheticResources)
    _, context = build_mcp_server(production)
    principal = PRINCIPAL.set('public')
    try:
        dispatch = context['tools']['dispatch_agent']
        result = dispatch(agent='jax', task='bounded review', workspace_id='leaf')
        assert result['request']['read_only'] is True
        for args in ({'read_only': False}, {'allow_commit': True}, {'allow_push': True}):
            with pytest.raises(PermissionError):
                dispatch(agent='jax', task='bounded review', workspace_id='leaf', **args)
        with pytest.raises(PermissionError):
            dispatch(agent='jax', task='bounded review', workspace_id='repos')
        assert len(observed) == 1
    finally:
        PRINCIPAL.reset(principal)
