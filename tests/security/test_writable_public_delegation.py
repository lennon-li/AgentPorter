"""Explicit local edit delegation preserves public and kernel boundaries."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from starlette.testclient import TestClient

from agentporter.agents.broker import AgentBroker
from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.server import create_asgi_app


@pytest.fixture
def configured(temp_config, tmp_path, monkeypatch):
    temp_config.security.allowed_hosts = ['testserver']
    root = tmp_path / 'project'
    root.mkdir()
    temp_config.workspaces['project'] = {'path': str(root), 'writable': True,
        'allow_execute': True, 'allow_agent_dispatch': True}
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {'project': {
        'path': str(root), 'operations': ['read', 'write', 'dispatch', 'dispatch_write']}}}))
    policy.chmod(0o600)
    monkeypatch.setattr(AgentBroker, 'list_agents', lambda self: [
        {'agent': name, 'worker_cli': 'codex' if name in {'jax', 'liz', 'prof'} else
            {'ming': 'claude', 'phil': 'phil', 'wei': 'opencode', 'argie': 'agy'}[name],
         'available': True, 'delegatable': True, 'runtime_profile': 'development',
         'runtime_dispatch_workspaces': ['project'],
         'runtime_writable_dispatch_workspaces': ['project']} for name in PUBLIC_AGENT_IDS])
    dispatch = Mock(return_value={'job_id': 'synthetic-job', 'status': 'running'})
    monkeypatch.setattr(AgentBroker, 'dispatch_agent', dispatch)
    return temp_config, policy, dispatch


def request(client, config, agent='liz', **kwargs):
    return client.post('/api/v1/workspaces/project/agents/dispatch',
        headers={'X-AgentPorter-Key': config.api_key},
        json={'agent': agent, 'task': 'Authorized local edit', **kwargs})


@pytest.mark.parametrize('agent', sorted(PUBLIC_AGENT_IDS))
def test_each_named_worker_accepts_explicit_writable_request(configured, agent):
    config, _, dispatch = configured
    with TestClient(create_asgi_app(config)) as client:
        result = request(client, config, agent, read_only=False)
    assert result.status_code == 200, result.text
    assert dispatch.call_args.kwargs['read_only'] is False
    assert dispatch.call_args.kwargs['allow_commit'] is False
    assert dispatch.call_args.kwargs['allow_push'] is False


def test_opt_in_does_not_change_read_only_default(configured):
    config, _, dispatch = configured
    with TestClient(create_asgi_app(config)) as client:
        assert request(client, config).status_code == 200
    assert dispatch.call_args.kwargs['read_only'] is True


@pytest.mark.parametrize('missing', ['dispatch_write', 'write', 'dispatch'])
def test_existing_scopes_cannot_silently_gain_edit_delegation(configured, missing):
    config, path, dispatch = configured
    policy = yaml.safe_load(path.read_text())
    policy['workspaces']['project']['operations'].remove(missing)
    path.write_text(yaml.safe_dump(policy))
    with TestClient(create_asgi_app(config)) as client:
        assert request(client, config, read_only=False).status_code == 403
    dispatch.assert_not_called()


@pytest.mark.parametrize('flag', ['allow_push'])
def test_write_scope_does_not_authorize_publication(configured, flag):
    config, _, dispatch = configured
    with TestClient(create_asgi_app(config)) as client:
        assert request(client, config, read_only=False, **{flag: True}).status_code == 403
    dispatch.assert_not_called()


def test_readonly_registry_cannot_be_overridden_by_scope(configured):
    config, _, dispatch = configured
    config.workspaces['project']['writable'] = False
    with TestClient(create_asgi_app(config)) as client:
        assert request(client, config, read_only=False).status_code == 403
    dispatch.assert_not_called()


def test_inventory_distinguishes_readonly_and_writable_grants(configured):
    config, _, _ = configured
    with TestClient(create_asgi_app(config)) as client:
        rows = client.get('/api/v1/workspaces/project/agents/list',
                          headers={'X-AgentPorter-Key': config.api_key}).json()
    assert len(rows) == 7
    assert all(row['public_writable_dispatch_workspaces'] == ['project'] for row in rows)
    assert all(row['public_dispatch_read_only'] is False for row in rows)
    assert all('runtime_writable_dispatch_workspaces' not in row for row in rows)


@pytest.fixture
def migration(monkeypatch):
    path = Path(__file__).parents[2] / 'scripts/authorize-a7dev-writable-delegation.py'
    spec = importlib.util.spec_from_file_location('writable_authorization', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    monkeypatch.setattr(helper.storage.os.path, 'realpath', lambda p: str(p))
    monkeypatch.setattr(helper.Path, 'is_dir', lambda p: True)
    return helper


@pytest.fixture
def migration_inputs(migration):
    root = migration.storage.EXPECTED_ROOTS['agentporter-dev']
    policy = {'version': 1, 'workspaces': {'agentporter-dev': {
        'path': root, 'operations': ['read', 'write', 'dispatch']}}}
    registry = {'workspaces': {'agentporter-dev': {'path': root, 'writable': True,
        'allow_execute': True, 'allow_agent_dispatch': True}}}
    runtime = {'enabled': True, 'profile': 'development',
               'allowed_workspace_roots': [{'path': root, 'writable': True}]}
    inputs = {n: yaml.safe_dump(value).encode() for n, value in
              zip(migration.storage.FILES, (policy, registry, runtime))}
    inputs[migration.storage.HTTPS] = b'unchanged HTTPS policy'
    return inputs


def test_migration_changes_only_named_public_grant(migration, migration_inputs):
    helper, inputs = migration, migration_inputs
    output, plan = helper.transform(inputs, Path('/fixture/release'), ['agentporter-dev'])
    assert output[helper.storage.FILES[1]] == inputs[helper.storage.FILES[1]]
    assert output[helper.storage.FILES[2]] == inputs[helper.storage.FILES[2]]
    assert yaml.safe_load(output[helper.storage.FILES[0]])['workspaces']['agentporter-dev']['operations'] == [
        'read', 'write', 'dispatch', 'dispatch_write']
    assert plan['network_changed'] is False and plan['production_changed'] is False


@pytest.mark.parametrize('mutation', ['protected', 'no_write', 'missing_root', 'nested', 'production', 'disabled'])
def test_migration_preserves_existing_workspace_boundaries(migration, migration_inputs, mutation):
    helper, inputs = migration, migration_inputs
    names = ['agentporter-dev']
    if mutation == 'protected':
        names = ['AgentPorter']
    elif mutation == 'no_write':
        policy = yaml.safe_load(inputs[helper.storage.FILES[0]])
        policy['workspaces']['agentporter-dev']['operations'].remove('write')
        inputs[helper.storage.FILES[0]] = yaml.safe_dump(policy).encode()
    else:
        runtime = yaml.safe_load(inputs[helper.storage.FILES[2]])
        if mutation == 'missing_root':
            runtime['allowed_workspace_roots'] = []
        elif mutation == 'nested':
            runtime['allowed_workspace_roots'].append({'path': helper.storage.EXPECTED_ROOTS['agentporter-dev'] + '/child', 'writable': False})
        elif mutation == 'production':
            runtime['profile'] = 'production'
        else:
            runtime['enabled'] = False
        inputs[helper.storage.FILES[2]] = yaml.safe_dump(runtime).encode()
    with pytest.raises(RuntimeError):
        helper.transform(inputs, Path('/fixture/release'), names)


def test_migration_upgrades_only_explicit_root_from_readonly(migration, migration_inputs):
    helper, inputs = migration, migration_inputs
    runtime = yaml.safe_load(inputs[helper.storage.FILES[2]])
    runtime['allowed_workspace_roots'][0]['writable'] = False
    runtime['allowed_workspace_roots'].append({'path': '/unrelated/project', 'writable': False})
    inputs[helper.storage.FILES[2]] = yaml.safe_dump(runtime).encode()
    output, _ = helper.transform(inputs, Path('/fixture/release'), ['agentporter-dev'])
    upgraded = yaml.safe_load(output[helper.storage.FILES[2]])
    assert upgraded['allowed_workspace_roots'][0]['writable'] is True
    assert upgraded['allowed_workspace_roots'][1] == runtime['allowed_workspace_roots'][1]
    assert output[helper.storage.FILES[1]] == inputs[helper.storage.FILES[1]]


def test_mcp_accepts_same_scoped_edit_and_rejects_publication(configured):
    import json
    config, _, dispatch = configured
    with TestClient(create_asgi_app(config)) as client:
        def call(**extra):
            response = client.post('/mcp', headers={
                'X-AgentPorter-Key': config.api_key, 'Accept': 'application/json, text/event-stream'},
                json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                    'name': 'dispatch_agent', 'arguments': {'agent': 'liz', 'workspace_id': 'project',
                    'task': 'Authorized local edit', 'read_only': False, **extra}}})
            assert response.status_code == 200
            if response.headers.get('content-type', '').startswith('text/event-stream'):
                return json.loads(next(line[6:] for line in response.text.splitlines()
                                       if line.startswith('data: ')))['result']
            return response.json()['result']
        assert not call().get('isError')
        assert dispatch.call_args.kwargs['read_only'] is False
        dispatch.reset_mock()
        refused = call(allow_push=True)
        assert refused['isError'] is True
        assert 'cannot push' in json.dumps(refused)
        assert call(workspace_id='unadmitted')['isError'] is True
        dispatch.assert_not_called()
