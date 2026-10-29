"""Public readiness must include the workspace gate used by actual dispatch."""
import json
from unittest.mock import Mock

import pytest
import yaml
from starlette.testclient import TestClient

from agentporter.agents.broker import AgentBroker
from agentporter.server import create_asgi_app


@pytest.fixture
def app_config(temp_config, tmp_path, monkeypatch):
    temp_config.security.allowed_hosts = ['testserver']
    workspaces = {}
    for name in ('cranary', 'Qman', 'disabled'):
        root = tmp_path / name
        root.mkdir()
        temp_config.workspaces[name] = {
            'path': str(root), 'allow_agent_dispatch': name != 'disabled',
            'allow_execute': True,
        }
        workspaces[name] = {'path': str(root), 'operations':
                            ['read', 'exec'] + ([] if name == 'Qman' else ['dispatch'])}
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': workspaces}))
    policy.chmod(0o600)
    key = temp_config.config_dir / 'internal-client.key'
    key.write_text('synthetic-internal-client-key-32-bytes')
    key.chmod(0o600)
    monkeypatch.setattr(AgentBroker, 'list_agents', lambda self: [
        {'agent': 'jax', 'worker_cli': 'codex', 'available': True,
         'delegatable': True, 'availability_reason': 'Synthetic runtime verified',
         'runtime_profile': 'development',
         'runtime_dispatch_workspaces': ['cranary', 'Qman', 'disabled', 'hidden-runtime-project']},
        {'agent': 'liz', 'worker_cli': 'codex', 'available': False, 'delegatable': False},
    ])
    dispatch = Mock(return_value={'job_id': 'synthetic-job', 'status': 'running'})
    monkeypatch.setattr(AgentBroker, 'dispatch_agent', dispatch)
    return temp_config, dispatch


def rpc(client, key, name, arguments):
    response = client.post('/mcp', headers={
        'X-AgentPorter-Key': key, 'Accept': 'application/json, text/event-stream'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
              'params': {'name': name, 'arguments': arguments}})
    assert response.status_code == 200, response.text
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        data = json.loads(next(line[6:] for line in response.text.splitlines()
                               if line.startswith('data: ')))
    else:
        data = response.json()
    return data['result']


def rows(result):
    assert not result.get('isError'), result
    data = result.get('structuredContent')
    if data is None:
        data = json.loads(''.join(item['text'] for item in result['content']
                                  if item['type'] == 'text'))
    return data['result'] if isinstance(data, dict) and set(data) == {'result'} else data


def test_mcp_inventory_and_dispatch_agree_on_workspace_scope(app_config):
    config, dispatch = app_config
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        for workspace in ('Qman', 'cranary'):
            inventory = rows(rpc(client, config.api_key, 'list_agents', {'workspace_id': workspace}))
            jax = next(row for row in inventory if row['agent'] == 'jax')
            assert jax['runtime_delegatable'] is True
            assert jax['public_dispatch_workspaces'] == ['cranary']
            assert jax['workspace_dispatch_authorized'] is (workspace == 'cranary')
            assert jax['delegatable'] is (workspace == 'cranary')
            assert next(row for row in inventory if row['agent'] == 'liz')['delegatable'] is False
            result = rpc(client, config.api_key, 'dispatch_agent', {
                'agent': 'jax', 'workspace_id': workspace, 'task': 'Synthetic read-only test'})
            if workspace == 'Qman':
                assert result['isError'] is True
                assert 'Public agent dispatch is not authorized' in json.dumps(result)
                assert 'File and offline execution access do not grant delegation' in json.dumps(result)
                dispatch.assert_not_called()
            else:
                assert not result.get('isError'), result
                dispatch.assert_called_once()
        global_jax = next(row for row in rows(rpc(client, config.api_key, 'list_agents', {}))
                          if row['agent'] == 'jax')
        assert global_jax['delegatable'] is True
        assert global_jax['public_dispatch_workspaces'] == ['cranary']
        assert 'quota' in global_jax['readiness_note']


def test_rest_preserves_scoped_readiness_and_denial(app_config):
    config, dispatch = app_config
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        headers = {'X-AgentPorter-Key': config.api_key}
        for workspace in ('Qman', 'cranary'):
            response = client.get(f'/api/v1/workspaces/{workspace}/agents/list', headers=headers)
            assert response.status_code == 200, response.text
            jax = next(row for row in response.json() if row['agent'] == 'jax')
            assert jax['delegatable'] is (workspace == 'cranary')
            assert jax['runtime_delegatable'] is True
            assert jax['public_dispatch_workspaces'] == ['cranary']
        response = client.post('/api/v1/workspaces/Qman/agents/dispatch', headers=headers,
                               json={'agent': 'jax', 'task': 'Do not launch'})
        assert response.status_code == 403
        assert 'not authorized' in response.text
        dispatch.assert_not_called()


def test_public_workspace_permissions_and_internal_access_stay_distinct(app_config):
    config, dispatch = app_config
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        public = {'X-AgentPorter-Key': config.api_key}
        listed = client.get('/api/v1/workspaces/', headers=public).json()
        assert next(row for row in listed if row['workspace_id'] == 'Qman')['permissions']['agent_dispatch'] is False
        assert next(row for row in listed if row['workspace_id'] == 'cranary')['permissions']['agent_dispatch'] is True
        denied = rpc(client, config.api_key, 'list_agents', {'workspace_id': 'unlisted'})
        assert denied['isError'] is True
        internal = {'X-AgentPorter-Key': 'synthetic-internal-client-key-32-bytes'}
        inventory = client.get('/api/v1/workspaces/Qman/agents/list', headers=internal).json()
        assert next(row for row in inventory if row['agent'] == 'jax')['delegatable'] is True
        listed = client.get('/api/v1/workspaces/', headers=internal).json()
        assert next(row for row in listed if row['workspace_id'] == 'Qman')['permissions']['agent_dispatch'] is True
        dispatch.assert_not_called()


def test_no_public_delegation_grant_does_not_report_ready(app_config):
    config, dispatch = app_config
    path = config.config_dir / 'public-client-policy.yaml'
    policy = yaml.safe_load(path.read_text())
    for scope in policy['workspaces'].values():
        scope['operations'] = ['read', 'exec']
    path.write_text(yaml.safe_dump(policy))
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        inventory = rows(rpc(client, config.api_key, 'list_agents', {}))
        jax = next(row for row in inventory if row['agent'] == 'jax')
        assert jax['runtime_delegatable'] is True
        assert jax['delegatable'] is False
        assert jax['public_dispatch_workspaces'] == []
        assert 'not authorized for any workspace' in jax['availability_reason']
        dispatch.assert_not_called()


def test_runtime_mismatch_cannot_be_promoted_to_ready(app_config, monkeypatch):
    config, dispatch = app_config
    monkeypatch.setattr(AgentBroker, 'list_agents', lambda self: [
        {'agent': 'jax', 'worker_cli': 'opencode', 'available': True,
         'delegatable': True},
    ])
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        inventory = rows(rpc(client, config.api_key, 'list_agents', {'workspace_id': 'cranary'}))
        jax = next(row for row in inventory if row['agent'] == 'jax')
        assert jax['workspace_dispatch_authorized'] is True
        assert jax['available'] is False
        assert jax['delegatable'] is False
        assert jax['runtime_delegatable'] is False
        dispatch.assert_not_called()


@pytest.mark.parametrize('runtime_workspaces', [[], None])
def test_development_runtime_workspace_denial_overrides_public_grant(app_config, monkeypatch, runtime_workspaces):
    config, dispatch = app_config
    row = {'agent': 'jax', 'worker_cli': 'codex', 'available': True,
           'delegatable': True, 'runtime_profile': 'development'}
    if runtime_workspaces is not None:
        row['runtime_dispatch_workspaces'] = runtime_workspaces
    monkeypatch.setattr(AgentBroker, 'list_agents', lambda self: [row])
    with TestClient(create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
        inventory = rows(rpc(client, config.api_key, 'list_agents', {'workspace_id': 'cranary'}))
        jax = next(item for item in inventory if item['agent'] == 'jax')
        assert jax['delegatable'] is False
        assert jax['workspace_dispatch_authorized'] is False
        assert jax['public_dispatch_workspaces'] == []
        assert 'runtime_dispatch_workspaces' not in jax
        assert 'hidden-runtime-project' not in json.dumps(inventory)
        dispatch.assert_not_called()
