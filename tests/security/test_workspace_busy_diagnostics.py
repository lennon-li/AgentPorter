"""Ordinary execution reports lock contention without weakening serialization."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import json

import pytest

from agentporter.policy_errors import WorkspaceBusyError
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.jobs import JobManager


BUSY = {
    'status': 'busy', 'launched': False, 'executed': False,
    'error': {
        'code': 'WORKSPACE_BUSY',
        'reason': 'workspace_transaction_active',
        'message': 'Workspace already has an active transaction.',
        'retry_after_seconds': 3,
    },
}


class Resources:
    def create(self):
        return SimpleNamespace(close=lambda: None)


class Registry:
    def __init__(self, path):
        self.workspace = SimpleNamespace(path=path, writable=True, allow_execute=True)

    def get(self, workspace_id):
        assert workspace_id == 'project'
        return self.workspace


def admission_count(manager):
    conn = manager._get_db()
    try:
        return conn.execute('SELECT count(*) FROM job_admissions').fetchone()[0]
    finally:
        conn.close()


def setup(tmp_path):
    workspace = tmp_path / 'project'
    workspace.mkdir()
    (workspace / 'input.txt').write_text('safe fixture')
    state = tmp_path / 'state'
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = Resources()
    manager = JobManager(state)
    manager.resources = sandbox.resources
    run, start = create_execution_tools(Registry(workspace), sandbox, manager)
    return workspace, state, sandbox, manager, run, start


def test_sync_exec_reports_busy_and_recovers_after_owner_releases(tmp_path, monkeypatch):
    workspace, state, sandbox, _manager, run, _start = setup(tmp_path)
    low_level = Mock(return_value={'stdout': 'later', 'stderr': '', 'exit_code': 0, 'timeout': False})
    monkeypatch.setattr(sandbox, '_run_command', low_level)
    owner = WorkspaceTransaction(workspace, state / 'workspace-transactions', git_sandbox=sandbox)
    try:
        with pytest.raises(WorkspaceBusyError) as caught:
            run('project', ['/bin/true'])
        assert caught.value.detail == BUSY
        low_level.assert_not_called()
        assert admission_count(_manager) == 0
    finally:
        owner.close()

    result = run('project', ['/bin/true'])
    assert result['stdout'] == 'later'
    low_level.assert_called_once()
    assert not list((state / 'workspace-transactions').glob('*/upper'))


def test_async_exec_reports_busy_before_launch_and_recovers(tmp_path, monkeypatch):
    workspace, state, sandbox, manager, _run, start = setup(tmp_path)
    launch = Mock(return_value='job_fixture')
    def accepted(**kwargs):
        transaction = kwargs['workspace_transaction']
        transaction.close()
        return launch(**kwargs)
    monkeypatch.setattr(manager, '_start_process_job', accepted)
    owner = WorkspaceTransaction(workspace, state / 'workspace-transactions', git_sandbox=sandbox)
    try:
        with pytest.raises(WorkspaceBusyError) as caught:
            start('project', ['/bin/true'])
        assert caught.value.detail == BUSY
        launch.assert_not_called()
        assert manager.active_processes == {}
        assert admission_count(manager) == 0
    finally:
        owner.close()

    result = start('project', ['/bin/true'])
    assert result['job_id'] == 'job_fixture'
    launch.assert_called_once()


def test_mcp_wrapper_returns_structured_busy_and_preserves_policy_denial():
    from agentporter.policy_errors import ActionPolicyDenied, install_mcp_policy_results
    from pydantic import BaseModel

    class ExistingResult(BaseModel):
        outcome: str

    class Tool:
        def __init__(self, fn):
            self.fn = fn
            self.fn_metadata = SimpleNamespace(output_model=ExistingResult, output_schema={})

    class Manager:
        def __init__(self):
            self.tools = {
                'exec_run': Tool(lambda **_: (_ for _ in ()).throw(WorkspaceBusyError())),
                'git_commit': Tool(lambda **_: (_ for _ in ()).throw(ActionPolicyDenied('git_commit', 'LOCKED'))),
            }
        def get_tool(self, name):
            return self.tools.get(name)

    mcp = SimpleNamespace(_tool_manager=Manager())
    install_mcp_policy_results(mcp)
    assert mcp._tool_manager.tools['exec_run'].fn_metadata.output_schema['type'] == 'object'
    busy = mcp._tool_manager.tools['exec_run'].fn()
    assert busy.structured_content == BUSY
    assert busy.is_error is False
    denied = mcp._tool_manager.tools['git_commit'].fn()
    assert denied.structured_content == {
        'status': 'denied', 'executed': False,
        'error': {'code': 'POLICY_DENIED', 'action': 'git_commit',
                  'mode': 'LOCKED', 'reason': 'action_locked'},
    }


def test_rest_execution_busy_is_http_conflict(temp_config):
    from fastapi.testclient import TestClient
    from agentporter.server import create_asgi_app

    temp_config.security.allowed_hosts.append('testserver')
    secured_app = create_asgi_app(temp_config)
    secured_app.app.state.tools['exec_run'] = Mock(side_effect=WorkspaceBusyError())
    openapi = secured_app.app.openapi()
    for action in ('run', 'start'):
        path = f'/api/v1/workspaces/{{workspace_id}}/exec/{action}'
        response_schema = openapi['paths'][path]['post']['responses']['409']
        assert response_schema['content']['application/json']['schema'] == {
            '$ref': '#/components/schemas/WorkspaceBusyResponse'}
    busy_schema = openapi['components']['schemas']['WorkspaceBusyResponse']
    assert set(busy_schema['properties']) == {'status', 'launched', 'executed', 'error'}
    assert busy_schema['properties']['launched']['const'] is False
    assert busy_schema['properties']['executed']['const'] is False
    busy_detail = openapi['components']['schemas']['WorkspaceBusyDetail']
    assert busy_detail['properties']['code']['const'] == 'WORKSPACE_BUSY'
    assert busy_detail['properties']['reason']['const'] == 'workspace_transaction_active'
    with TestClient(secured_app) as client:
        response = client.post(
            '/api/v1/workspaces/project/exec/run',
            headers={'X-AgentPorter-Key': temp_config.api_key},
            json={'argv': ['/bin/true']},
        )
    assert response.status_code == 409
    assert response.headers['Retry-After'] == '3'
    assert response.json() == BUSY


@pytest.mark.parametrize('tool', ['exec_run', 'exec_start'])
def test_mcp_rpc_execution_busy_is_structured_data(temp_config, tmp_path, monkeypatch, tool):
    from fastapi.testclient import TestClient
    from agentporter.server import create_asgi_app

    workspace = tmp_path / 'mcp-workspace'
    workspace.mkdir()
    temp_config.workspaces = {'project': {'path': str(workspace)}}
    temp_config.security.allowed_hosts = ['testserver']

    low_level = Mock(side_effect=AssertionError('busy requests must not execute a command'))
    job_launch = Mock(side_effect=AssertionError('busy requests must not launch a job'))
    monkeypatch.setattr(BubblewrapSandbox, '_run_command', low_level)
    monkeypatch.setattr(JobManager, '_popen', job_launch)
    if tool == 'exec_run':
        def busy_run(self, *args, **kwargs):
            raise WorkspaceBusyError()
        monkeypatch.setattr(BubblewrapSandbox, 'run', busy_run)
    else:
        def busy_start(self, **kwargs):
            raise WorkspaceBusyError()
        monkeypatch.setattr(JobManager, 'start_raw_job', busy_start)

    def rpc(client, headers, method, params, request_id=1):
        response = client.post('/mcp', headers=headers,
            json={'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        assert response.status_code == 200, response.text
        if response.headers.get('content-type', '').startswith('text/event-stream'):
            line = next(line[6:] for line in response.text.splitlines() if line.startswith('data: '))
            return json.loads(line)
        return response.json()

    with TestClient(create_asgi_app(temp_config)) as client:
        headers = {'X-AgentPorter-Key': temp_config.api_key,
                   'Accept': 'application/json, text/event-stream'}
        initialized = client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-03-26', 'capabilities': {},
                'clientInfo': {'name': 'busy-diagnostic-fixture', 'version': '1'}}})
        assert initialized.status_code == 200, initialized.text
        if 'mcp-session-id' in initialized.headers:
            headers['Mcp-Session-Id'] = initialized.headers['mcp-session-id']
        client.post('/mcp', headers=headers,
                    json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools = rpc(client, headers, 'tools/list', {})['result']['tools']
        declared = next(item for item in tools if item['name'] == tool)
        assert 'outputSchema' in declared
        assert 'WORKSPACE_BUSY' in json.dumps(declared['outputSchema'])
        arguments = {'workspace_id': 'project', 'argv': ['/bin/true']}
        result = rpc(client, headers, 'tools/call', {
            'name': tool, 'arguments': arguments})['result']
    assert result['isError'] is False
    assert result['structuredContent'] == BUSY
    assert json.loads(result['content'][0]['text']) == BUSY
    low_level.assert_not_called()
    job_launch.assert_not_called()


@pytest.mark.parametrize('tool', ['exec_run', 'exec_start'])
def test_mcp_rpc_execution_success_preserves_arbitrary_metadata(temp_config, tmp_path, monkeypatch, tool):
    from fastapi.testclient import TestClient
    from mcp.server.mcpserver import MCPServer
    from agentporter.server import create_asgi_app

    workspace = tmp_path / 'mcp-success-workspace'
    workspace.mkdir()
    temp_config.workspaces = {'project': {'path': str(workspace)}}
    temp_config.security.allowed_hosts = ['testserver']
    low_level = Mock(side_effect=AssertionError('fixture result must not execute a process'))
    monkeypatch.setattr(BubblewrapSandbox, '_run_command', low_level)
    monkeypatch.setattr(JobManager, '_popen', low_level)

    if tool == 'exec_run':
        monkeypatch.setattr(BubblewrapSandbox, 'run', Mock(return_value={
            'stdout': 'fixture stdout', 'stderr': '', 'exit_code': 0, 'timeout': False}))
    else:
        monkeypatch.setattr(JobManager, 'start_raw_job', Mock(return_value='job_fixture'))

    captured = {}
    streamable_http_app = MCPServer.streamable_http_app
    def capture_server(self, *args, **kwargs):
        captured['mcp'] = self
        return streamable_http_app(self, *args, **kwargs)
    monkeypatch.setattr(MCPServer, 'streamable_http_app', capture_server)
    secured_app = create_asgi_app(temp_config)
    registered_tool = captured['mcp']._tool_manager.get_tool(tool)
    original = registered_tool.fn
    def include_fixture_metadata(**kwargs):
        result = original(**kwargs)
        result['workspace_id'] = 'project'
        result['custom_metadata'] = {'fixture': True, 'origin': 'mcp-rpc'}
        return result
    registered_tool.fn = include_fixture_metadata

    def rpc(client, headers, method, params, request_id=1):
        response = client.post('/mcp', headers=headers,
            json={'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        assert response.status_code == 200, response.text
        if response.headers.get('content-type', '').startswith('text/event-stream'):
            line = next(line[6:] for line in response.text.splitlines() if line.startswith('data: '))
            return json.loads(line)
        return response.json()

    with TestClient(secured_app) as client:
        headers = {'X-AgentPorter-Key': temp_config.api_key,
                   'Accept': 'application/json, text/event-stream'}
        initialized = client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-03-26', 'capabilities': {},
                'clientInfo': {'name': 'busy-success-fixture', 'version': '1'}}})
        assert initialized.status_code == 200, initialized.text
        if 'mcp-session-id' in initialized.headers:
            headers['Mcp-Session-Id'] = initialized.headers['mcp-session-id']
        client.post('/mcp', headers=headers,
                    json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        result = rpc(client, headers, 'tools/call', {
            'name': tool, 'arguments': {'workspace_id': 'project', 'argv': ['/bin/true']}})['result']

    assert result['isError'] is False
    structured = result['structuredContent']
    assert structured['workspace_id'] == 'project'
    assert structured['custom_metadata'] == {'fixture': True, 'origin': 'mcp-rpc'}
    if tool == 'exec_run':
        assert structured['stdout'] == 'fixture stdout'
        assert structured['exit_code'] == 0
    else:
        assert structured['job_id'] == 'job_fixture'
        assert structured['status'] == 'running'
    assert json.loads(result['content'][0]['text']) == structured
    low_level.assert_not_called()
