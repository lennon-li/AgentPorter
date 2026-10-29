"""Capability names mirror MCP registration without granting execution rights."""
import asyncio
import json
from types import SimpleNamespace

import yaml
from starlette.testclient import TestClient

from agentporter.server import build_mcp_server, create_asgi_app
from agentporter.tools.system import create_system_tools
from agentporter.workspaces.registry import WorkspaceRegistry


def test_original_factory_api_includes_https_download():
    capabilities, _, _ = create_system_tools(
        WorkspaceRegistry(), SimpleNamespace(is_available=lambda: False))
    names = capabilities()['supported_tools']
    assert {'get_capabilities', 'exec_run', 'https_download', 'dispatch_agent'} <= set(names)
    assert len(names) == len(set(names))


def test_inventory_callback_is_lazy_live_and_returns_independent_snapshots():
    names = ['get_capabilities']
    calls = []
    def inventory():
        calls.append(True)
        return iter(names)
    capabilities, _, _ = create_system_tools(
        WorkspaceRegistry(), SimpleNamespace(is_available=lambda: False), inventory)
    assert not calls
    first = capabilities()['supported_tools']
    names.extend(['https_download', 'https_download'])
    assert first == ['get_capabilities']
    assert capabilities()['supported_tools'] == ['get_capabilities', 'https_download']
    assert len(calls) == 2


def test_server_inventory_equals_actual_sdk_tools_list_and_tracks_changes(temp_config, monkeypatch):
    monkeypatch.setattr('agentporter.sandbox.bubblewrap.BubblewrapSandbox.is_available', lambda self: False)
    mcp, context = build_mcp_server(temp_config)
    def inventory():
        return context['tools']['get_capabilities']()['supported_tools']
    registered = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert set(inventory()) == registered
    assert {'https_download', 'server_deploy_info', 'local_http_request', 'git_push',
            'scinet_inference_preflight'} <= registered
    def synthetic_inventory_probe() -> dict:
        return {'fixture': True}
    mcp.add_tool(synthetic_inventory_probe)
    assert 'synthetic_inventory_probe' in inventory()
    assert set(inventory()) == {tool.name for tool in asyncio.run(mcp.list_tools())}
    mcp.remove_tool('synthetic_inventory_probe')
    assert 'synthetic_inventory_probe' not in inventory()
    assert set(inventory()) == registered


def rpc(client, key, method, params):
    response = client.post('/mcp', headers={
        'X-AgentPorter-Key': key, 'Accept': 'application/json, text/event-stream'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    assert response.status_code == 200, response.text
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        return json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))
    return response.json()


def test_authenticated_public_inventory_parity_does_not_authorize_https(temp_config, tmp_path, monkeypatch):
    root = tmp_path / 'cranary'
    root.mkdir()
    temp_config.workspaces = {'cranary': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'cranary': {'path': str(root), 'operations': ['read']}}}))
    policy.chmod(0o600)
    calls = []
    def factory(*args, **kwargs):
        def download(*args, **kwargs):
            calls.append(True)
            raise AssertionError('Denied download must never reach acquisition worker')
        return download
    monkeypatch.setattr('agentporter.https_download.create_https_download_tool', factory)
    monkeypatch.setattr('agentporter.sandbox.bubblewrap.BubblewrapSandbox.is_available', lambda self: False)
    with TestClient(create_asgi_app(temp_config), client=('127.0.0.1', 12345)) as client:
        key = temp_config.api_key
        listed = rpc(client, key, 'tools/list', {})['result']['tools']
        result = rpc(client, key, 'tools/call', {'name': 'get_capabilities', 'arguments': {}})['result']
        assert not result.get('isError'), result
        capabilities = result.get('structuredContent')
        if capabilities is None:
            capabilities = json.loads(next(block['text'] for block in result['content'] if block['type'] == 'text'))
        assert set(capabilities['supported_tools']) == {tool['name'] for tool in listed}
        assert 'https_download' in capabilities['supported_tools']
        assert capabilities['scoped_public_https']['enabled'] is False
        assert capabilities['scoped_public_https']['generic_shell_network'] is False
        denied = rpc(client, key, 'tools/call', {'name': 'https_download', 'arguments': {
            'workspace_id': 'cranary', 'url': 'https://cran.r-project.org/src/contrib/example.tar.gz',
            'filename': 'example.tar.gz'}})['result']
        assert denied['isError'] is True
        assert calls == []
        unauthorized = client.post('/mcp', headers={'Accept': 'application/json, text/event-stream'},
            json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        assert unauthorized.status_code == 401
