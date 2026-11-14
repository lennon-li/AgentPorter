"""Capability names mirror MCP registration without granting execution rights."""
import asyncio
import json
import inspect
from types import SimpleNamespace

import yaml
from starlette.testclient import TestClient

from agentporter.server import build_mcp_server, create_asgi_app
from agentporter.tools.system import create_system_tools
from agentporter.workspaces.registry import WorkspaceRegistry


def install_synthetic_commit_authority(config, monkeypatch):
    """Install a real owner policy with a fixture-only Ed25519 identity."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agentporter.git_approvals import GitApprovalVerifier
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox

    workspace = config.config_dir.parent / 'synthetic-git-workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    config.workspaces = {'synthetic-git': {
        'path': str(workspace), 'writable': True, 'allow_git': True,
    }}
    config.sandbox.workspace_transactions = True
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.state_dir.chmod(0o700)

    signing_key = Ed25519PrivateKey.generate()
    verification_key = signing_key.public_key()
    ledger = config.state_dir / 'synthetic-git-approvals.sqlite3'
    GitApprovalVerifier(verification_key, ledger)
    public_bytes = verification_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    config.config_dir.mkdir(parents=True, exist_ok=True)
    policy = config.config_dir / 'git-commit-policy.json'
    policy.write_text(json.dumps({
        'version': 1,
        'author_name': 'Synthetic Fixture',
        'author_email': 'fixture@example.invalid',
        'verification_key': public_bytes.hex(),
        'ledger_path': str(ledger),
        'workspaces': ['synthetic-git'],
    }))
    policy.chmod(0o600)

    client_policy = config.config_dir / 'public-client-policy.yaml'
    client_policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'synthetic-git': {'path': str(workspace), 'operations': ['read', 'write', 'git_commit']},
    }}))
    client_policy.chmod(0o600)

    monkeypatch.setattr('agentporter.resources.load_gateway_job_resources', lambda _: {
        'memory_bytes': 4 * 1024**3, 'pids': 128,
        'cpu_quota_us': 200000, 'cpu_period_us': 100000,
    })
    class SyntheticResources:
        def __init__(self, settings, *, expected_service=None):
            self.settings = dict(settings)
        def recover(self):
            return None
    monkeypatch.setattr('agentporter.server.JobResources', SyntheticResources)
    monkeypatch.setattr(BubblewrapSandbox, 'is_available', lambda self: True)
    monkeypatch.setattr(
        'agentporter.agents.development.DevelopmentRuntime._sandbox_executable',
        lambda *args: '/fixture/bwrap',
    )


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


def test_workspace_access_reports_configured_transaction_mode():
    sandbox = SimpleNamespace(is_available=lambda: False, transactional_writes=False)
    capabilities, _, _ = create_system_tools(WorkspaceRegistry(), sandbox)
    assert capabilities()['sandbox']['workspace_access'] == 'read-only'
    sandbox.transactional_writes = True
    assert capabilities()['sandbox']['workspace_access'] == 'transactional'


def test_git_inventory_reports_effective_global_gates(temp_config, monkeypatch):
    monkeypatch.setattr('agentporter.sandbox.bubblewrap.BubblewrapSandbox.is_available', lambda self: False)
    _, context = build_mcp_server(temp_config)
    operations = context['tools']['get_capabilities']()['git_operations']
    assert operations['git_commit'] == {'backend_available': False, 'available': False, 'reason': 'backend_unavailable'}
    assert operations['git_push']['available'] is False
    assert operations['git_push']['reason'] == 'policy_denied'

    policy = temp_config.config_dir / 'action-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'action_modes': {
        'git_commit': 'LOCKED', 'git_push': 'ALLOW'}}))
    policy.chmod(0o600)
    _, context = build_mcp_server(temp_config)
    operations = context['tools']['get_capabilities']()['git_operations']
    assert operations['git_commit']['available'] is False
    assert operations['git_commit']['reason'] == 'policy_denied'
    assert operations['git_push']['available'] is False
    assert operations['git_push']['reason'] == 'policy_denied'


def test_push_inventory_remains_denied_with_permissive_policy_and_backend(temp_config, monkeypatch):
    from agentporter.client_policy import PRINCIPAL
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox

    monkeypatch.setattr(BubblewrapSandbox, 'is_available', lambda self: True)
    _, context = build_mcp_server(temp_config)
    monkeypatch.setattr(context['operator_action_policy'], 'check', lambda action, arguments: 'ALLOW')
    capabilities = context['tools']['get_capabilities']
    implementation = inspect.unwrap(capabilities)
    cells = dict(zip(implementation.__code__.co_freevars, implementation.__closure__))
    monkeypatch.setattr(cells['approved_pushes'], 'cell_contents', object())

    for principal in (None, 'public'):
        token = PRINCIPAL.set(principal)
        try:
            assert capabilities()['git_operations']['git_push'] == {
                'backend_available': True, 'available': False, 'reason': 'policy_denied'}
        finally:
            PRINCIPAL.reset(token)
    monkeypatch.setattr(cells['approved_pushes'], 'cell_contents', None)
    assert capabilities()['git_operations']['git_push'] == {
        'backend_available': False, 'available': False, 'reason': 'policy_denied'}


def test_git_inventory_reports_conditional_commit_backend(temp_config, monkeypatch):
    from agentporter.client_policy import PRINCIPAL
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    install_synthetic_commit_authority(temp_config, monkeypatch)
    _, context = build_mcp_server(temp_config)
    token = PRINCIPAL.set('public')
    try:
        result = context['tools']['get_capabilities']()
    finally:
        PRINCIPAL.reset(token)
    assert result['sandbox']['workspace_access'] == 'transactional'
    assert result['git_operations']['git_commit'] == {
        'backend_available': True, 'available': None,
        'reason': 'authorization_conditional', 'mode': 'APPROVAL'}
    assert result['git_operations']['git_push']['available'] is False
    monkeypatch.setattr(BubblewrapSandbox, 'is_available', lambda self: False)
    token = PRINCIPAL.set('public')
    try:
        assert context['tools']['get_capabilities']()['git_operations']['git_commit'] == {
            'backend_available': True, 'available': False, 'reason': 'sandbox_unavailable'}
    finally:
        PRINCIPAL.reset(token)


def test_read_only_client_and_policy_error_redaction(temp_config, monkeypatch):
    from agentporter.client_policy import PRINCIPAL
    install_synthetic_commit_authority(temp_config, monkeypatch)
    _, context = build_mcp_server(temp_config)
    context['client_policy'].scopes = {'read_only': frozenset({'read'})}
    token = PRINCIPAL.set('public')
    try:
        operation = context['tools']['get_capabilities']()['git_operations']['git_commit']
        assert operation['backend_available'] is True
        assert operation['available'] is None
        assert operation['reason'] == 'authorization_conditional'
        try:
            context['client_policy'].check('git_commit', {'workspace_id': 'read_only'})
        except PermissionError:
            pass
        else:
            raise AssertionError('read-only client must not be authorized to commit')
        policy = context['operator_action_policy']
        original_check = policy.check
        def denied(action, arguments):
            if action in {'git_commit', 'git_push'}:
                raise PermissionError('sensitive override policy details')
            return original_check(action, arguments)
        monkeypatch.setattr(policy, 'check', denied)
        result = context['tools']['get_capabilities']()
        assert all(result['git_operations'][action]['reason']=='policy_denied' for action in ('git_commit','git_push'))
        assert all(result['git_operations'][action]['reason']=='backend_unavailable' for action in ('git_fetch','git_pull','git_clone'))
        assert 'sensitive override policy details' not in json.dumps(result)
    finally:
        PRINCIPAL.reset(token)


def test_server_inventory_equals_actual_sdk_tools_list_and_tracks_changes(temp_config, monkeypatch):
    monkeypatch.setattr('agentporter.sandbox.bubblewrap.BubblewrapSandbox.is_available', lambda self: False)
    mcp, context = build_mcp_server(temp_config)
    def inventory():
        return context['tools']['get_capabilities']()['supported_tools']
    registered = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert set(inventory()) == registered
    assert {'https_download', 'server_deploy_info', 'local_http_request', 'git_push'} <= registered
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
    root = tmp_path / 'public-data'
    root.mkdir()
    temp_config.workspaces = {'public-data': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'public-data': {'path': str(root), 'operations': ['read']}}}))
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
            'workspace_id': 'public-data', 'url': 'https://cran.r-project.org/src/contrib/example.tar.gz',
            'filename': 'example.tar.gz'}})['result']
        assert denied['isError'] is True
        assert calls == []
        unauthorized = client.post('/mcp', headers={'Accept': 'application/json, text/event-stream'},
            json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
        assert unauthorized.status_code == 401
