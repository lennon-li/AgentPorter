"""Exercise actual authenticated REST/MCP serialization, not mocked returns."""
import hashlib
import json

import pytest
import yaml
from starlette.testclient import TestClient

from agentporter.server import create_asgi_app


def rpc(client, key, method, params):
    response = client.post('/mcp', headers={
        'X-AgentPorter-Key': key, 'Accept': 'application/json, text/event-stream'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    assert response.status_code == 200
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        return json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))
    return response.json()


@pytest.mark.parametrize('ranged', [False, True])
def test_authenticated_file_read_content_survives_both_transports(temp_config, tmp_path, ranged):
    root = tmp_path / 'workspace'
    root.mkdir()
    contents = 'first line\nsecond line\nthird line\n'
    (root / 'sample.txt').write_text(contents)
    temp_config.workspaces = {'sample': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'sample': {'path': str(root), 'operations': ['read']}}}))
    policy.chmod(0o600)
    with TestClient(create_asgi_app(temp_config), client=('127.0.0.1', 12345)) as client:
        key = temp_config.api_key
        arguments = {'workspace_id': 'sample', 'path': 'sample.txt'}
        if ranged:
            arguments.update(start_line=2, end_line=2)
        tools = rpc(client, key, 'tools/list', {})['result']['tools']
        tool = next(tool for tool in tools if tool['name'] == 'read_file')
        assert set(tool['outputSchema']['properties']) == {
            'path', 'content', 'sha256', 'size_bytes', 'total_lines', 'range'}
        result = rpc(client, key, 'tools/call', {'name': 'read_file', 'arguments': arguments})['result']
        assert not result.get('isError', False)
        text = json.loads(result['content'][0]['text'])
        structured = result['structuredContent']
        assert text == structured
        assert structured['content'] == ('second line\n' if ranged else contents)
        assert structured['sha256'] == hashlib.sha256(contents.encode()).hexdigest()
        body = {k: v for k, v in arguments.items() if k != 'workspace_id'}
        rest = client.post('/api/v1/workspaces/sample/files/read', json=body,
                           headers={'X-AgentPorter-Key': key})
        assert rest.status_code == 200
        assert rest.json() == structured
        assert structured['range'] == {'start_line': 2 if ranged else 1, 'end_line': 2 if ranged else 3}
        assert client.post('/api/v1/workspaces/sample/files/read', json=body).status_code == 401
        denied = rpc(client, key, 'tools/call', {'name': 'read_file', 'arguments': {
            'workspace_id': 'unscoped', 'path': 'sample.txt'}})['result']
        assert denied['isError'] is True
        assert 'structuredContent' not in denied
        assert contents not in str(denied)


@pytest.mark.parametrize('content,expected_lines', [
    ('first\rsecond\r', 2),
    ('first\r\nsecond\r\n', 2),
    ('first\n\nthird', 3),
    ('', 0),
])
def test_file_read_uses_same_line_boundaries_for_full_and_range(
        temp_config, tmp_path, content, expected_lines):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'sample.txt').write_bytes(content.encode())
    temp_config.workspaces = {'sample': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'sample': {'path': str(root), 'operations': ['read']}}}))
    policy.chmod(0o600)
    with TestClient(create_asgi_app(temp_config), client=('127.0.0.1', 12345)) as client:
        key = temp_config.api_key
        full_args = {'workspace_id': 'sample', 'path': 'sample.txt'}
        full = rpc(client, key, 'tools/call', {'name': 'read_file', 'arguments': full_args})['result']['structuredContent']
        assert full['total_lines'] == expected_lines
        assert full['range'] == {'start_line': 1, 'end_line': expected_lines}
        assert full['sha256'] == hashlib.sha256(content.encode()).hexdigest()
        for start, end in [(1, 1), (2, 5), (10, 12)]:
            args = {**full_args, 'start_line': start, 'end_line': end}
            mcp = rpc(client, key, 'tools/call', {'name': 'read_file', 'arguments': args})['result']['structuredContent']
            rest = client.post('/api/v1/workspaces/sample/files/read',
                               json={k: v for k, v in args.items() if k != 'workspace_id'},
                               headers={'X-AgentPorter-Key': key}).json()
            assert mcp == rest
            assert mcp['total_lines'] == expected_lines
            assert mcp['range'] == {'start_line': start, 'end_line': end}
            assert mcp['sha256'] == full['sha256']
            selected = ''.join(content.encode().decode().splitlines(keepends=True)[start - 1:end])
            assert mcp['content'] == selected


@pytest.mark.parametrize('field,value', [('start_line', 0), ('end_line', 0)])
def test_file_read_rejects_zero_line_bounds(temp_config, tmp_path, field, value):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'sample.txt').write_text('one\ntwo\n')
    temp_config.workspaces = {'sample': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'sample': {'path': str(root), 'operations': ['read']}}}))
    policy.chmod(0o600)
    with TestClient(create_asgi_app(temp_config), client=('127.0.0.1', 12345)) as client:
        args = {'workspace_id': 'sample', 'path': 'sample.txt', field: value}
        result = rpc(client, temp_config.api_key, 'tools/call',
                     {'name': 'read_file', 'arguments': args})['result']
        assert result['isError'] is True
        rest = client.post('/api/v1/workspaces/sample/files/read',
                           json={k: v for k, v in args.items() if k != 'workspace_id'},
                           headers={'X-AgentPorter-Key': temp_config.api_key})
        assert rest.status_code == 422


@pytest.fixture
def denial_read_client(temp_config, tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'sample.txt').write_text('one\ntwo\n')
    outside = tmp_path / 'private-owner-directory' / 'private-file.txt'
    outside.parent.mkdir()
    outside.write_text('private-outside-content')
    (root / 'escape.txt').symlink_to(outside)
    temp_config.workspaces = {'sample': {'path': str(root)}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'sample': {'path': str(root), 'operations': ['read']}}}))
    policy.chmod(0o600)
    app = create_asgi_app(temp_config)
    with TestClient(app, client=('127.0.0.1', 12345),
                    raise_server_exceptions=False) as client:
        yield client, temp_config.api_key, app.app.state.tools, outside


@pytest.mark.parametrize('body,status,detail', [
    ({'path': '../README.md'}, 400, 'File read request denied'),
    ({'path': 'escape.txt'}, 400, 'File read request denied'),
    ({'path': '.ssh/id_rsa'}, 400, 'File read request denied'),
    ({'path': 'sample.txt', 'start_line': 2, 'end_line': 1},
     400, 'File read request denied'),
    ({'path': 'missing.txt'}, 404, 'File not found'),
])
def test_rest_file_read_denials_have_sanitized_client_errors(
        denial_read_client, body, status, detail):
    client, key, _, outside = denial_read_client
    response = client.post('/api/v1/workspaces/sample/files/read', json=body,
                           headers={'X-AgentPorter-Key': key})
    assert response.status_code == status
    assert response.json() == {'detail': detail}
    assert str(outside) not in response.text
    assert str(outside.parent) not in response.text
    assert outside.read_text() not in response.text
    for headers in ({}, {'X-AgentPorter-Key': 'invalid-key'}):
        assert client.post('/api/v1/workspaces/sample/files/read', json=body,
                           headers=headers).status_code == 401


@pytest.mark.parametrize('path', ['../README.md', 'escape.txt', '.ssh/id_rsa', 'missing.txt'])
def test_mcp_file_read_denials_remain_tool_errors(denial_read_client, path):
    client, key, _, outside = denial_read_client
    result = rpc(client, key, 'tools/call', {'name': 'read_file', 'arguments': {
        'workspace_id': 'sample', 'path': path}})['result']
    assert result['isError'] is True
    assert 'structuredContent' not in result
    assert outside.read_text() not in str(result)


@pytest.mark.parametrize('exception,status,detail', [
    (PermissionError('private-owner-directory/private-file.txt'),
     403, 'File read access denied'),
    (RuntimeError('private-owner-directory/private-file.txt'), 500, None),
    (OSError('private-owner-directory/private-file.txt'), 500, None),
])
def test_rest_file_read_maps_access_denial_but_preserves_unexpected_faults(
        denial_read_client, monkeypatch, exception, status, detail):
    client, key, tools, _ = denial_read_client
    def fail_read(**kwargs):
        raise exception
    monkeypatch.setitem(tools, 'read_file', fail_read)
    response = client.post('/api/v1/workspaces/sample/files/read',
                           json={'path': 'sample.txt'}, headers={'X-AgentPorter-Key': key})
    assert response.status_code == status
    if detail is not None:
        assert response.json() == {'detail': detail}
    assert 'private-owner-directory' not in response.text


def test_file_read_mapping_does_not_swallow_other_tool_value_errors(
        denial_read_client, monkeypatch):
    client, key, tools, _ = denial_read_client
    def fail_list(**kwargs):
        raise ValueError('unexpected unrelated tool failure')
    monkeypatch.setitem(tools, 'list_files', fail_list)
    response = client.post('/api/v1/workspaces/sample/files/list',
                           json={'path': ''}, headers={'X-AgentPorter-Key': key})
    assert response.status_code == 500
