"""Actual authenticated file writes: stale conflicts preserve native filesystem bytes."""
import hashlib

import pytest
import yaml
from starlette.testclient import TestClient

from agentporter.server import create_asgi_app
from agentporter.workspaces import shared_access


@pytest.fixture
def write_client(temp_config, tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    temp_config.workspaces = {'sample': {'path': str(root), 'writable': True}}
    temp_config.security.allowed_hosts = ['testserver']
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'sample': {'path': str(root), 'operations': ['read', 'write']}}}))
    policy.chmod(0o600)
    app = create_asgi_app(temp_config)
    with TestClient(app, client=('127.0.0.1', 12345), raise_server_exceptions=False) as client:
        yield root, app, client, {'X-AgentPorter-Key': temp_config.api_key}


def write(client, headers, expected):
    return client.post('/api/v1/workspaces/sample/files/write', headers=headers,
                       json={'path': 'file.txt', 'content': 'replacement', 'expected_sha256': expected})


@pytest.mark.parametrize('exists', [True, False])
def test_stale_expected_hash_or_missing_file_is_409_without_mutation(write_client, exists):
    root, _, client, headers = write_client
    path = root / 'file.txt'
    if exists:
        path.write_bytes(b'owner current bytes')
        before = path.stat()
    response = write(client, headers, hashlib.sha256(b'older bytes').hexdigest())
    assert response.status_code == 409
    assert response.json() == {'detail': 'File changed; read its current version before writing'}
    if exists:
        assert path.read_bytes() == b'owner current bytes'
        assert path.stat().st_ino == before.st_ino
    else:
        assert not path.exists()
    assert not list(root.glob('.agentporter-write-*'))


def test_concurrent_native_edit_is_409_and_preserves_later_owner_bytes(write_client, monkeypatch):
    root, _, client, headers = write_client
    path = root / 'file.txt'
    path.write_bytes(b'before')
    real_share = shared_access.share
    def concurrent(*args, **kwargs):
        real_share(*args, **kwargs)
        path.write_bytes(b'later owner edit')
    monkeypatch.setattr(shared_access, 'share', concurrent)
    response = write(client, headers, hashlib.sha256(b'before').hexdigest())
    assert response.status_code == 409
    assert path.read_bytes() == b'later owner edit'
    assert not list(root.glob('.agentporter-write-*'))


def test_unexpected_value_error_remains_500(write_client, monkeypatch):
    root, app, client, headers = write_client
    path = root / 'file.txt'
    path.write_bytes(b'unchanged')
    def unexpected(*args, **kwargs):
        raise ValueError('unexpected private diagnostic')
    monkeypatch.setattr(shared_access, 'acl', unexpected)
    response = write(client, headers, None)
    assert response.status_code == 500
    assert 'unexpected private diagnostic' not in response.text
    assert path.read_bytes() == b'unchanged'


def test_native_stale_error_retains_value_error_compatibility(tmp_path):
    target = tmp_path / 'file.txt'
    target.write_bytes(b'current')
    with pytest.raises(shared_access.StaleFileError) as error:
        shared_access.atomic_write(tmp_path, 'file.txt', b'replacement', '0' * 64)
    assert isinstance(error.value, ValueError)
    assert target.read_bytes() == b'current'


def test_native_positive_search_rest_file_and_mcp_path_preserve_colon_newline_contracts(write_client):
    import json
    root, _, client, headers = write_client
    marker = 'S07_NATIVE_REST_SEARCH_EXACT'
    names = ['search-folder/plain.txt', 'search-folder/colon:name.txt', 'search-folder/newline\nname.txt']
    for name in names:
        response = client.post('/api/v1/workspaces/sample/files/write', headers=headers,
                               json={'path': name, 'content': 'first\n'+marker+'\n'})
        assert response.status_code == 200
        assert (root/name).read_text() == 'first\n'+marker+'\n'
    arguments = {'query': marker, 'glob': 'search-folder/**', 'max_results': 10}
    response = client.post('/api/v1/workspaces/sample/files/search', headers=headers, json=arguments)
    assert response.status_code == 200
    expected = [{'file': name, 'line': 2, 'text': marker} for name in names]
    assert sorted(response.json(), key=lambda row: row['file']) == sorted(expected, key=lambda row: row['file'])
    mcp = client.post('/mcp', headers=dict(headers, Accept='application/json, text/event-stream'), json={
        'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call', 'params': {
            'name': 'search_text', 'arguments': dict(arguments, workspace_id='sample')}})
    assert mcp.status_code == 200
    envelope = json.loads(next(line[6:] for line in mcp.text.splitlines() if line.startswith('data: '))) if mcp.headers.get('content-type', '').startswith('text/event-stream') else mcp.json()
    result = envelope['result']
    assert not result.get('isError', False)
    if 'structuredContent' in result:
        hits = result['structuredContent']['result']
    else:
        objects = [json.loads(block['text']) for block in result['content']]
        hits = objects[0] if len(objects) == 1 and isinstance(objects[0], list) else objects
    assert sorted(hits, key=lambda row: row['path']) == sorted([
        {'path': name, 'line': 2, 'text': marker} for name in names], key=lambda row: row['path'])
    schema = client.get('/openapi.json', headers=headers)
    assert schema.status_code == 200
    properties = schema.json()['components']['schemas']['SearchResult']['properties']
    assert set(properties) == {'file', 'line', 'text'}
