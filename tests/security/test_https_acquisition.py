"""Offline acquisition security tests; no upstream access or owner-policy writes."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from agentporter.https_download import create_https_download_tool, publish, stream_download
from agentporter.scoped_https import ScopedPublicHTTPSPolicy
from agentporter.workspaces.registry import WorkspaceRegistry

URL = 'https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz'
DIRECTORY = 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads'


def policy(tmp_path):
    config = tmp_path / 'config'; config.mkdir(mode=0o700)
    text = Path('docs/examples/a7dev-cranary-acquisition-https.yaml').read_text()
    path = config / 'public-https.yaml'; path.write_text(text); path.chmod(0o600)
    return ScopedPublicHTTPSPolicy(config)


class Response:
    def __init__(self, body=b'\x1f\x8b\xff\0\x80', status=200, headers=None):
        self.status = status; self.body = io.BytesIO(body)
        self.headers = headers if headers is not None else [('Content-Length', str(len(body)))]
    def getheaders(self): return self.headers
    def read(self, size): return self.body.read(size)


def connection(response):
    conn = Mock(); conn.getresponse.return_value = response
    return Mock(return_value=conn), conn


def test_binary_bytes_and_independently_supplied_checksum(tmp_path):
    data = bytes(range(256)) * 2048
    factory, conn = connection(Response(data)); out = io.BytesIO()
    receipt = stream_download(policy(tmp_path), 'cranary', URL, out,
        expected_sha256=hashlib.sha256(data).hexdigest(), connection_factory=factory)
    assert out.getvalue() == data
    assert receipt['bytes'] == len(data) and receipt['expected_sha256_verified'] is True
    assert receipt['sha256'] == hashlib.sha256(data).hexdigest()
    args = conn.request.call_args
    assert args.args[:2] == ('GET', '/cran/2021-06-30/src/contrib/PACKAGES.gz')
    assert args.kwargs['headers']['Accept-Encoding'] == 'identity'
    assert 'Authorization' not in args.kwargs['headers']
    conn.close.assert_called_once()


def test_first_fetch_digest_does_not_claim_external_verification(tmp_path):
    factory, _ = connection(Response())
    assert stream_download(policy(tmp_path), 'cranary', URL, io.BytesIO(),
        connection_factory=factory)['expected_sha256_verified'] is False


@pytest.mark.parametrize('status', [201, 204, 206, 301, 302, 307, 308, 401, 404, 500])
def test_redirects_partial_and_error_responses_rejected(tmp_path, status):
    factory, conn = connection(Response(status=status)); out = io.BytesIO()
    with pytest.raises(PermissionError):
        stream_download(policy(tmp_path), 'cranary', URL, out, connection_factory=factory)
    assert not out.getvalue(); conn.close.assert_called_once()


@pytest.mark.parametrize('headers,body', [
    ([('Content-Length', '200')], b'abc'),
    ([('Content-Length', '2')], b'abc'),
    ([('Content-Length', '16777217')], b''),
    ([('Content-Length', '3'), ('Content-Length', '3')], b'abc'),
    ([('Content-Length', '-1')], b'abc'),
    ([('Content-Length', '3'), ('Transfer-Encoding', 'chunked')], b'abc'),
    ([('Content-Encoding', 'gzip')], b'abc'),
    ([('Transfer-Encoding', 'gzip, chunked')], b'abc'),
    ([('ETag', 'x\nsecret')], b'abc'),
    ([('ETag', 'x' * 513)], b'abc'),
])
def test_framing_truncation_encoding_and_receipt_limits(tmp_path, headers, body):
    factory, _ = connection(Response(body, headers=headers))
    with pytest.raises(ValueError):
        stream_download(policy(tmp_path), 'cranary', URL, io.BytesIO(), connection_factory=factory)


def test_chunked_stream_cap_and_checksum_mismatch(tmp_path):
    p = policy(tmp_path)
    for expected, cap, response in [('0' * 64, 10, Response(b'abc')),
            (None, 2, Response(b'abc', headers=[('Transfer-Encoding', 'chunked')]))]:
        factory, _ = connection(response)
        with pytest.raises(ValueError):
            stream_download(p, 'cranary', URL, io.BytesIO(), expected_sha256=expected,
                            max_bytes=cap, connection_factory=factory)


@pytest.mark.parametrize('url', [
    'https://packagemanager.posit.co/cran/latest/src/contrib/PACKAGES.gz',
    'https://packagemanager.posit.co/cran/2021-02-30/src/contrib/PACKAGES.gz',
    'https://packagemanager.posit.co/__api__/admin',
    URL + '?redirect=https://example.com', URL + '#fragment',
    URL.replace('https:', 'http:'), URL.replace('.co/', '.co:444/'),
    URL.replace('packagemanager.posit.co', '127.0.0.1'),
    URL.replace('packagemanager.posit.co', '169.254.169.254'),
    'https://cran.r-project.org/src/contrib/Archive/Foo/Bar_1.0.tar.gz',
    'https://api.github.com/repos/ropensci-archive/rrlite',
    'https://evil.example/file',
])
def test_download_host_path_authorization(tmp_path, url):
    p = policy(tmp_path)
    with pytest.raises((PermissionError, ValueError)):
        p.authorize_download('cranary', url)


def test_owner_grant_and_workspace_required(tmp_path):
    p = policy(tmp_path)
    with pytest.raises(PermissionError): p.authorize_download('agentporter-dev', URL)
    path = p.config_dir / 'public-https.yaml'
    doc = yaml.safe_load(path.read_text()); doc['version'] = 1
    del doc['workspaces']['cranary']['downloads']
    path.write_text(yaml.safe_dump(doc)); path.chmod(0o600)
    with pytest.raises(PermissionError):
        ScopedPublicHTTPSPolicy(p.config_dir).authorize_download('cranary', URL)
    with pytest.raises(PermissionError): p.authorize('cranary', 'POST', URL)


def test_publication_is_exact_no_overwrite_and_binary_safe(tmp_path):
    body = b'\xff\0\x80'; expected = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    root = tmp_path / 'workspace'; root.mkdir()
    path = publish(root, DIRECTORY, 'PACKAGES.gz', io.BytesIO(body), expected)
    assert (root / path).read_bytes() == body
    with pytest.raises(FileExistsError):
        publish(root, DIRECTORY, 'PACKAGES.gz', io.BytesIO(b'new'), {'bytes': 3, 'sha256': hashlib.sha256(b'new').hexdigest()})
    assert (root / path).read_bytes() == body
    with pytest.raises(ValueError):
        publish(root, DIRECTORY, 'bad.gz', io.BytesIO(body), {'bytes': 3, 'sha256': '0' * 64})
    assert not (root / DIRECTORY / 'bad.gz').exists()
    assert not list((root / DIRECTORY).glob('.acquire-*'))


@pytest.mark.parametrize('filename', ['../config.yaml', '/tmp/escape', '.env', 'x/y', 'x\\y', '', 'x' * 129])
def test_publication_rejects_paths(tmp_path, filename):
    with pytest.raises(ValueError): publish(tmp_path, DIRECTORY, filename, io.BytesIO(), {})


def test_publication_denies_directory_and_existing_target_symlinks(tmp_path):
    outside = tmp_path / 'outside'; outside.mkdir()
    root = tmp_path / 'workspace'; root.mkdir(); (root / 'data-raw').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError): publish(root, DIRECTORY, 'x', io.BytesIO(), {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()})
    assert not list(outside.iterdir())


def test_fixed_worker_receipt_spool_and_clean_environment(tmp_path, monkeypatch):
    p = policy(tmp_path); root = tmp_path / 'workspace'; root.mkdir()
    registry = WorkspaceRegistry({'cranary': {'path': str(root)}})
    data = b'\x1f\x8b\x80\0'; digest = hashlib.sha256(data).hexdigest()
    seen = {}
    def run(cmd, **kwargs):
        seen.update(kwargs); seen['cmd'] = cmd
        assert cmd[1:4] == ['-I', '-m', 'agentporter.https_download']
        assert kwargs['cwd'] == '/' and kwargs['timeout'] == 60
        assert set(kwargs['env']) == {'PATH', 'LANG', 'HOME'}
        os.write(kwargs['pass_fds'][0], data)
        return SimpleNamespace(returncode=0, stdout=json.dumps({'bytes': len(data), 'sha256': digest,
            'http_status': 200, 'expected_sha256_verified': True}).encode(), stderr=b'')
    monkeypatch.setattr(subprocess, 'run', run)
    tool = create_https_download_tool(registry, p, tmp_path)
    receipt = tool('cranary', URL, 'PACKAGES.gz', digest)
    assert (root / receipt['path']).read_bytes() == data
    assert receipt['training_eligible'] is False and receipt['historical_identity_verified'] is False
    assert not set(seen['env']) & {'HTTP_PROXY', 'HTTPS_PROXY', 'OPENAI_API_KEY', 'AGENTPORTER_API_KEY'}


def test_child_failure_timeout_or_bad_checksum_never_publishes(tmp_path, monkeypatch):
    p = policy(tmp_path); root = tmp_path / 'workspace'; root.mkdir()
    tool = create_https_download_tool(WorkspaceRegistry({'cranary': {'path': str(root)}}), p, tmp_path)
    for mode in ('denied', 'timeout', 'mismatch'):
        def run(cmd, **kwargs):
            if mode == 'timeout': raise subprocess.TimeoutExpired(cmd, 60)
            return SimpleNamespace(returncode=77 if mode == 'denied' else 0,
                stdout=json.dumps({'bytes': 1, 'sha256': '0' * 64, 'http_status': 200,
                                  'expected_sha256_verified': True}).encode(), stderr=b'')
        monkeypatch.setattr(subprocess, 'run', run)
        with pytest.raises((ValueError, subprocess.TimeoutExpired)):
            tool('cranary', URL, mode + '.gz', '1' * 64)
    assert not list(root.iterdir())


@pytest.mark.parametrize('field,value', [
    ('max_response_bytes', 16777217), ('max_response_bytes', True),
    ('timeout_seconds', 61), ('timeout_seconds', -1),
    ('directory', '../config'), ('directory', 'data-raw/cran-history/reports/../downloads'),
    ('hosts', ['api.github.com']), ('hosts', ['cran.r-project.org', 'cran.r-project.org']),
])
def test_owner_download_approval_rejects_unsafe_grants(tmp_path, field, value):
    p = policy(tmp_path); path = p.config_dir / 'public-https.yaml'
    doc = yaml.safe_load(path.read_text()); doc['workspaces']['cranary']['downloads'][field] = value
    path.write_text(yaml.safe_dump(doc)); path.chmod(0o600)
    with pytest.raises(ValueError): ScopedPublicHTTPSPolicy(p.config_dir)


def test_exact_mcp_and_rest_public_scope_is_enforced(temp_config, tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    from agentporter.server import create_asgi_app
    from test_closeout_client_policy import rpc
    root = tmp_path / 'workspace'; root.mkdir()
    temp_config.security.allowed_hosts = ['testserver']
    temp_config.workspaces = {'cranary': {'path': str(root)}}
    control = temp_config.config_dir / 'public-client-policy.yaml'
    control.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'cranary': {'path': str(root), 'operations': ['https']}}})); control.chmod(0o600)
    calls = []
    def factory(*args, **kwargs):
        def run(*args, **kwargs): calls.append((args, kwargs)); return {'approved_fixture': True}
        return run
    monkeypatch.setattr('agentporter.https_download.create_https_download_tool', factory)
    with TestClient(create_asgi_app(temp_config), client=('127.0.0.1', 12345)) as client:
        key = temp_config.api_key
        result = rpc(client, key, 'https_download', {'workspace_id': 'cranary', 'url': URL, 'filename': 'PACKAGES.gz'})
        assert not result['result'].get('isError'), result
        assert len(calls) == 1
        response = client.post('/api/v1/workspaces/cranary/exec/https-download',
            json={'url': URL, 'filename': 'PACKAGES.gz'}, headers={'X-AgentPorter-Key': key})
        assert response.status_code == 200 and len(calls) == 2
        assert rpc(client, key, 'https_download', {'workspace_id': 'obsidian', 'url': URL, 'filename': 'x'})['result']['isError']
        assert rpc(client, key, 'write_file', {'workspace_id': 'cranary', 'path': '.env', 'content': 'bad'})['result']['isError']
        assert len(calls) == 2


def test_single_download_slot_is_held_until_worker_finishes(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    p = policy(tmp_path); root = tmp_path / 'workspace'; root.mkdir()
    tool = create_https_download_tool(WorkspaceRegistry({'cranary': {'path': str(root)}}), p, tmp_path)
    entered = threading.Event(); finish = threading.Event()
    def run(cmd, **kwargs):
        entered.set(); assert finish.wait(5)
        return SimpleNamespace(returncode=77, stdout=b'', stderr=b'')
    monkeypatch.setattr(subprocess, 'run', run)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(tool, 'cranary', URL, 'one.gz')
        assert entered.wait(5)
        try:
            with pytest.raises(PermissionError, match='capacity'): tool('cranary', URL, 'two.gz')
        finally: finish.set()
        with pytest.raises(ValueError): first.result(timeout=5)
    with pytest.raises(ValueError): tool('cranary', URL, 'reused.gz')


def test_rest_and_mcp_use_actual_owner_grant_and_fixed_binary_worker(temp_config, tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    from agentporter.server import create_asgi_app
    # No public-client-policy here: exercise v12-compatible owner authorization too.
    root = tmp_path / 'workspace'; root.mkdir()
    temp_config.security.allowed_hosts = ['testserver']
    other = tmp_path / 'other-workspace'; other.mkdir()
    temp_config.workspaces = {'cranary': {'path': str(root)}, 'other': {'path': str(other)}}
    control = temp_config.config_dir / 'public-https.yaml'
    control.write_text(Path('docs/examples/a7dev-cranary-acquisition-https.yaml').read_text()); control.chmod(0o600)
    app = create_asgi_app(temp_config)
    data = b'\x1f\x8b\xff\0' * 100000; digest = hashlib.sha256(data).hexdigest()
    def run(cmd, **kwargs):
        assert cmd[1:4] == ['-I', '-m', 'agentporter.https_download']
        os.write(kwargs['pass_fds'][0], data)
        return SimpleNamespace(returncode=0, stdout=json.dumps({'bytes': len(data), 'sha256': digest,
            'http_status': 200, 'expected_sha256_verified': True}).encode(), stderr=b'')
    monkeypatch.setattr(subprocess, 'run', run)
    with TestClient(app, client=('127.0.0.1', 12345)) as client:
        headers = {'X-AgentPorter-Key': temp_config.api_key}
        response = client.post('/api/v1/workspaces/cranary/exec/https-download',
            json={'url': URL, 'filename': 'rest.gz', 'expected_sha256': digest}, headers=headers)
        assert response.status_code == 200, response.text
        assert (root / response.json()['path']).read_bytes() == data
        bad = client.post('/api/v1/workspaces/other/exec/https-download',
            json={'url': URL, 'filename': 'bad.gz'}, headers=headers)
        assert bad.status_code == 403
        rpc_headers = {**headers, 'Accept': 'application/json, text/event-stream'}
        initialized = client.post('/mcp', headers=rpc_headers, json={'jsonrpc': '2.0', 'id': 0,
            'method': 'initialize', 'params': {'protocolVersion': '2025-03-26', 'capabilities': {},
                'clientInfo': {'name': 'acquisition-fixture', 'version': '1'}}})
        assert initialized.status_code == 200, initialized.text
        if 'mcp-session-id' in initialized.headers:
            rpc_headers['Mcp-Session-Id'] = initialized.headers['mcp-session-id']
        client.post('/mcp', headers=rpc_headers, json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        response = client.post('/mcp', headers=rpc_headers, json={'jsonrpc': '2.0', 'id': 1,
            'method': 'tools/call', 'params': {'name': 'https_download', 'arguments': {
                'workspace_id': 'cranary', 'url': URL, 'filename': 'mcp.gz', 'expected_sha256': digest}}})
        assert response.status_code == 200
        if response.headers.get('content-type', '').startswith('text/event-stream'):
            result = json.loads(next(x[6:] for x in response.text.splitlines() if x.startswith('data: ')))
        else: result = response.json()
        assert not result['result'].get('isError'), result
        assert (root / DIRECTORY / 'mcp.gz').read_bytes() == data


def test_uncertain_resource_cleanup_never_publishes_and_keeps_global_capacity(tmp_path, monkeypatch):
    from agentporter.admission import synchronous_slot
    from agentporter.resources import ResourceCleanupError
    from agentporter.tools.jobs import JobManager
    p = policy(tmp_path); root = tmp_path / 'workspace'; root.mkdir()
    manager = JobManager(tmp_path / 'state')
    lease = Mock(); lease.command.side_effect = lambda cmd: cmd
    lease.close.side_effect = ResourceCleanupError('synthetic populated envelope')
    resources = Mock(); resources.create.return_value = lease
    tool = create_https_download_tool(WorkspaceRegistry({'cranary': {'path': str(root)}}), p, tmp_path,
        resources=resources, slot=lambda: synchronous_slot(manager))
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs:
        SimpleNamespace(returncode=77, stdout=b'', stderr=b''))
    with pytest.raises(ResourceCleanupError): tool('cranary', URL, 'held.gz')
    db = manager._get_db()
    try: assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 1
    finally: db.close()
    assert not list(root.iterdir())
