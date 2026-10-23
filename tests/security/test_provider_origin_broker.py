"""Nonsecret synthetic tests; no external network or provider accounts."""
import socket
import ssl
import threading
import json
import subprocess

import pytest

from agentporter.agents import provider_egress as broker


@pytest.mark.parametrize('agent', ['jax', 'liz', 'prof', 'ming', 'wei', 'argie', 'phil'])
def test_no_repository_or_general_https_capability(agent):
    rules = broker.provider_rules(agent)
    for host in ['github.com', 'api.github.com', 'gitlab.com', 'example.com']:
        assert not broker.operation_allowed(rules, host, 'POST', '/repos/a/b/git/refs')
    assert not broker.operation_allowed(rules, 'search.parallel.ai', 'POST', '/mcp')


def test_parallel_is_explicit_and_operation_scoped():
    rules = broker.provider_rules('jax', True)
    assert broker.operation_allowed(rules, 'search.parallel.ai', 'POST', '/mcp')
    assert not broker.operation_allowed(rules, 'search.parallel.ai', 'POST', '/upload')
    assert not broker.provider_rules('jax')


@pytest.mark.parametrize('target', ['https://github.com/v1/responses', '//github.com/v1/responses',
    '/v1/../repos', '/v1/%72esponses', '/v1/responses#fragment', '/v1\\responses'])
def test_ambiguous_request_targets_fail_closed(target):
    assert not broker.operation_allowed(broker.provider_rules('liz'), 'api.openai.com', 'POST', target)


def request(extra=b'', host=b'api.openai.com'):
    return b'POST /v1/responses HTTP/1.1\r\nHost: ' + host + b'\r\nContent-Length: 2' + extra


@pytest.mark.parametrize('extra', [b'\r\nTransfer-Encoding: chunked',
    b'\r\nContent-Length: 2', b'\r\nExpect: 100-continue', b'\r\n folded: value',
    b'\r\nConnection: content-length', b'\r\nBad Header: value'])
def test_smuggling_and_ambiguous_framing_rejected(extra):
    with pytest.raises(ValueError):
        broker.request_header(request(extra), 'api.openai.com', broker.provider_rules('liz'))


@pytest.mark.parametrize('encoding', [b'zstd', b'gzip', b'br', b'identity, gzip', b''])
def test_encoded_requests_cannot_change_the_inspected_body(encoding):
    with pytest.raises(PermissionError, match='Encoded request bodies'):
        broker.request_header(request(b'\r\nContent-Encoding: ' + encoding),
                              'api.openai.com', broker.provider_rules('liz'))
    with pytest.raises(PermissionError, match='Encoded request bodies'):
        broker.validate_payload(request(b'\r\nContent-Encoding: ' + encoding), b'{}', 'api.openai.com')


def test_authority_mismatch_and_disallowed_operations_rejected():
    rules = broker.provider_rules('liz')
    with pytest.raises(PermissionError):
        broker.request_header(request(host=b'github.com'), 'api.openai.com', rules)
    for method, path in [(b'POST', b'/repos/a/b'), (b'DELETE', b'/v1/responses'),
                         (b'GET', b'/v1/files')]:
        with pytest.raises(PermissionError):
            broker.request_header(method + b' ' + path + b' HTTP/1.1\r\nHost: api.openai.com',
                                  'api.openai.com', rules)


def test_canonical_upstream_has_no_rewrite_or_proxy_credentials():
    data, length = broker.request_header(request(
        b'\r\nX-Forwarded-Host: github.com\r\nX-Original-URL: /repos/a/b'
        b'\r\nProxy-Authorization: secret\r\nAuthorization: Bearer synthetic'),
        'api.openai.com', broker.provider_rules('liz'))
    assert length == 2
    assert b'Host: api.openai.com\r\n' in data
    assert b'Connection: close\r\n' in data
    assert b'authorization: Bearer synthetic' in data
    assert b'github.com' not in data and b'/repos/' not in data and b'secret' not in data


def test_observed_argie_bootstrap_is_method_and_path_scoped():
    rules = broker.provider_rules('argie')
    assert broker.operation_allowed(rules, 'www.googleapis.com', 'GET', '/oauth2/v2/userinfo')
    assert not broker.operation_allowed(rules, 'www.googleapis.com', 'POST', '/upload/drive/v3/files')
    assert broker.operation_allowed(rules, 'lh3.googleusercontent.com', 'GET', '/a/synthetic=s96-c')
    assert not broker.operation_allowed(rules, 'lh3.googleusercontent.com', 'POST', '/a/synthetic')
    for operation in ('fetchAdminControls', 'fetchUserInfo', 'retrieveUserQuotaSummary', 'listExperiments'):
        assert broker.operation_allowed(rules, 'daily-cloudcode-pa.googleapis.com', 'POST', '/v1internal:' + operation)
    assert not broker.operation_allowed(rules, 'daily-cloudcode-pa.googleapis.com', 'POST', '/v1internal:updateAdminControls')


@pytest.mark.parametrize('agent', ['liz', 'prof'])
def test_codex_workspace_discovery_does_not_grant_account_or_hosted_tool_writes(agent):
    rules = broker.provider_rules(agent)
    assert broker.operation_allowed(rules, 'chatgpt.com', 'GET', '/backend-api/wham/accounts/check')
    for method, path in [('POST', '/backend-api/wham/accounts/check'),
                         ('GET', '/backend-api/wham/accounts/other'),
                         ('POST', '/backend-api/wham/accounts/send_add_credits_nudge_email'),
                         ('POST', '/backend-api/ps/mcp')]:
        assert not broker.operation_allowed(rules, 'chatgpt.com', method, path)
    assert not broker.operation_allowed(rules, 'api.openai.com', 'GET', '/backend-api/wham/accounts/check')


@pytest.fixture
def relay(tmp_path):
    tmp_path.chmod(0o700)
    proxy = broker.ProviderEgress(tmp_path / 'relay.sock', agent='liz')
    yield proxy
    proxy.close()


def test_server_leaf_is_not_a_ca_and_private_keys_do_not_remain_on_disk(relay):
    directory = relay._tls_directory
    info = subprocess.check_output(['/usr/bin/openssl', 'x509', '-in', str(directory / 'leaf.pem'),
        '-noout', '-ext', 'basicConstraints,extendedKeyUsage'], text=True)
    assert 'CA:FALSE' in info and 'TLS Web Server Authentication' in info
    assert not (directory / 'key.pem').exists()
    assert not (directory / 'leaf-key.pem').exists()
    assert b'PRIVATE KEY' not in relay.ca_bundle.read_bytes()


def connect_client(relay, host='api.openai.com', server_name=None):
    client, server = socket.socketpair()
    assert relay._slots.acquire(blocking=False)
    with relay._lock:
        relay._connections.add(server)
    thread = threading.Thread(target=relay._handle, args=(server,), daemon=True)
    thread.start()
    client.settimeout(5)
    client.sendall(('CONNECT ' + host + ':443 HTTP/1.1\r\nHost: ' + host + ':443\r\n\r\n').encode())
    header = client.recv(4096)
    if not header.startswith(b'HTTP/1.1 200 '):
        return client, thread, header
    context = ssl.create_default_context(cafile=str(relay.ca_bundle))
    context.set_alpn_protocols(['http/1.1'])
    return context.wrap_socket(client, server_hostname=server_name or host), thread, header


def test_real_tls_domain_fronting_cannot_open_upstream(relay, monkeypatch):
    calls = []
    monkeypatch.setattr(broker, '_connect_public', lambda host: calls.append(host))
    client, thread, _ = connect_client(relay)
    try:
        client.sendall(request(host=b'github.com') + b'\r\n\r\n{}')
        assert client.recv(4096).startswith(b'HTTP/1.1 403 ')
    finally:
        client.close()
        thread.join(2)
    assert not calls and not thread.is_alive()


def test_real_tls_valid_request_reaches_fixed_verified_origin(relay, monkeypatch):
    observed = []
    server_threads = []
    relay._upstream_context = ssl.create_default_context(cafile=str(relay.ca_bundle))
    def connect(host):
        observed.append(host)
        client, server = socket.socketpair()
        def serve():
            with relay._contexts[host].wrap_socket(server, server_side=True) as connection:
                header, body = broker.read_header(connection)
                while len(body) < 2:
                    body += connection.recv(2 - len(body))
                observed.append((header, body))
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        server_threads.append(thread)
        return client
    monkeypatch.setattr(broker, '_connect_public', connect)
    client, thread, _ = connect_client(relay)
    try:
        client.sendall(request() + b'\r\n\r\n{}')
        data = bytearray()
        while block := client.recv(4096):
            data.extend(block)
        assert data.startswith(b'HTTP/1.1 200 ') and data.endswith(b'{}')
    finally:
        client.close()
        thread.join(2)
        for server_thread in server_threads:
            server_thread.join(2)
    assert observed[0] == 'api.openai.com'
    assert b'Host: api.openai.com\r\n' in observed[1][0]
    assert observed[1][1] == b'{}'


def test_unlisted_connect_and_sni_mismatch_rejected(relay, monkeypatch):
    calls = []
    monkeypatch.setattr(broker, '_connect_public', lambda host: calls.append(host))
    client, thread, header = connect_client(relay, 'github.com')
    assert header.startswith(b'HTTP/1.1 403 ')
    client.close()
    thread.join(2)
    with pytest.raises(ssl.SSLError):
        connect_client(relay, server_name='chatgpt.com')
    assert not calls


def model_body(data, host='api.openai.com', path='/v1/responses'):
    broker.validate_payload(('POST ' + path + ' HTTP/1.1\r\nHost: ' + host).encode(),
                            json.dumps(data).encode(), host)


@pytest.mark.parametrize('tool', [{'type': 'mcp', 'server_url': 'https://example.com'},
    {'type': 'web_search'}, {'type': 'code_interpreter'},
    {'type': 'function', 'name': 'fake', 'server_url': 'https://example.com'},
    {'type': 'namespace', 'tools': [{'type': 'mcp', 'server_url': 'https://example.com'}]}])
def test_hosted_provider_capabilities_cannot_bypass_origin_controls(tool):
    with pytest.raises(PermissionError):
        model_body({'tools': [tool]})


@pytest.mark.parametrize('value', ['synthetic', {}, [], None, False])
@pytest.mark.parametrize('field', ['previous_response_id', 'conversation', 'prompt',
                                 'mcp_servers', 'web_search_options', 'cachedContent'])
def test_uninspected_server_state_and_hosted_configuration_rejected(field, value):
    with pytest.raises(PermissionError):
        model_body({field: value})


def test_local_tool_schemas_and_known_google_envelope_are_admitted():
    model_body({'tools': [{'type': 'function', 'name': 'exec'},
                         {'type': 'custom', 'name': 'patch'},
                         {'type': 'namespace', 'tools': [{'type': 'function', 'name': 'read'}]}]})
    model_body({'tools': [{'name': 'Read', 'input_schema': {}}]}, 'api.anthropic.com', '/v1/messages')
    model_body({'request': {'tools': [{'functionDeclarations': [{'name': 'read_file'}]}]}},
               'daily-cloudcode-pa.googleapis.com', '/v1internal:streamGenerateContent')
    with pytest.raises(PermissionError):
        model_body({'request': {'tools': [{'googleSearch': {}}]}},
                   'daily-cloudcode-pa.googleapis.com', '/v1internal:streamGenerateContent')


@pytest.mark.parametrize('method,params,allowed', [
    ('initialize', {}, True), ('tools/list', {}, True),
    ('tools/call', {'name': 'web_search'}, True),
    ('tools/call', {'name': 'web_fetch'}, True),
    ('tools/call', {'name': 'publish_repository'}, False),
    ('resources/read', {'uri': 'https://example.com'}, False),
    ('prompts/get', {}, False)])
def test_parallel_payload_only_admits_approved_mcp_tools(method, params, allowed):
    data = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    if allowed:
        model_body(data, 'search.parallel.ai', '/mcp')
    else:
        with pytest.raises(PermissionError):
            model_body(data, 'search.parallel.ai', '/mcp')


def test_duplicate_json_members_and_mcp_continuations_rejected():
    with pytest.raises(ValueError):
        broker.validate_payload(request(), b'{"tools":[],"tools":[]}', 'api.openai.com')
    with pytest.raises(PermissionError):
        model_body({'input': [{'type': 'mcp_approval_response', 'approve': True}]})


def test_opaque_upgrades_rejected_even_on_admitted_get_route():
    with pytest.raises(PermissionError):
        broker.request_header(b'GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nUpgrade: websocket',
                              'api.openai.com', broker.provider_rules('liz'))


def test_real_tls_hosted_tool_request_never_opens_upstream(relay, monkeypatch):
    calls = []
    monkeypatch.setattr(broker, '_connect_public', lambda host: calls.append(host))
    body = json.dumps({'tools': [{'type': 'mcp', 'server_url': 'https://example.com'}]}).encode()
    header = b'POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: ' + str(len(body)).encode()
    client, thread, _ = connect_client(relay)
    try:
        client.sendall(header + b'\r\n\r\n' + body)
        assert client.recv(4096).startswith(b'HTTP/1.1 403 ')
    finally:
        client.close()
        thread.join(2)
    assert not calls

