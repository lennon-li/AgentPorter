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



def _diagnostic_for_upstream(relay, monkeypatch, caplog, behavior):
    relay._upstream_context = ssl.create_default_context(cafile=str(relay.ca_bundle))
    servers = []
    def connect(host):
        client, server = socket.socketpair()
        def serve():
            try:
                with relay._contexts[host].wrap_socket(server, server_side=True) as connection:
                    broker.read_header(connection)
                    behavior(connection)
            except OSError:
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        servers.append(thread)
        return client
    monkeypatch.setattr(broker, '_connect_public', connect)
    caplog.set_level('WARNING', logger='agentporter.agents.provider_egress')
    client, thread, _ = connect_client(relay)
    try:
        client.sendall(request() + b'\r\n\r\n{}')
        assert client.recv(4096).startswith(b'HTTP/1.1 403 ')
    finally:
        client.close()
        thread.join(2)
        for server_thread in servers:
            server_thread.join(2)
    events = [json.loads(r.getMessage().split(' ', 1)[1]) for r in caplog.records]
    assert len(events) == 1
    return events[0]


def test_upstream_close_before_header_is_classified_without_status(relay, monkeypatch, caplog):
    event = _diagnostic_for_upstream(relay, monkeypatch, caplog, lambda connection: None)
    assert event['stage'] == 'upstream_response' and event['upstream_status'] is None
    # TLS shutdown without a response can surface as EOF, reset, or a broken
    # pipe while OpenSSL finishes its protocol exchange, depending on the host.
    assert event['reason'] in {'eof_before_header', 'tls_eof', 'reset', 'broken_pipe'}


def test_oversized_upstream_header_is_classified_without_leaking(relay, monkeypatch, caplog):
    def behavior(connection):
        connection.sendall(b'HTTP/1.1 200 OK\r\nX-Secret-Marker: ' + b'a' * broker.MAX_HEADER)
    event = _diagnostic_for_upstream(relay, monkeypatch, caplog, behavior)
    assert event['stage'] == 'upstream_response' and event['reason'] == 'header_size'
    assert 'Secret' not in json.dumps(event)


ARGIE_HOST = 'cloudcode-pa.googleapis.com'
ARGIE_PATH = b'/v1internal:streamGenerateContent'
ARGIE_SSE_PATH = ARGIE_PATH + b'?alt=sse'
ARGIE_BODY = json.dumps({'request': {'contents': [{'role': 'user', 'parts': [{'text': 'hi'}]}]}}).encode()


def chunked(body, size=7):
    parts = [b'%x\r\n' % len(body[i:i + size]) + body[i:i + size] + b'\r\n'
             for i in range(0, len(body), size)]
    return b''.join(parts) + b'0\r\n\r\n'


def argie_head(extra=b'', path=ARGIE_PATH, te=b'Transfer-Encoding: chunked'):
    return (b'POST ' + path + b' HTTP/1.1\r\nHost: ' + ARGIE_HOST.encode() + b'\r\n' + te + extra
            + b'\r\n\r\n')


@pytest.fixture
def argie_relay(tmp_path):
    tmp_path.chmod(0o700)
    proxy = broker.ProviderEgress(tmp_path / 'relay.sock', agent='argie')
    yield proxy
    proxy.close()


def run_argie(relay, monkeypatch, payload, host=None):
    seen = []
    servers = []
    relay._upstream_context = ssl.create_default_context(cafile=str(relay.ca_bundle))

    def connect(host):
        seen.append(host)
        client, server = socket.socketpair()

        def serve():
            try:
                with relay._contexts[host].wrap_socket(server, server_side=True) as connection:
                    header, body = broker.read_header(connection)
                    length = int(header.lower().split(b'content-length: ')[1].split(b'\r\n')[0])
                    while len(body) < length:
                        body += connection.recv(length - len(body))
                    seen.append((header, body))
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
            except OSError:
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        servers.append(thread)
        return client
    monkeypatch.setattr(broker, '_connect_public', connect)
    client, thread, _ = connect_client(relay, host or ARGIE_HOST)
    data = bytearray()
    try:
        client.sendall(payload)
        with pytest.MonkeyPatch.context():
            while True:
                try:
                    block = client.recv(4096)
                except OSError:
                    break
                if not block:
                    break
                data.extend(block)
    finally:
        client.close()
        thread.join(2)
        for server_thread in servers:
            server_thread.join(2)
    return bytes(data), seen


def test_real_tls_argie_chunked_request_is_normalized(argie_relay, monkeypatch):
    data, seen = run_argie(argie_relay, monkeypatch, argie_head() + chunked(ARGIE_BODY))
    assert data.startswith(b'HTTP/1.1 200 ')
    header, body = seen[1]
    assert body == ARGIE_BODY
    lowered = header.lower()
    assert lowered.count(b'content-length:') == 1
    assert b'Content-Length: ' + str(len(ARGIE_BODY)).encode() in header
    for name in (b'transfer-encoding', b'trailer', b'expect'):
        assert name not in lowered


def test_real_tls_argie_chunked_sse_query_is_normalized_with_same_target(argie_relay, monkeypatch):
    data, seen = run_argie(argie_relay, monkeypatch, argie_head(path=ARGIE_SSE_PATH) + chunked(ARGIE_BODY))
    assert data.startswith(b'HTTP/1.1 200 ')
    header, body = seen[1]
    assert body == ARGIE_BODY
    assert header.startswith(b'POST ' + ARGIE_SSE_PATH + b' HTTP/1.1\r\n')
    lowered = header.lower()
    assert lowered.count(b'content-length:') == 1
    for name in (b'transfer-encoding', b'trailer', b'expect'):
        assert name not in lowered


@pytest.mark.parametrize('query', [
    b'?', b'?alt=json', b'?alt=sse&alt=sse', b'?alt=sse&x=1', b'?x=1&alt=sse', b'?alt=SSE',
    b'?alt=%73se', b'?%61lt=sse', b'?alt=sse%26x=1', b'?alt=sse#f', b'?alt=sse&', b'?alt=',
    b'?alt=sse;x=1', b'?alt=sse%20'])
def test_real_tls_argie_chunked_query_variants_denied(argie_relay, monkeypatch, query):
    path = ARGIE_PATH + query
    with pytest.raises((ValueError, PermissionError)):
        broker.request_header(argie_head(path=path).split(b'\r\n\r\n')[0], ARGIE_HOST,
                              broker.provider_rules('argie'), chunked_ok=True)
    data, seen = run_argie(argie_relay, monkeypatch, argie_head(path=path) + chunked(ARGIE_BODY))
    assert not data.startswith(b'HTTP/1.1 200 ') and not seen


@pytest.mark.parametrize('path', [b'/v1internal:countTokens?alt=sse', b'/v1internal:generateContent?alt=sse',
                                  b'/v1internal:streamGenerateContent/?alt=sse'])
def test_argie_chunked_sse_query_other_operations_denied(path):
    with pytest.raises((ValueError, PermissionError)):
        broker.request_header(argie_head(path=path).split(b'\r\n\r\n')[0], ARGIE_HOST,
                              broker.provider_rules('argie'), chunked_ok=True)


def test_argie_sse_query_cl_and_default_denied():
    head = argie_head(b'\r\nContent-Length: 2', path=ARGIE_SSE_PATH).split(b'\r\n\r\n')[0]
    with pytest.raises(ValueError):
        broker.request_header(head, ARGIE_HOST, broker.provider_rules('argie'), chunked_ok=True)
    outgoing, size = broker.request_header(
        argie_head(b'\r\nTE: chunked', path=ARGIE_SSE_PATH).split(b'\r\n\r\n')[0], ARGIE_HOST,
        broker.provider_rules('argie'), chunked_ok=True)
    assert size is None and b'\r\nTE:' not in outgoing
    with pytest.raises(ValueError):
        broker.request_header(argie_head(path=ARGIE_SSE_PATH).split(b'\r\n\r\n')[0], ARGIE_HOST,
                              broker.provider_rules('argie'))


def test_real_tls_argie_chunked_hosted_tool_never_opens_upstream(argie_relay, monkeypatch):
    body = json.dumps({'request': {'tools': [{'googleSearch': {}}]}}).encode()
    data, seen = run_argie(argie_relay, monkeypatch, argie_head() + chunked(body))
    assert data.startswith(b'HTTP/1.1 403 ') and not seen


@pytest.mark.parametrize('wire', [
    b'2\r\n{}\r\n0\r\nX: y\r\n\r\n', b'2\r\n{}\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n',
    b'2;ext=1\r\n{}\r\n0\r\n\r\n', b'g\r\n{}\r\n0\r\n\r\n', b'\r\n{}\r\n0\r\n\r\n',
    b'2\n{}\r\n0\r\n\r\n', b'2\r\n{}\n0\r\n\r\n', b'02\r\n{}\r\n0\r\n\r\n',
    b'2\r\n{}XX0\r\n\r\n', b'2\r\n{}\r\n0\r\n', b'2\r\n{', b'FFFFFFFFF\r\n',
    b'7fffffff\r\n', b'2\r\n{}\r\n0\n\n', b'0\r\n\r\n'])
def test_real_tls_argie_malformed_chunked_denied(argie_relay, monkeypatch, wire):
    data, seen = run_argie(argie_relay, monkeypatch, argie_head() + wire)
    assert not data.startswith(b'HTTP/1.1 200 ') and not seen


@pytest.mark.parametrize('head', [
    argie_head(b'\r\nContent-Length: 2'), argie_head(b'\r\nTransfer-Encoding: chunked'),
    argie_head(b'\r\nExpect: 100-continue'), argie_head(b'\r\nTrailer: X'),
    argie_head(te=b'Transfer-Encoding: gzip, chunked'), argie_head(te=b'Transfer-Encoding: Chunked'),
    argie_head(te=b'Transfer-Encoding: chunked, chunked'),
    argie_head(path=b'/v1internal:countTokens'), argie_head(path=b'/v1internal:streamGenerateContent?x=1'),
    argie_head(path=b'/v1internal:generateContent')])
def test_argie_chunked_header_variants_rejected(head):
    with pytest.raises((ValueError, PermissionError)):
        broker.request_header(head.split(b'\r\n\r\n')[0], ARGIE_HOST, broker.provider_rules('argie'),
                              chunked_ok=True)


def test_chunked_is_default_denied_and_scoped():
    head = argie_head().split(b'\r\n\r\n')[0]
    with pytest.raises(ValueError):
        broker.request_header(head, ARGIE_HOST, broker.provider_rules('argie'))
    liz = (b'POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked')
    with pytest.raises(ValueError):
        broker.request_header(liz, 'api.openai.com', broker.provider_rules('liz'), chunked_ok=True)
    with pytest.raises(PermissionError):
        broker.request_header(head, 'oauth2.googleapis.com',
                              broker.provider_rules('argie'), chunked_ok=True)


def test_chunk_count_and_size_bounds(monkeypatch):
    left, right = socket.socketpair()
    with left, right:
        monkeypatch.setattr(broker, 'MAX_CHUNKS', 2)
        right.sendall(b'1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n')
        with pytest.raises(ValueError, match='too large'):
            broker.read_chunked_body(left, b'')
    left, right = socket.socketpair()
    with left, right:
        monkeypatch.setattr(broker, 'MAX_BODY', 3)
        with pytest.raises(ValueError, match='too large'):
            broker.read_chunked_body(left, b'4\r\nabcd\r\n0\r\n\r\n')


def test_chunked_body_deadline_applies_to_whole_body():
    left, right = socket.socketpair()
    with left, right:
        with pytest.raises(TimeoutError):
            broker.read_chunked_body(left, b'1\r\na', timeout=0.2)


CLAUDE_HOST = 'api.business.githubcopilot.com'


@pytest.fixture
def phil_relay(tmp_path):
    tmp_path.chmod(0o700)
    proxy = broker.ProviderEgress(tmp_path / 'relay.sock', agent='phil')
    yield proxy
    proxy.close()


def claude_wire(data, target='/v1/messages', host=CLAUDE_HOST, method='POST', extra=b''):
    body = json.dumps(data).encode()
    return (method + ' ' + target + ' HTTP/1.1\r\nHost: ' + host + '\r\nContent-Length: '
            + str(len(body))).encode() + extra + b'\r\n\r\n' + body


def test_phil_claude_route_admits_only_exact_business_post():
    rules = broker.provider_rules('phil')
    assert broker.operation_allowed(rules, CLAUDE_HOST, 'POST', '/v1/messages')
    for host in ('api.githubcopilot.com', 'api.individual.githubcopilot.com',
                 'api.enterprise.githubcopilot.com', 'api.github.com'):
        assert not broker.operation_allowed(rules, host, 'POST', '/v1/messages')
    for method, target in [('GET', '/v1/messages'), ('POST', '/v1/messages?beta=true'),
            ('POST', '/v1/messages?'), ('POST', '/v1/messages/count_tokens'), ('POST', '/v1/messages/'),
            ('POST', '/v1/%6dessages'), ('POST', '/v1/messages#x'), ('POST', '/v1/../v1/messages')]:
        assert not broker.operation_allowed(rules, CLAUDE_HOST, method, target)
    assert not broker.operation_allowed(rules, 'api.github.com', 'GET', '/copilot_internal/v2/token')
    assert not broker.operation_allowed(rules, 'api.github.com', 'GET', '/user')
    assert not broker.operation_allowed(broker.provider_rules('liz'), CLAUDE_HOST, 'POST', '/v1/messages')
    assert broker.operation_allowed(rules, CLAUDE_HOST, 'POST', '/chat/completions')
    assert broker.operation_allowed(rules, CLAUDE_HOST, 'GET', '/models')


def test_phil_claude_chunked_remains_forbidden():
    header = (b'POST /v1/messages HTTP/1.1\r\nHost: ' + CLAUDE_HOST.encode()
              + b'\r\nTransfer-Encoding: chunked')
    for chunked_ok in (True, False):
        with pytest.raises(ValueError):
            broker.request_header(header, CLAUDE_HOST, broker.provider_rules('phil'), chunked_ok)


def test_claude_payload_validation_scope():
    model_body({'model': 'claude', 'tools': [{'name': 'Read', 'input_schema': {}},
                {'type': 'custom', 'name': 'x', 'input_schema': {}}]}, CLAUDE_HOST, '/v1/messages')
    for bad in ({'type': 'web_search_20250305', 'name': 'web_search'},
                {'type': 'computer_20250124', 'name': 'computer'},
                {'type': 'bash_20250124', 'name': 'bash'},
                {'type': 'mcp', 'name': 'x', 'server_url': 'https://example.com'},
                {'name': 'x', 'connector_id': 'c'}):
        with pytest.raises(PermissionError):
            model_body({'tools': [bad]}, CLAUDE_HOST, '/v1/messages')
    for field in ('mcp_servers', 'previous_response_id', 'conversation'):
        with pytest.raises(PermissionError):
            model_body({field: 'x'}, CLAUDE_HOST, '/v1/messages')
    # Copilot chat keeps the generic validator; Ming's Anthropic route is unchanged.
    model_body({'tools': [{'type': 'function', 'name': 'x'}]}, CLAUDE_HOST, '/chat/completions')
    with pytest.raises(PermissionError):
        model_body({'tools': [{'name': 'Read', 'input_schema': {}}]}, CLAUDE_HOST, '/chat/completions')
    with pytest.raises(PermissionError):
        model_body({'tools': [{'name': 'Read', 'input_schema': {}}]}, 'api.githubcopilot.com', '/v1/messages')
    model_body({'tools': [{'name': 'Read', 'input_schema': {}}]}, 'api.anthropic.com', '/v1/messages')
    with pytest.raises(PermissionError):
        model_body({'tools': [{'type': 'web_search_20250305', 'name': 'w'}]}, 'api.anthropic.com', '/v1/messages')


def test_real_tls_claude_messages_forwarded_after_validation(phil_relay, monkeypatch):
    payload = {'model': 'claude', 'messages': [{'role': 'user', 'content': 'hi'}],
               'tools': [{'name': 'Read', 'input_schema': {'type': 'object'}}]}
    data, seen = run_argie(phil_relay, monkeypatch, claude_wire(payload), CLAUDE_HOST)
    assert data.startswith(b'HTTP/1.1 200 ')
    assert seen[0] == CLAUDE_HOST
    assert seen[1][0].startswith(b'POST /v1/messages HTTP/1.1\r\n')
    assert json.loads(seen[1][1]) == payload


def test_real_tls_claude_chat_unchanged(phil_relay, monkeypatch):
    data, seen = run_argie(phil_relay, monkeypatch,
                           claude_wire({'model': 'm', 'messages': []}, '/chat/completions'), CLAUDE_HOST)
    assert data.startswith(b'HTTP/1.1 200 ') and seen[1][0].startswith(b'POST /chat/completions ')


@pytest.mark.parametrize('wire', [
    claude_wire({'tools': [{'type': 'web_search_20250305', 'name': 'w'}]}),
    claude_wire({'tools': [{'type': 'mcp', 'name': 'x', 'server_url': 'https://e.com'}]}),
    claude_wire({'mcp_servers': []}),
    claude_wire({}, '/v1/messages?beta=true'),
    claude_wire({}, '/v1/messages', method='GET'),
    claude_wire({}, '/v1/messages', host='api.githubcopilot.com'),
    claude_wire({}, '/v1/%6dessages'),
    claude_wire({}, extra=b'\r\nTransfer-Encoding: chunked'),
    claude_wire({}, '/v1/messages/count_tokens')])
def test_real_tls_claude_rejected_before_upstream(phil_relay, monkeypatch, wire):
    data, seen = run_argie(phil_relay, monkeypatch, wire, CLAUDE_HOST)
    assert not data.startswith(b'HTTP/1.1 200 ')
    assert not [item for item in seen if isinstance(item, tuple)]
