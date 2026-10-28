"""Provider-only HTTPS broker with verified upstream origin and operation scopes.

The private per-job CA key never enters a worker. Only its public certificate
bundle is mounted there. Clients keep their canonical HTTPS URLs and accounts.
Unlike an opaque CONNECT tunnel, this broker checks decrypted HTTP authority,
method and path, then sends the request to a separately verified fixed origin.
"""
from __future__ import annotations

import contextlib
import json
import re
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from agentporter.agents.development_egress import (
    PublicEgress, _connect_public, _read_connect, HEADER_TIMEOUT, IDLE_TIMEOUT,
)

# Deliberately deny unlisted operations, including repository APIs and device
# registration. An observed missing operation requires explicit review.
OPENAI_API = frozenset({('POST', '/v1/responses'), ('POST', '/v1/chat/completions'),
                       ('GET', '/v1/models')})
CODEX_API = frozenset({('POST', '/backend-api/codex/responses'),
                      ('GET', '/backend-api/codex/models'),
                      # Native Codex resolves its selected account's workspace
                      # origin before opening either model transport.
                      ('GET', '/backend-api/wham/accounts/check')})
COPILOT_API = frozenset({('POST', '/chat/completions'), ('POST', '/responses'),
                        ('GET', '/models')})
GOOGLE_API = frozenset((method, '/v1internal:' + operation)
    for method, operation in [('POST', 'loadCodeAssist'),
        ('POST', 'fetchAvailableModels'), ('POST', 'streamGenerateContent'),
        ('POST', 'generateContent'), ('POST', 'countTokens')])
GOOGLE_BOOTSTRAP = frozenset(('POST', '/v1internal:' + operation) for operation in (
    'fetchAdminControls', 'fetchUserInfo', 'retrieveUserQuotaSummary', 'listExperiments'))
RULES = {
    'jax': {},  # Existing fixed Headroom bridge is the only model route.
    'liz': {'chatgpt.com': CODEX_API, 'api.openai.com': OPENAI_API,
            'auth.openai.com': frozenset({('POST', '/oauth/token')})},
    'ming': {'api.anthropic.com': frozenset({('POST', '/v1/messages'),
            ('POST', '/v1/messages/count_tokens')}),
             'platform.claude.com': frozenset({('POST', '/v1/oauth/token')})},
    'wei': {'opencode.ai': frozenset({
        # Installed OpenCode v2.1.1 native free route, observed fail-closed.
        ('POST', '/inference/openai/v1/chat/completions')})},
    'argie': {'cloudcode-pa.googleapis.com': GOOGLE_API,
              'daily-cloudcode-pa.googleapis.com': GOOGLE_API | GOOGLE_BOOTSTRAP,
              'www.googleapis.com': frozenset({('GET', '/oauth2/v2/userinfo')}),
              'oauth2.googleapis.com': frozenset({('POST', '/token')}),
              'lh3.googleusercontent.com': frozenset()},
    'phil': {host: COPILOT_API for host in ('api.githubcopilot.com',
        'api.individual.githubcopilot.com', 'api.business.githubcopilot.com',
        'api.enterprise.githubcopilot.com')},
}
RULES['prof'] = RULES['liz']
# Native Copilot validates the selected account before opening model APIs.
# Admit that read only; repository APIs, login and token issuance remain denied.
RULES['phil']['api.github.com'] = frozenset({('GET', '/copilot_internal/user')})
MAX_HEADER = 32768
MAX_BODY = 16 * 1024 * 1024
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def provider_rules(agent: str, parallel_search: bool = False) -> dict:
    rules = dict(RULES[agent])
    if parallel_search:
        rules['search.parallel.ai'] = frozenset({('POST', '/mcp'),
                                                ('GET', '/mcp'), ('DELETE', '/mcp')})
    return rules


def operation_allowed(rules: dict, host: str, method: str, target: str) -> bool:
    if host not in rules or not target.startswith('/') or target.startswith('//'):
        return False
    # The observed bootstrap has no query parameters; reject alternate forms.
    if host == 'api.github.com':
        return (method, target) in rules[host] and target == '/copilot_internal/user'
    parsed = urlsplit(target)
    path = parsed.path
    if (parsed.scheme or parsed.netloc or parsed.fragment or '%' in path or
            '\\' in path or any(part in ('.', '..') for part in path.split('/'))):
        return False
    if (method, path) in rules[host]:
        return True
    # Account-bootstrap profile image; GET only, one constrained origin/path.
    return (host == 'lh3.googleusercontent.com' and method == 'GET' and
            re.fullmatch(r'/a/[A-Za-z0-9_=-]+', path) is not None)


def read_header(connection: socket.socket, timeout=HEADER_TIMEOUT) -> tuple[bytes, bytes]:
    data = bytearray()
    deadline = time.monotonic() + timeout
    while b'\r\n\r\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(data) >= MAX_HEADER:
            raise ValueError('HTTP header bound exceeded')
        connection.settimeout(remaining)
        block = connection.recv(min(4096, MAX_HEADER - len(data)))
        if not block:
            raise ValueError('Incomplete HTTP header')
        data.extend(block)
    header, remainder = bytes(data).split(b'\r\n\r\n', 1)
    return header, remainder


def request_header(header: bytes, host: str, rules: dict) -> tuple[bytes, int]:
    """Reject ambiguous framing/authority; construct a single canonical request."""
    lines = header.split(b'\r\n')
    match = re.fullmatch(rb'(GET|POST|DELETE) ([\x21-\x7e]+) HTTP/1\.1', lines[0])
    if match is None:
        raise ValueError('Unsupported HTTP request')
    method, target = (part.decode('ascii') for part in match.groups())
    if not operation_allowed(rules, host, method, target):
        raise PermissionError('Operation is not admitted')
    values = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b':')
        if not sep or not TOKEN.fullmatch(name) or any(c < 32 or c == 127 for c in value):
            raise ValueError('Invalid HTTP header')
        name = name.lower()
        if name in values:
            raise ValueError('Duplicate HTTP header')
        values[name] = value.strip()
    authority = values.get(b'host', b'').decode('ascii').lower()
    if authority not in (host, host + ':443'):
        raise PermissionError('HTTP authority differs from admitted origin')
    if b'transfer-encoding' in values or b'expect' in values:
        raise ValueError('Ambiguous or unsupported body framing')
    if b'content-encoding' in values and values[b'content-encoding'].lower() != b'identity':
        raise PermissionError('Encoded request bodies are not admitted')
    length = values.get(b'content-length', b'0')
    if not re.fullmatch(rb'0|[1-9][0-9]{0,8}', length) or int(length) > MAX_BODY:
        raise ValueError('Invalid HTTP body length')
    size = int(length)
    if method != 'POST' and size:
        raise ValueError('Unexpected HTTP body')
    # Opaque upgraded frames could introduce provider-hosted remote tools after
    # admission. Require inspectable HTTP requests rather than forwarding them.
    if b'upgrade' in values:
        raise PermissionError('Opaque protocol upgrades are not admitted')
    # Never forward hop-by-hop or origin/method rewrite instructions.
    connection_tokens = {v.strip().lower() for v in values.get(b'connection', b'').split(b',')}
    removed = {b'host', b'connection', b'proxy-authorization', b'proxy-connection',
               b'te', b'trailer', b'upgrade', b'forwarded', b'x-http-method-override',
               b'x-method-override', b'x-original-url', b'x-rewrite-url'} | connection_tokens
    if connection_tokens & {b'host', b'content-length', b'authorization'}:
        raise ValueError('Connection header removes critical metadata')
    outgoing = [lines[0], b'Host: ' + host.encode(), b'Connection: close']
    for name, value in values.items():
        if name not in removed and not name.startswith((b'x-forwarded-', b'x-original-')):
            outgoing.append(name + b': ' + value)
    return b'\r\n'.join(outgoing) + b'\r\n\r\n', size


def validate_payload(header: bytes, body: bytes, host: str) -> None:
    """Admit local function schemas, never provider-hosted networking/tools.

    Body bytes are inspected transiently and are never logged or persisted.
    Disallow references to opaque prior server state that could retain hosted
    tools from an uninspected request. Model responses remain normal data.
    """
    method, target, _ = header.split(b'\r\n', 1)[0].split(b' ')
    if method != b'POST':
        return
    # The Headroom bridge uses this validator too. Its upstream must interpret
    # exactly the JSON bytes we inspect, without another decoding step.
    for line in header.split(b'\r\n')[1:]:
        name, _, value = line.partition(b':')
        if name.lower() == b'content-encoding' and value.strip().lower() != b'identity':
            raise PermissionError('Encoded request bodies are not admitted')
    path = urlsplit(target.decode('ascii')).path
    if path in ('/oauth/token', '/v1/oauth/token', '/token'):
        return  # Existing OAuth refresh operation; no model/remote tool API.
    member_count = 0
    def unique(pairs):
        nonlocal member_count
        member_count += len(pairs)
        if member_count > 100000:
            raise ValueError('JSON structure bound exceeded')
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('Duplicate JSON member')
            result[name] = value
        return result
    try:
        data = json.loads(body, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('Invalid bounded JSON request') from error
    if not isinstance(data, dict):
        raise ValueError('Request must be a JSON object')
    if host == 'opencode.ai':
        from agentporter.agents.adapters.opencode import WeiAdapter
        free = {name.partition('/')[2] for name in WeiAdapter.free_models}
        if data.get('model') not in free:
            raise PermissionError('Wei admits only reviewed free models')
    if host == 'search.parallel.ai':
        method = data.get('method')
        if data.get('jsonrpc') != '2.0' or not isinstance(method, str) or method not in {
                'initialize', 'notifications/initialized', 'notifications/cancelled',
                'ping', 'tools/list', 'tools/call'}:
            raise PermissionError('Unadmitted Parallel MCP operation')
        if method == 'tools/call':
            from agentporter.agents.parallel_search import PARALLEL_MCP_TOOLS
            params = data.get('params')
            if not isinstance(params, dict) or params.get('name') not in PARALLEL_MCP_TOOLS:
                raise PermissionError('Unadmitted Parallel MCP tool')
        return
    for envelope in (data, data.get('request', {})):
        if not isinstance(envelope, dict):
            raise ValueError('Invalid model envelope')
        for field in ('mcp_servers', 'mcpServers', 'web_search_options', 'webSearchOptions',
                      'previous_response_id', 'previousResponseId',
                      'conversation', 'prompt', 'cachedContent', 'cached_content'):
            if field in envelope:
                raise PermissionError('Opaque state or hosted capability is not admitted')
        choice = envelope.get('tool_choice')
        if choice is not None:
            if isinstance(choice, dict):
                kind = choice.get('type')
                if not isinstance(kind, str) or kind not in {'function', 'custom', 'tool', 'auto', 'any', 'none'}:
                    raise PermissionError('Hosted tool choice is not admitted')
            elif not isinstance(choice, str) or choice not in {'auto', 'required', 'none', 'any'}:
                raise PermissionError('Invalid tool choice')
        tools = envelope.get('tools', [])
        if not isinstance(tools, list):
            raise ValueError('Invalid tool declarations')
        google = host.endswith('cloudcode-pa.googleapis.com')
        anthropic = host == 'api.anthropic.com'
        def check_tools(items, depth=0):
            if depth > 8 or not isinstance(items, list):
                raise ValueError('Invalid tool namespace')
            for tool in items:
                if not isinstance(tool, dict):
                    raise ValueError('Invalid tool definition')
                kind = tool.get('type')
                if any(field in tool for field in ('server_url', 'connector_id', 'authorization', 'require_approval')):
                    raise PermissionError('Remote connector metadata is not admitted')
                if google:
                    if set(tool) - {'functionDeclarations'} or not isinstance(tool.get('functionDeclarations'), list):
                        raise PermissionError('Hosted Google tool is not admitted')
                elif anthropic:
                    if kind not in (None, 'custom') or not isinstance(tool.get('name'), str):
                        raise PermissionError('Hosted Anthropic tool is not admitted')
                elif kind == 'namespace':
                    check_tools(tool.get('tools'), depth + 1)
                elif kind not in ('function', 'custom'):
                    raise PermissionError('Hosted provider tool is not admitted')
        check_tools(tools)
        inputs = envelope.get('input', [])
        if isinstance(inputs, list) and any(isinstance(item, dict) and
                str(item.get('type', '')).startswith('mcp_') for item in inputs):
            raise PermissionError('Hosted MCP continuation is not admitted')


class ProviderEgress(PublicEgress):
    """Exact-origin, operation-scoped TLS relay, never an opaque CONNECT tunnel."""

    def __init__(self, socket_path: Path, *, agent: str, parallel_search: bool = False):
        super().__init__(socket_path)
        self.rules = provider_rules(agent, parallel_search)
        self._tls_directory = Path(socket_path).parent / 'provider-tls'
        self._tls_directory.mkdir(mode=0o700)
        key = self._tls_directory / 'key.pem'
        certificate = self._tls_directory / 'ca.pem'
        # Even Jax may use the separately opted-in Parallel service. An empty
        # ruleset still has no admitted HTTP operations or CONNECT authorities.
        hosts = sorted(self.rules) or ['unused.invalid']
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-nodes', '-days', '1', '-subj', '/CN=AgentPorter per-job provider broker',
            '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectAltName=' + ','.join('DNS:' + h for h in hosts),
            '-keyout', str(key), '-out', str(certificate)], check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        key.chmod(0o600)
        # Rust/webpki clients correctly reject a CA certificate used as a TLS
        # server leaf. Issue a distinct CA:FALSE/serverAuth leaf for this job.
        leaf_key = self._tls_directory / 'leaf-key.pem'
        leaf_request = self._tls_directory / 'leaf.csr'
        leaf_certificate = self._tls_directory / 'leaf.pem'
        extensions = self._tls_directory / 'leaf.extensions'
        extensions.write_text('basicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth\nsubjectAltName='
            + ','.join('DNS:' + host for host in hosts) + '\n')
        subprocess.run(['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=AgentPorter per-job provider endpoint', '-keyout', str(leaf_key),
            '-out', str(leaf_request)], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        leaf_key.chmod(0o600)
        subprocess.run(['/usr/bin/openssl', 'x509', '-req', '-in', str(leaf_request),
            '-CA', str(certificate), '-CAkey', str(key), '-CAcreateserial', '-days', '1',
            '-extfile', str(extensions), '-out', str(leaf_certificate)], check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        self.ca_bundle = self._tls_directory / 'public-ca-bundle.pem'
        self.ca_bundle.write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
                                   + b'\n' + certificate.read_bytes())
        self.ca_bundle.chmod(0o444)
        self._contexts = {}
        for host in self.rules:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1'])
            context.load_cert_chain(leaf_certificate, leaf_key)
            def check_sni(connection, server_name, _context, expected=host):
                if server_name != expected:
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            context.set_servername_callback(check_sni)
            self._contexts[host] = context
        key.unlink()
        leaf_key.unlink()
        self._upstream_context = ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt')
        self._upstream_context.set_alpn_protocols(['http/1.1'])

    def _handle(self, client: socket.socket) -> None:
        downstream = upstream = None
        response_started = False
        try:
            host, remainder = _read_connect(client)
            host = host.lower()
            if host not in self.rules or remainder:
                raise PermissionError('Unadmitted CONNECT authority or early payload')
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            downstream = self._contexts[host].wrap_socket(client, server_side=True)
            with self._lock:
                self._connections.add(downstream)
            header, initial_body = read_header(downstream)
            outgoing, length = request_header(header, host, self.rules)
            if len(initial_body) > length:
                raise ValueError('Pipelined request or excessive body')
            body = bytearray(initial_body)
            downstream.settimeout(IDLE_TIMEOUT)
            while len(body) < length:
                block = downstream.recv(min(65536, length - len(body)))
                if not block:
                    raise ValueError('Truncated request body')
                body.extend(block)
            validate_payload(header, body, host)
            # No upstream connection exists until authority and operation pass.
            raw = _connect_public(host)
            try:
                upstream = self._upstream_context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                raw.close()
                raise
            with self._lock:
                self._connections.add(upstream)
            upstream.settimeout(IDLE_TIMEOUT)
            downstream.settimeout(IDLE_TIMEOUT)
            upstream.sendall(outgoing + body)
            response_header, response_body = read_header(upstream, timeout=IDLE_TIMEOUT)
            if response_header.startswith(b'HTTP/1.1 101 '):
                raise ValueError('Unexpected protocol upgrade')
            downstream.sendall(response_header + b'\r\n\r\n' + response_body)
            response_started = True
            while not self._stop.is_set():
                block = upstream.recv(65536)
                if not block:
                    break
                downstream.sendall(block)
        except (OSError, ValueError, PermissionError, ssl.SSLError):
            if not response_started:
                with contextlib.suppress(OSError):
                    (downstream or client).sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        finally:
            for connection in (upstream, downstream, client):
                if connection is not None:
                    if isinstance(connection, ssl.SSLSocket):
                        with contextlib.suppress(OSError):
                            connection.settimeout(1)
                            connection.unwrap().close()
                    with contextlib.suppress(OSError):
                        connection.close()
            with self._lock:
                self._connections.discard(client)
                self._connections.discard(downstream)
                self._connections.discard(upstream)
                self._threads.discard(threading.current_thread())
            self._slots.release()


