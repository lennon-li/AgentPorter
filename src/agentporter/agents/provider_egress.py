"""Provider-only HTTPS broker with verified upstream origin and operation scopes.

The private per-job CA key never enters a worker. Only its public certificate
bundle is mounted there. Clients keep their canonical HTTPS URLs and accounts.
Unlike an opaque CONNECT tunnel, this broker checks decrypted HTTP authority,
method and path, then sends the request to a separately verified fixed origin.
"""
from __future__ import annotations

import contextlib
import json
import logging
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
# Native Copilot Claude models use the Anthropic Messages route on this one origin only.
COPILOT_CLAUDE_HOST = 'api.business.githubcopilot.com'
RULES['phil'][COPILOT_CLAUDE_HOST] = COPILOT_API | {('POST', '/v1/messages')}
MAX_HEADER = 32768
MAX_BODY = 16 * 1024 * 1024
# Observed Argie model streaming sends Transfer-Encoding: chunked. Only these
# exact request targets (plain and the observed alt=sse query) may be normalized;
# every other route or query form keeps rejecting it.
CHUNKED_OPERATIONS = frozenset((host, 'POST', target)
    for target in ('/v1internal:streamGenerateContent', '/v1internal:streamGenerateContent?alt=sse')
    for host in ('cloudcode-pa.googleapis.com', 'daily-cloudcode-pa.googleapis.com'))
MAX_CHUNKS = 16384
MAX_CHUNKED_WIRE = MAX_BODY + MAX_CHUNKS * 14 + 16
CHUNKED_BODY_TIMEOUT = 120.0
_CHUNK_SIZE_LINE = re.compile(rb'(0|[1-9a-fA-F][0-9a-fA-F]{0,7})\r')
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


_DIAGNOSTIC_LOGGER = logging.getLogger('agentporter.agents.provider_egress')
_DIAGNOSTIC_HOSTS = frozenset(host for rules in RULES.values() for host in rules) | {
    'search.parallel.ai',
    # Recognized native public origins for diagnosis only; not egress admission.
    'daily-cloudcode-pa.sandbox.googleapis.com',
    'autopush-cloudcode-pa.sandbox.googleapis.com',
}
_DIAGNOSTIC_STAGES = frozenset({'connect', 'downstream_tls', 'request_header', 'request_body',
    'payload', 'upstream_connect', 'upstream_tls', 'upstream_request', 'upstream_response',
    'downstream_response', 'response_stream', 'upstream_status'})
_DIAGNOSTIC_OPERATIONS = {
    '/v1/responses':'responses', '/backend-api/codex/responses':'codex_responses',
    '/responses':'responses', '/chat/completions':'chat_completions',
    '/v1/chat/completions':'chat_completions', '/v1/messages':'claude_messages',
    '/v1/messages/count_tokens':'claude_count_tokens', '/v1/oauth/token':'oauth_refresh',
    '/oauth/token':'oauth_refresh', '/token':'oauth_refresh',
    '/copilot_internal/user':'copilot_account_read', '/models':'models', '/v1/models':'models',
    '/backend-api/codex/models':'codex_models', '/backend-api/wham/accounts/check':'codex_account_read',
    '/oauth2/v2/userinfo':'google_userinfo', '/inference/openai/v1/chat/completions':'wei_chat',
    '/v1internal:loadCodeAssist':'google_load_code_assist',
    '/v1internal:fetchAvailableModels':'google_models',
    '/v1internal:streamGenerateContent':'google_stream_generate',
    '/v1internal:generateContent':'google_generate', '/v1internal:countTokens':'google_count_tokens',
    '/v1internal:fetchAdminControls':'google_admin_controls',
    '/v1internal:fetchUserInfo':'google_user_info',
    '/v1internal:retrieveUserQuotaSummary':'google_quota_summary',
    '/v1internal:listExperiments':'google_experiments', '/mcp':'parallel_mcp',
    # Recognized native operations for diagnosis only; RULES stay unchanged.
    '/v1internal:getCodeAssistGlobalUserSetting':'google_global_user_setting',
    '/v1internal:listCloudAICompanionProjects':'google_companion_projects',
    '/v1internal:initiateMeshSession':'google_mesh_session',
    '/v1internal:internalAtomicAgenticChat':'google_atomic_agentic_chat',
    '/v1internal:fetchCodeCustomizationState':'google_code_customization',
    '/v1internal:listAuthorizedDevices':'google_authorized_devices',
    '/copilot_internal/v2/token':'copilot_token_exchange',
}


_DIAGNOSTIC_REASONS = frozenset({'timeout', 'tls_eof', 'tls_error', 'reset', 'broken_pipe',
    'not_admitted', 'eof_before_header', 'header_deadline', 'header_size', 'invalid_value',
    'os_error', 'unknown'})


def _diagnostic_reason(exc):
    # Exception class and our own fixed messages only; never exception text.
    if isinstance(exc, PermissionError):
        return 'not_admitted'
    if isinstance(exc, TimeoutError):
        return 'timeout'
    if isinstance(exc, ssl.SSLEOFError):
        return 'tls_eof'
    if isinstance(exc, ssl.SSLError):
        return 'tls_error'
    if isinstance(exc, ConnectionResetError):
        return 'reset'
    if isinstance(exc, BrokenPipeError):
        return 'broken_pipe'
    if isinstance(exc, ValueError):
        return {'Incomplete HTTP header': 'eof_before_header',
                'HTTP header deadline exceeded': 'header_deadline',
                'HTTP header size exceeded': 'header_size'}.get(str(exc), 'invalid_value')
    return 'os_error' if isinstance(exc, OSError) else 'unknown'


def _diagnostic_operation(header):
    # Raw header/path/query bytes are transient and never returned or logged.
    try:
        parts = header.split(b'\r\n', 1)[0].split(b' ')
        if len(parts) != 3:
            return 'unknown', 'unknown'
        method = parts[0].decode('ascii')
        path = parts[1].split(b'?', 1)[0].decode('ascii')
        return (method if method in {'GET', 'POST', 'DELETE'} else 'unknown',
                _DIAGNOSTIC_OPERATIONS.get(path, 'unknown'))
    except (AttributeError, UnicodeError, ValueError):
        return 'unknown', 'unknown'


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
    if host == COPILOT_CLAUDE_HOST and path == '/v1/messages' and target != path:
        return False
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
        if remaining <= 0:
            raise ValueError('HTTP header deadline exceeded')
        if len(data) >= MAX_HEADER:
            raise ValueError('HTTP header size exceeded')
        connection.settimeout(remaining)
        block = connection.recv(min(4096, MAX_HEADER - len(data)))
        if not block:
            raise ValueError('Incomplete HTTP header')
        data.extend(block)
    header, remainder = bytes(data).split(b'\r\n\r\n', 1)
    return header, remainder


def request_header(header: bytes, host: str, rules: dict,
                   chunked_ok: bool = False) -> tuple[bytes, int | None]:
    """Reject ambiguous framing/authority; construct a single canonical request.

    With chunked_ok, an eligible request using exactly one `Transfer-Encoding:
    chunked` returns (header without any length, None); the caller must decode
    the body and finish the header with with_content_length().
    """
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
    chunked = False
    if b'transfer-encoding' in values:
        if (not chunked_ok or method != 'POST' or (host, method, target) not in CHUNKED_OPERATIONS
                or values[b'transfer-encoding'] != b'chunked' or b'content-length' in values
                or b'trailer' in values):
            raise ValueError('Ambiguous or unsupported body framing')
        chunked = True
    if b'expect' in values:
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
               b'te', b'trailer', b'transfer-encoding', b'upgrade', b'forwarded', b'x-http-method-override',
               b'x-method-override', b'x-original-url', b'x-rewrite-url'} | connection_tokens
    if connection_tokens & {b'host', b'content-length', b'authorization',
                             b'transfer-encoding'}:
        raise ValueError('Connection header removes critical metadata')
    outgoing = [lines[0], b'Host: ' + host.encode(), b'Connection: close']
    for name, value in values.items():
        if name not in removed and not name.startswith((b'x-forwarded-', b'x-original-')):
            outgoing.append(name + b': ' + value)
    return b'\r\n'.join(outgoing) + b'\r\n\r\n', (None if chunked else size)


def with_content_length(outgoing: bytes, length: int) -> bytes:
    return outgoing[:-2] + b'Content-Length: ' + str(length).encode() + b'\r\n\r\n'


def read_chunked_body(connection: socket.socket, initial: bytes,
                      timeout: float = CHUNKED_BODY_TIMEOUT) -> bytes:
    """Strictly decode one bounded chunked body: no extensions, trailers or extra bytes."""
    deadline = time.monotonic() + timeout
    buffer = bytearray(initial)
    wire = len(buffer)
    body = bytearray()
    chunks = 0

    def need_more():
        nonlocal wire
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Chunked body deadline exceeded')
        if wire >= MAX_CHUNKED_WIRE:
            raise ValueError('Chunked body too large')
        connection.settimeout(min(remaining, IDLE_TIMEOUT))
        block = connection.recv(min(65536, MAX_CHUNKED_WIRE - wire))
        if not block:
            raise ValueError('Truncated request body')
        wire += len(block)
        buffer.extend(block)

    while True:
        end = buffer.find(b'\n')
        if end < 0:
            if len(buffer) > 9:
                raise ValueError('Invalid chunk size')
            need_more()
            continue
        match = _CHUNK_SIZE_LINE.fullmatch(bytes(buffer[:end]))
        if match is None:
            raise ValueError('Invalid chunk size')
        size = int(match[1], 16)
        rest = end + 1
        if size == 0:
            while len(buffer) < rest + 2:
                if bytes(buffer[rest:]) != b'\r\n'[:len(buffer) - rest]:
                    raise ValueError('Chunk trailers are not admitted')
                need_more()
            if len(buffer) != rest + 2 or buffer[rest:] != b'\r\n':
                raise ValueError('Chunk trailers or extra bytes are not admitted')
            return bytes(body)
        chunks += 1
        if chunks > MAX_CHUNKS or len(body) + size > MAX_BODY:
            raise ValueError('Chunked body too large')
        while len(buffer) < rest + size + 2:
            need_more()
        if buffer[rest + size:rest + size + 2] != b'\r\n':
            raise ValueError('Invalid chunk terminator')
        body.extend(buffer[rest:rest + size])
        del buffer[:rest + size + 2]


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
        anthropic = host == 'api.anthropic.com' or (
            host == COPILOT_CLAUDE_HOST and target == b'/v1/messages')
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

    def __init__(self, socket_path: Path, *, agent: str, parallel_search: bool = False, model_evidence=None):
        super().__init__(socket_path)
        self.rules = provider_rules(agent, parallel_search)
        self._diagnostic_agent = agent if agent in RULES else 'unknown'
        self._diagnostic_count = 0
        self._diagnostic_lock = threading.Lock()
        self._model_evidence = model_evidence
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

    def _diagnostic(self, *, stage, host='unknown', method='unknown', operation='unknown', status=None, reason=None):
        # Only static enums and a bounded integer enter the service journal.
        # Diagnostics are secondary: any failure must leave forwarding unchanged.
        try:
            with self._diagnostic_lock:
                if self._diagnostic_count >= 32:
                    return
                self._diagnostic_count += 1
            safe_stage = stage if stage in _DIAGNOSTIC_STAGES else 'unknown'
            event = {
                'event':'provider_egress_diagnostic',
                'agent':self._diagnostic_agent if self._diagnostic_agent in RULES else 'unknown',
                'host':host if host in _DIAGNOSTIC_HOSTS else 'unknown',
                'method':method if method in {'GET','POST','DELETE'} else 'unknown',
                'operation':operation if operation in _DIAGNOSTIC_OPERATIONS.values() else 'unknown',
                'stage':safe_stage,
                'error_code':'upstream_non_2xx' if safe_stage == 'upstream_status' else 'local_rejection_or_transport_failure',
                'reason':reason if reason in _DIAGNOSTIC_REASONS else None,
                'upstream_status':status if type(status) is int and 100 <= status <= 599 else None,
            }
            _DIAGNOSTIC_LOGGER.warning('provider_egress_diagnostic %s', json.dumps(event, sort_keys=True))
        except Exception:
            pass

    def _handle(self, client: socket.socket) -> None:
        downstream = upstream = None
        response_started = False
        observer = None
        stage, host, method, operation = 'connect', 'unknown', 'unknown', 'unknown'
        try:
            host, remainder = _read_connect(client)
            host = host.lower()
            if host not in self.rules or remainder:
                raise PermissionError('Unadmitted CONNECT authority or early payload')
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            stage = 'downstream_tls'
            downstream = self._contexts[host].wrap_socket(client, server_side=True)
            with self._lock:
                self._connections.add(downstream)
            stage = 'request_header'
            header, initial_body = read_header(downstream)
            method, operation = _diagnostic_operation(header)
            outgoing, length = request_header(header, host, self.rules,
                                              chunked_ok=self._diagnostic_agent == 'argie')
            if length is not None and len(initial_body) > length:
                raise ValueError('Pipelined request or excessive body')
            stage = 'request_body'
            if length is None:
                body = read_chunked_body(downstream, initial_body)
                outgoing = with_content_length(outgoing, len(body))
            else:
                body = bytearray(initial_body)
                downstream.settimeout(IDLE_TIMEOUT)
                while len(body) < length:
                    block = downstream.recv(min(65536, length - len(body)))
                    if not block:
                        raise ValueError('Truncated request body')
                    body.extend(block)
            stage = 'payload'
            validate_payload(header, body, host)
            # No upstream connection exists until authority and operation pass.
            stage = 'upstream_connect'
            raw = _connect_public(host)
            try:
                stage = 'upstream_tls'
                upstream = self._upstream_context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                raw.close()
                raise
            with self._lock:
                self._connections.add(upstream)
            upstream.settimeout(IDLE_TIMEOUT)
            downstream.settimeout(IDLE_TIMEOUT)
            stage = 'upstream_request'
            upstream.sendall(outgoing + body)
            stage = 'upstream_response'
            response_header, response_body = read_header(upstream, timeout=IDLE_TIMEOUT)
            status_match = re.match(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: |$)', response_header)
            status = int(status_match[1]) if status_match else None
            if status is not None and not 200 <= status < 300:
                self._diagnostic(stage='upstream_status', host=host, method=method,
                                 operation=operation, status=status)
            if response_header.startswith(b'HTTP/1.1 101 '):
                raise ValueError('Unexpected protocol upgrade')
            # Feed only authenticated upstream Responses data, never request or worker text.
            request_line = outgoing.split(b'\r\n', 1)[0].split(b' ')
            if (self._model_evidence is not None and len(request_line) == 3
                    and request_line[0] == b'POST'
                    and request_line[1] in {b'/v1/responses', b'/backend-api/codex/responses', b'/responses'}):
                observer = self._model_evidence.response()
                observer.feed(response_header + b'\r\n\r\n' + response_body)
            stage = 'downstream_response'
            downstream.sendall(response_header + b'\r\n\r\n' + response_body)
            response_started = True
            stage = 'response_stream'
            while not self._stop.is_set():
                block = upstream.recv(65536)
                if not block:
                    break
                if observer is not None:
                    observer.feed(block)
                downstream.sendall(block)
            if observer is not None:
                observer.finish()
        except (OSError, ValueError, PermissionError, ssl.SSLError) as exc:
            self._diagnostic(stage=stage, host=host, method=method, operation=operation,
                             reason=_diagnostic_reason(exc))
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


