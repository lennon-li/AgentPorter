"""Offline synthetic authority/framing regressions for the development overlay."""
from pathlib import Path
import hashlib
import importlib.util
import json
import ssl
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = Path('/opt/agentporter-development/current/src')
sys.path.insert(0, str(ACTIVE))
import agentporter.agents
spec = importlib.util.spec_from_file_location('agentporter.agents.provider_egress', ROOT / 'src/agentporter/agents/provider_egress.py')
broker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = broker
spec.loader.exec_module(broker)
agentporter.agents.provider_egress = broker


def request(method='GET', target='/copilot_internal/user', host='api.github.com', extras=''):
    return (f'{method} {target} HTTP/1.1\r\nHost: {host}' + extras).encode()


def test_reproduces_active_denial_and_candidate_admits_only_account_read():
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    original = Path(manifest['source']).read_bytes()
    assert hashlib.sha256(original).hexdigest() == manifest['source_sha256']
    native_spec = importlib.util.spec_from_file_location('unmodified_provider_egress', manifest['source'])
    native = importlib.util.module_from_spec(native_spec); native_spec.loader.exec_module(native)
    assert not native.operation_allowed(native.provider_rules('phil'), 'api.github.com', 'GET', '/copilot_internal/user')
    assert broker.operation_allowed(broker.provider_rules('phil'), 'api.github.com', 'GET', '/copilot_internal/user')


@pytest.mark.parametrize('agent', ['jax','liz','prof','ming','argie','wei'])
def test_new_origin_is_phil_only(agent):
    assert not broker.operation_allowed(broker.provider_rules(agent), 'api.github.com', 'GET', '/copilot_internal/user')


@pytest.mark.parametrize('method,target', [
    ('POST','/copilot_internal/user'), ('DELETE','/copilot_internal/user'),
    ('GET','/copilot_internal/user?redirect=https://example.com'),
    ('GET','/copilot_internal/user?'), ('GET','/copilot_internal/user#fragment'),
    ('GET','/copilot_internal/user/'), ('GET','/copilot_internal/v2/token'),
    ('GET','/user'), ('GET','/repos/owner/repository'), ('POST','/repos/owner/repository/git/refs'),
    ('GET','//api.github.com/copilot_internal/user'),
    ('GET','https://api.github.com/copilot_internal/user'),
    ('GET','/copilot_internal/%75ser'), ('GET','/copilot_internal/../user'),
])
def test_bootstrap_does_not_expand_token_repository_or_redirect_capability(method,target):
    assert not broker.operation_allowed(broker.provider_rules('phil'), 'api.github.com', method, target)


@pytest.mark.parametrize('host', ['github.com','evil.example','api.github.com.evil.example','127.0.0.1'])
def test_redirect_destination_origin_not_admitted(host):
    assert not broker.operation_allowed(broker.provider_rules('phil'),host,'GET','/copilot_internal/user')


@pytest.mark.parametrize('extras', ['\r\nContent-Length: 1','\r\nTransfer-Encoding: chunked',
    '\r\nUpgrade: websocket','\r\nExpect: 100-continue','\r\nHost: api.github.com'])
def test_bootstrap_has_no_body_upgrade_or_ambiguous_headers(extras):
    with pytest.raises((ValueError,PermissionError)):
        broker.request_header(request(extras=extras),'api.github.com',broker.provider_rules('phil'))


def test_bootstrap_keeps_origin_auth_and_strips_proxy_rewrite_headers():
    header, length = broker.request_header(request(extras='\r\nAuthorization: Bearer synthetic-only\r\nProxy-Authorization: synthetic-proxy\r\nX-Original-URL: /repos/o/r'), 'api.github.com', broker.provider_rules('phil'))
    assert length == 0
    assert b'Host: api.github.com\r\n' in header
    assert b'authorization: Bearer synthetic-only' in header
    assert b'synthetic-proxy' not in header and b'/repos/o/r' not in header
    with pytest.raises(PermissionError):
        broker.request_header(request(host='evil.example'),'api.github.com',broker.provider_rules('phil'))


@pytest.mark.parametrize('agent',['liz','prof'])
def test_codex_websocket_deny_and_https_model_operation_preserved(agent):
    rules=broker.provider_rules(agent)
    with pytest.raises(PermissionError, match='Opaque protocol upgrades'):
        broker.request_header(b'POST /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nUpgrade: websocket', 'chatgpt.com', rules)
    header, size=broker.request_header(b'POST /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nContent-Length: 2','chatgpt.com',rules)
    assert size==2 and b'Connection: close' in header


def test_unchanged_refresh_operations_do_not_prove_refresh_success():
    assert broker.operation_allowed(broker.provider_rules('ming'),'platform.claude.com','POST','/v1/oauth/token')
    assert broker.operation_allowed(broker.provider_rules('argie'),'oauth2.googleapis.com','POST','/token')
    assert not broker.operation_allowed(broker.provider_rules('ming'),'platform.claude.com','GET','/login')


def test_verified_upstream_tls_and_ca_key_isolation_preserved(tmp_path):
    tmp_path.chmod(0o700)
    relay=broker.ProviderEgress(tmp_path/'relay.sock',agent='phil')
    try:
        assert relay._upstream_context.verify_mode==ssl.CERT_REQUIRED
        assert relay._upstream_context.check_hostname is True
        assert set(relay._contexts)==set(broker.provider_rules('phil'))
        assert 'api.github.com' in relay._contexts
        assert not (relay._tls_directory/'key.pem').exists()
        assert not (relay._tls_directory/'leaf-key.pem').exists()
    finally:
        relay.close()


def test_empty_explicit_origin_rule_does_not_grant_bootstrap():
    assert not broker.operation_allowed({'api.github.com':frozenset()},'api.github.com','GET','/copilot_internal/user')
