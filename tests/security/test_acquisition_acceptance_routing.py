"""The live acceptance procedure cannot bypass v17 public-client isolation."""
from contextlib import asynccontextmanager
import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def verifier():
    path = Path(__file__).resolve().parents[2] / 'scripts/verify-a7dev-cranary-acquisition.py'
    spec = importlib.util.spec_from_file_location('acceptance_routing', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fake_gateway(verifier, tmp_path, monkeypatch):
    m = verifier
    public_key, internal_key, fp = 'p' * 64, 'i' * 64, 'f' * 64
    public = tmp_path / 'secrets.env'; public.write_text('AGENTPORTER_API_KEY=' + public_key + '\n')
    internal = tmp_path / 'internal.key'; internal.write_text(internal_key + '\n')
    output = tmp_path / 'output'; output.mkdir()
    state = SimpleNamespace(calls=[], clients=[], published=[], fingerprint=fp,
                            public_exec=False, internal_failure=False, internal_exec_count=0)
    scope = {'enabled': True, 'workspaces': ['cranary'], 'methods': ['GET', 'HEAD'],
        'hosts': sorted(m.helper.HOSTS | {'packagemanager.posit.co'}), 'generic_shell_network': False,
        'downloads': {'hosts': ['cran.r-project.org', 'packagemanager.posit.co'],
                      'directory': m.DIRECTORY, 'max_response_bytes': 16777216, 'timeout_seconds': 60}}
    state.scope = scope
    @asynccontextmanager
    async def client(headers):
        state.clients.append(headers)
        yield SimpleNamespace(headers=headers, follow_redirects=False)
    @asynccontextmanager
    async def stream(endpoint, http_client):
        token = http_client.headers['X-AgentPorter-Key']
        if token == internal_key:
            assert endpoint == m.helper.LOCAL
            assert set(http_client.headers) == {'X-AgentPorter-Key'}
        yield ((endpoint, token), None)
    class Session:
        def __init__(self, info, unused):self.endpoint, self.token = info
        async def __aenter__(self):return self
        async def __aexit__(self, *a):pass
        async def initialize(self):pass
        async def call_tool(self, name, args):
            state.calls.append((self.endpoint, self.token, name, args))
            denied = {'is_error': True, 'data': {'error': 'fixture denial'}}
            def ok(data):return {'is_error': False, 'data': data}
            if name == 'get_capabilities':return ok({'scoped_public_https': scope})
            if name == 'server_deploy_info':return ok({'pid': 123, 'loaded_fingerprint': state.fingerprint,
                'disk_fingerprint': state.fingerprint, 'stale': False})
            if name == 'https_download':
                assert self.token == public_key and self.endpoint == m.helper.PUBLIC
                if (args.get('workspace_id') != 'cranary' or args.get('url') not in {m.POSIT, m.TCIU}
                        or args['filename'].startswith(('over-', '../'))):return denied
                path = m.DIRECTORY + '/' + args['filename'];state.published.append(path)
                return ok({'http_status': 200, 'bytes': 100, 'sha256': args.get('expected_sha256') or 'a' * 64,
                    'expected_sha256_verified': args.get('expected_sha256') is not None,
                    'path': path, 'source_url': args['url'], 'training_eligible': False,
                    'historical_identity_verified': False})
            if name == 'list_files':return ok(state.published)
            if name == 'exec_run':
                if self.token == public_key:
                    return ok({'exit_code': 0}) if state.public_exec and args['argv'] == ['true'] else denied
                assert self.endpoint == m.helper.LOCAL and args['network_access'] is False
                state.internal_exec_count += 1
                payload = ({'saved_bytes_verified': True, 'consumer_sha256': 'b' * 64}
                    if state.internal_exec_count == 1 else {'population_size_candidate': 1000,
                    'sha256': 'c' * 64, 'training_eligible': False})
                return ok({'exit_code': 1 if state.internal_failure else 0, 'stdout': json.dumps(payload)})
            raise AssertionError(name)
    monkeypatch.setattr(m, 'create_mcp_http_client', client)
    monkeypatch.setattr(m, 'streamable_http_client', stream)
    monkeypatch.setattr(m, 'ClientSession', Session)
    monkeypatch.setattr(m.helper, 'unpack', lambda result: result)
    return state, {'public_key_file': public, 'internal_key_file': internal, 'expected_fingerprint': fp}, output


def test_after_uses_public_acquisition_and_private_loopback_offline_checks(verifier, fake_gateway):
    state, kwargs, output = fake_gateway
    asyncio.run(verifier.verify(True, output, **kwargs))
    assert state.internal_exec_count == 3
    assert json.loads((output / 'summary.json').read_text())['installed_acceptance'] == 'passed'
    receipt = json.loads((output / 'acquisition-receipts.json').read_text())
    assert len(receipt['downloads']) == 2 and receipt['saved_bytes_verified']
    for path in output.iterdir():
        assert 'p' * 64 not in path.read_text() and 'i' * 64 not in path.read_text()


@pytest.mark.parametrize('flag', [False, True])
def test_historical_acceptance_understands_explicit_cran_opt_in(verifier, fake_gateway, flag):
    state, kwargs, output = fake_gateway
    state.scope['downloads']['cran_all_paths'] = flag
    asyncio.run(verifier.verify(True, output, **kwargs))
    assert json.loads((output / 'summary.json').read_text())['installed_acceptance'] == 'passed'


@pytest.mark.parametrize('key,value', [('cran_all_paths', 'true'), ('cran_all_paths', 1),
    ('cran_all_paths', None), ('unknown_permission', True)])
def test_historical_acceptance_rejects_unknown_or_untyped_scope(verifier, fake_gateway, key, value):
    state, kwargs, output = fake_gateway
    state.scope['downloads'][key] = value
    with pytest.raises(AssertionError):
        asyncio.run(verifier.verify(True, output, **kwargs))


def test_after_requires_private_key_and_exact_fingerprint_before_access(verifier, tmp_path):
    with pytest.raises(ValueError, match='requires'):
        asyncio.run(verifier.verify(True, tmp_path))


def test_wrong_loaded_fingerprint_prevents_acquisition(verifier, fake_gateway):
    state, kwargs, output = fake_gateway;state.fingerprint = '0' * 64
    with pytest.raises(AssertionError):asyncio.run(verifier.verify(True, output, **kwargs))
    assert not state.published


def test_public_generic_execution_must_remain_denied(verifier, fake_gateway):
    state, kwargs, output = fake_gateway;state.public_exec = True
    with pytest.raises(AssertionError):asyncio.run(verifier.verify(True, output, **kwargs))
    assert not state.published


def test_nonzero_offline_exit_cannot_claim_acceptance(verifier, fake_gateway):
    state, kwargs, output = fake_gateway;state.internal_failure = True
    with pytest.raises(AssertionError):asyncio.run(verifier.verify(True, output, **kwargs))
    assert not (output / 'summary.json').exists()


def test_internal_credential_must_differ_from_public(verifier, fake_gateway):
    state, kwargs, output = fake_gateway
    kwargs['internal_key_file'].write_text('p' * 64)
    with pytest.raises(ValueError, match='distinct'):asyncio.run(verifier.verify(True, output, **kwargs))
    assert not state.calls
