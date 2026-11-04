"""Offline source contract checks; no real pull backend or network acceptance."""
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import agentporter
from agentporter import client_policy
from agentporter.git_approvals import GitApprovalVerifier
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_smart_http import RemoteRepository
from agentporter.rest.schemas import GitPullRequest
from agentporter.tools.git import create_git_tools


BASELINE = Path(__file__).resolve().parents[2] / 'src' / 'agentporter'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError('Network use is forbidden in these fixtures')
    monkeypatch.setattr('socket.create_connection', deny)
    monkeypatch.setattr('socket.getaddrinfo', deny)


class Registry:
    def __init__(self, root, *, writable=True, allow_git=True):
        self.entries = {'repo': SimpleNamespace(path=str(root), writable=writable,
                                                allow_git=allow_git)}

    def get(self, workspace_id):
        return self.entries[workspace_id]

    def list_all(self):
        return [{'path': row.path} for row in self.entries.values()]


class NoShellSandbox:
    transactional_writes = False

    def run(self, **kwargs):
        raise AssertionError('Inbound API must not invoke unrestricted shell Git')


class FetchBackend:
    def __init__(self):
        self.calls = []

    def prepare(self, workspace, remote, branch):
        self.calls.append(('prepare', workspace, remote, branch))
        return SimpleNamespace(to_payload=lambda: {'operation': 'fetch'},
                               digest='1' * 64)

    def fetch(self, workspace, remote, branch, receipt):
        self.calls.append(('fetch', workspace, remote, branch, receipt))
        return '2' * 40


def policy_fixture(tmp_path, operations):
    root = tmp_path / 'repo'
    root.mkdir()
    owner = tmp_path / 'owner'
    owner.mkdir(mode=0o700)
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate().public_key()
    ledger = owner / 'ledger.sqlite'
    GitApprovalVerifier(key, ledger)
    document = {
        'version': 1,
        'verification_key': key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        'ledger_path': str(ledger),
        'grants': [{
            'workspace_id': 'repo', 'remote_id': 'origin',
            'url': 'https://example.com/owner/repo.git',
            'ref': 'refs/heads/main', 'operations': operations,
            'credential_file': None, 'username': 'x-access-token',
        }],
    }
    path = owner / 'git-remote-policy.json'
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return owner, Registry(root), state


def test_imports_isolated_candidate_package():
    assert Path(agentporter.__file__).resolve().parent == BASELINE


def test_required_pull_has_explicit_public_scope():
    assert client_policy.OPERATIONS.get('git_pull') == 'git_pull'
    assert 'git_pull' in client_policy.SCOPES


def test_required_pull_request_can_bind_exact_approval_and_mode():
    fields = GitPullRequest.model_fields
    assert {'remote', 'branch', 'approval_receipt', 'prepare_only', 'mode'} <= fields.keys()
    assert GitPullRequest.model_config.get('extra') == 'forbid'


def test_required_pull_has_separate_injected_trusted_backend():
    assert 'approved_pulls' in inspect.signature(create_git_tools).parameters


def test_required_exact_pull_grant_is_representable(tmp_path):
    owner, registry, state = policy_fixture(tmp_path, ['fetch', 'pull'])
    authority = load_owner_git_remotes(owner, registry, state)
    grant, _ = authority.authorize('repo', 'origin', 'refs/heads/main', 'pull')
    assert grant.operations == frozenset({'fetch', 'pull'})
    with pytest.raises(PermissionError):
        authority.authorize('repo', 'origin', 'refs/heads/main', 'push')


def test_fetch_backend_receives_only_exact_fields(tmp_path):
    backend = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_fetches=backend)
    assert tools.git_fetch('repo', remote='origin', branch='refs/heads/main',
                           approval_receipt='fixture-signature') == '2' * 40
    assert backend.calls == [('fetch', 'repo', 'origin', 'refs/heads/main',
                              'fixture-signature')]


def test_fetch_preparation_routes_through_trusted_backend(tmp_path):
    backend = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_fetches=backend)
    request = json.loads(tools.git_fetch('repo', branch='refs/heads/main', prepare_only=True))
    assert request == {'request': {'operation': 'fetch'}, 'request_sha256': '1' * 64}
    assert backend.calls == [('prepare', 'repo', 'origin', 'refs/heads/main')]


def test_legacy_fetch_missing_authorization_cannot_reach_backend(tmp_path):
    backend = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_fetches=backend)
    with pytest.raises(PermissionError):
        tools.git_fetch('repo', branch='refs/heads/main')
    assert backend.calls == []


def test_fetch_preparation_cannot_also_execute_receipt(tmp_path):
    backend = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_fetches=backend)
    with pytest.raises(ValueError, match='Preparation cannot also'):
        tools.git_fetch('repo', branch='refs/heads/main', prepare_only=True,
                        approval_receipt='fixture-signature')
    assert backend.calls == []


@pytest.mark.parametrize('operation', ['git_fetch', 'git_pull'])
@pytest.mark.parametrize('permission', ['readonly', 'git_disabled'])
def test_workspace_denial_precedes_inbound_work(tmp_path, operation, permission):
    registry = Registry(tmp_path, writable=permission != 'readonly',
                        allow_git=permission != 'git_disabled')
    backend = FetchBackend()
    tools = create_git_tools(registry, NoShellSandbox(), approved_fetches=backend)
    with pytest.raises(PermissionError):
        getattr(tools, operation)('repo', branch='refs/heads/main')
    assert backend.calls == []


def test_pull_is_locked_even_when_fetch_backend_exists(tmp_path):
    backend = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_fetches=backend)
    with pytest.raises(PermissionError, match='Git pull is locked'):
        tools.git_pull('repo', branch='refs/heads/main')
    assert backend.calls == []


def test_push_stays_denied_despite_supplied_backend_and_receipt(tmp_path):
    class RejectBackend:
        def __getattr__(self, name):
            raise AssertionError('Push backend must remain unreachable')
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(),
                             approved_pushes=RejectBackend(), approved_fetches=FetchBackend())
    with pytest.raises(PermissionError, match='disabled by operator policy'):
        tools.git_push('repo', branch='refs/heads/main', approval_receipt='fixture-signature')


def test_fetch_only_exact_policy_cannot_grant_push_or_other_ref(tmp_path):
    owner, registry, state = policy_fixture(tmp_path, ['fetch'])
    authority = load_owner_git_remotes(owner, registry, state)
    grant, broker = authority.authorize('repo', 'origin', 'refs/heads/main', 'fetch')
    assert grant.repository.url == broker.remote.url == 'https://example.com/owner/repo.git'
    for args in [('repo', 'origin', 'refs/heads/main', 'push'),
                 ('repo', 'other', 'refs/heads/main', 'fetch'),
                 ('repo', 'origin', 'refs/heads/other', 'fetch')]:
        with pytest.raises(PermissionError, match='outside owner'):
            authority.authorize(*args)


@pytest.mark.parametrize('url', [
    'http://example.com/owner/repo.git', 'https://secret@example.com/owner/repo.git',
    'file:///tmp/repo.git', 'https://example.com/owner/repo.git?evil=1',
])
def test_transport_refuses_caller_url_expansion(url):
    with pytest.raises(ValueError):
        RemoteRepository(url)
