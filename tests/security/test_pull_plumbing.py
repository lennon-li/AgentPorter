"""Offline boundary fixtures; fake trusted backend does not implement Git pull."""
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from agentporter import client_policy, server
from agentporter.config import Config
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.rest.routers.git import router
from agentporter.rest.schemas import GitPullRequest
from agentporter.tools.git import create_git_tools
from agentporter.workspaces.leases import mutation_lease
from test_inbound_contract import Registry, NoShellSandbox, FetchBackend, policy_fixture


@pytest.fixture(autouse=True)
def offline_identities(tmp_path, monkeypatch):
    for name in ('CONFIG', 'STATE', 'CACHE'):
        monkeypatch.setenv('AGENTPORTER_' + name + '_DIR', str(tmp_path / name.lower()))
    def deny(*args, **kwargs):
        raise AssertionError('Network use is forbidden')
    monkeypatch.setattr('socket.create_connection', deny)
    monkeypatch.setattr('socket.getaddrinfo', deny)


class PullBackend:
    def __init__(self, outcome=None):
        self.calls = []
        self.outcome = outcome or {'operation': 'pull', 'status': 'recovery_required',
                                   'guard': 'synthetic-retained-guard'}

    def prepare(self, workspace, remote, branch, mode):
        self.calls.append(('prepare', workspace, remote, branch, mode))
        return SimpleNamespace(to_payload=lambda: {'operation': 'pull', 'mode': mode},
                               digest='3' * 64)

    def pull(self, workspace, remote, branch, receipt, mode):
        self.calls.append(('pull', workspace, remote, branch, receipt, mode))
        return dict(self.outcome)


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_pull_preparation_routes_exact_mode_without_executing(tmp_path, mode):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_pulls=backend)
    assert tools.git_pull('repo', branch='refs/heads/main', mode=mode, prepare_only=True) == {
        'request': {'operation': 'pull', 'mode': mode}, 'request_sha256': '3' * 64}
    assert backend.calls == [('prepare', 'repo', 'origin', 'refs/heads/main', mode)]


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_pull_execute_keeps_structured_retained_guard_outcome(tmp_path, mode):
    backend = PullBackend()
    fetch = FetchBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(),
                             approved_pulls=backend, approved_fetches=fetch)
    outcome = tools.git_pull('repo', remote='scoped', branch='refs/heads/main',
                             approval_receipt='exact-signed-pull', mode=mode)
    assert outcome == {'operation': 'pull', 'status': 'recovery_required',
                       'guard': 'synthetic-retained-guard'}
    assert backend.calls == [('pull', 'repo', 'scoped', 'refs/heads/main',
                              'exact-signed-pull', mode)]
    assert fetch.calls == []


@pytest.mark.parametrize('kwargs,error', [
    ({}, PermissionError),
    ({'prepare_only': True, 'approval_receipt': 'both'}, ValueError),
    ({'prepare_only': 'yes'}, ValueError),
    ({'mode': 'shell --exec'}, ValueError),
    ({'mode': True}, ValueError),
    ({'remote': 'https://example.com/unapproved.git'}, ValueError),
    ({'remote': '../origin'}, ValueError),
    ({'remote': 'a' * 129}, ValueError),
    ({'branch': 'refs/heads/../main'}, ValueError),
    ({'branch': 'refs/tags/main'}, ValueError),
    ({'branch': 'x' * 1025}, ValueError),
    ({'approval_receipt': 'a' * 8193}, ValueError),
    ({'approval_receipt': None}, ValueError),
])
def test_invalid_pull_request_cannot_reach_backend(tmp_path, kwargs, error):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_pulls=backend)
    base = {'branch': 'refs/heads/main', **kwargs}
    with pytest.raises(error):
        tools.git_pull('repo', **base)
    assert backend.calls == []


@pytest.mark.parametrize('permission', ['readonly', 'git_disabled'])
def test_pull_backend_never_receives_disabled_workspace(tmp_path, permission):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path, writable=permission != 'readonly',
                                    allow_git=permission != 'git_disabled'),
                             NoShellSandbox(), approved_pulls=backend)
    with pytest.raises(PermissionError):
        tools.git_pull('repo', branch='refs/heads/main', prepare_only=True)
    assert backend.calls == []


def test_trusted_pull_backend_owns_single_workspace_lease(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    state = tmp_path / 'state'
    class LeaseBackend(PullBackend):
        def pull(self, workspace, remote, branch, receipt, mode):
            with mutation_lease(root, state / 'workspace-transactions'):
                return {'status': 'synthetic_backend_reached'}
    sandbox = NoShellSandbox()
    sandbox.transactional_writes = True
    sandbox.state_dir = state
    tools = create_git_tools(Registry(root), sandbox, approved_pulls=LeaseBackend())
    assert tools.git_pull('repo', branch='refs/heads/main',
                          approval_receipt='exact-signed-pull') == {'status': 'synthetic_backend_reached'}


@pytest.mark.parametrize('scope,allowed', [('git_pull', True), ('git_fetch', False),
    ('git_write', False), ('write', False), ('dispatch_write', False)])
def test_public_pull_requires_its_distinct_scope(tmp_path, scope, allowed):
    policy = client_policy.PublicClientPolicy.__new__(client_policy.PublicClientPolicy)
    policy.scopes = {'repo': frozenset({scope})}
    token = client_policy.PRINCIPAL.set('public')
    try:
        if allowed:
            policy.check('git_pull', {'workspace_id': 'repo'})
        else:
            with pytest.raises(PermissionError):
                policy.check('git_pull', {'workspace_id': 'repo'})
        with pytest.raises(PermissionError):
            policy.check('git_pull', {'workspace_id': 'other'})
    finally:
        client_policy.PRINCIPAL.reset(token)


@pytest.mark.parametrize('field,value', [('mode','exec'), ('remote','a' * 129),
    ('branch','b' * 1025), ('approval_receipt','c' * 8193),
    ('url','https://example.com/other.git'), ('credential_file','/private'),
    ('force',True), ('argv',['git','pull']), ('prepare_only','true')])
def test_rest_schema_refuses_expansion_and_oversized_fields(field, value):
    with pytest.raises(ValidationError):
        GitPullRequest(**{field: value})


def test_pull_only_authority_does_not_imply_fetch_or_push(tmp_path):
    owner, registry, state = policy_fixture(tmp_path, ['pull'])
    authority = load_owner_git_remotes(owner, registry, state)
    grant, _ = authority.authorize('repo', 'origin', 'refs/heads/main', 'pull')
    assert grant.operations == frozenset({'pull'})
    for operation in ('fetch', 'push'):
        with pytest.raises(PermissionError):
            authority.authorize('repo', 'origin', 'refs/heads/main', operation)


def app_with_tool(tool):
    app = FastAPI()
    app.state.tools = {'git_pull': tool}
    app.include_router(router)
    return app


def test_rest_forwards_only_explicit_fields_and_structured_guard(tmp_path):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_pulls=backend)
    with TestClient(app_with_tool(tools.git_pull)) as client:
        response = client.post('/workspaces/repo/git/pull', json={
            'remote': 'scoped', 'branch': 'refs/heads/main', 'mode': 'rebase',
            'approval_receipt': 'exact-signed-pull'})
    assert response.status_code == 200
    assert response.json() == backend.outcome
    assert backend.calls == [('pull', 'repo', 'scoped', 'refs/heads/main',
                              'exact-signed-pull', 'rebase')]


def test_rest_absent_backend_is_explicit_forbidden(tmp_path):
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox())
    with TestClient(app_with_tool(tools.git_pull)) as client:
        response = client.post('/workspaces/repo/git/pull', json={'branch': 'refs/heads/main'})
    assert response.status_code == 403
    assert 'Git pull is locked' in response.json()['detail']


@pytest.mark.parametrize('body,status', [
    ({'branch': 'refs/heads/main'}, 403),
    ({'branch': 'refs/tags/main', 'prepare_only': True}, 422),
    ({'branch': 'refs/heads/main', 'prepare_only': True, 'approval_receipt': 'both'}, 422),
    ({'branch': 'refs/heads/main', 'backend': 'caller-selected'}, 422),
])
def test_rest_refusal_keeps_backend_unreached(tmp_path, body, status):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_pulls=backend)
    with TestClient(app_with_tool(tools.git_pull)) as client:
        response = client.post('/workspaces/repo/git/pull', json=body)
    assert response.status_code == status
    assert backend.calls == []


def test_mcp_registered_wrapper_passes_all_pull_fields(tmp_path, monkeypatch):
    backend = PullBackend()
    original = create_git_tools
    def injected(registry, sandbox, **kwargs):
        assert kwargs.get('approved_pulls') is None  # Runtime remains disabled without implementation.
        return original(registry, sandbox, **{**kwargs, 'approved_pulls': backend})
    monkeypatch.setattr(server, 'create_git_tools', injected)
    monkeypatch.setattr(server, 'AgentBroker', lambda *a, **k: SimpleNamespace(
        development_runtime=None, list_agents=lambda: []))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    cfg = Config(config_dir=tmp_path/'config', state_dir=tmp_path/'state', cache_dir=tmp_path/'cache')
    cfg.workspaces = {'repo': {'path': str(workspace), 'writable': True, 'allow_git': True}}
    _, context = server.build_mcp_server(cfg)
    assert context['tools']['git_pull'](workspace_id='repo', branch='refs/heads/main', mode='merge',
                                       prepare_only=True) == {
        'request': {'operation': 'pull', 'mode': 'merge'}, 'request_sha256': '3' * 64}
    assert context['tools']['git_pull'](workspace_id='repo', branch='refs/heads/main', mode='rebase',
                                       approval_receipt='exact-signed-pull') == backend.outcome
    assert backend.calls == [('prepare', 'repo', 'origin', 'refs/heads/main', 'merge'),
                             ('pull', 'repo', 'origin', 'refs/heads/main', 'exact-signed-pull', 'rebase')]


def test_supplied_pull_backend_does_not_enable_push(tmp_path):
    backend = PullBackend()
    tools = create_git_tools(Registry(tmp_path), NoShellSandbox(), approved_pulls=backend)
    with pytest.raises(PermissionError, match='disabled by operator policy'):
        tools.git_push('repo', branch='refs/heads/main', approval_receipt='exact-signed-pull')
    assert backend.calls == []
