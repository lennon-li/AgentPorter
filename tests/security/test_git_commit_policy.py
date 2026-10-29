"""Public requests must never choose the approval key or backend authority."""
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from agentporter.git_approvals import GitApprovalRequest, issue_git_approval
from agentporter.git_policy import load_approved_commits
from agentporter.rest.schemas import GitCommitRequest
from agentporter.tools.git import create_git_tools
from tests.security.test_git_admission import setup, count
from tests.security.test_git_approval_state import git

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(),
                               reason='Native BCC approved Git required')


def configured(tmp_path):
    root, original, sandbox, key, manager = setup(tmp_path)
    config = tmp_path / 'operator'
    config.mkdir(mode=0o700)
    data = {'version': 1, 'author_name': 'Owner', 'author_email': 'owner@example.invalid',
            'verification_key': key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            'ledger_path': str(original.verifier.ledger_path), 'workspaces': ['repo']}
    policy = config / 'git-commit-policy.json'
    policy.write_text(json.dumps(data))
    policy.chmod(0o600)
    service = load_approved_commits(config, original.registry, sandbox, manager)
    return root, service, sandbox, key, manager, policy


def test_shared_tool_prepares_exact_request_then_commits_with_owner_signature(tmp_path):
    root, backend, sandbox, key, manager, _ = configured(tmp_path)
    tools = create_git_tools(backend.backend.registry, sandbox, approved_commits=backend)
    proposal = json.loads(tools.git_commit('repo', 'Reviewed API change', prepare_only=True))
    request = GitApprovalRequest.from_payload(proposal['request'])
    receipt = issue_git_approval(key, request)
    result = tools.git_commit('repo', 'Reviewed API change',
        approval_timestamp=proposal['request']['parameters']['timestamp'], approval_receipt=receipt)
    assert result == git(root, 'rev-parse', 'HEAD')
    assert count(manager) == 0


def test_missing_policy_stays_disabled(tmp_path):
    _, service, sandbox, _, manager = setup(tmp_path)
    assert load_approved_commits(tmp_path / 'absent', service.registry, sandbox, manager) is None


def test_policy_change_revokes_loaded_authority(tmp_path):
    _, service, _, _, _, policy = configured(tmp_path)
    data = json.loads(policy.read_text())
    data['workspaces'] = []
    policy.write_text(json.dumps(data))
    with pytest.raises(PermissionError, match='policy changed'):
        service.prepare('repo', 'not authorized', 1000)


def test_unlisted_workspace_cannot_use_owner_authority(tmp_path):
    root, service, _, _, _, _ = configured(tmp_path)
    service.backend.registry.register('other', str(root), writable=True)
    with pytest.raises(PermissionError, match='outside owner'):
        service.prepare('other', 'not authorized', 1000)


def test_registered_parent_cannot_expose_owner_policy(tmp_path):
    _, service, _, _, _, _ = configured(tmp_path)
    service.backend.registry.register('parent', str(tmp_path), writable=True)
    with pytest.raises(PermissionError, match='overlaps'):
        service.prepare('repo', 'not authorized', 1000)


@pytest.mark.parametrize('field', ['verification_key', 'ledger_path', 'policy_path'])
def test_rest_request_cannot_supply_approval_authority(field):
    with pytest.raises(ValidationError):
        GitCommitRequest(message='cannot choose authority', **{field: 'attacker choice'})


def test_unsigned_request_and_implicit_staging_are_denied(tmp_path):
    root, backend, sandbox, _, _, _ = configured(tmp_path)
    tools = create_git_tools(backend.backend.registry, sandbox, approved_commits=backend)
    before = git(root, 'rev-parse', 'HEAD')
    with pytest.raises(PermissionError):
        tools.git_commit('repo', 'no receipt')
    with pytest.raises(PermissionError):
        tools.git_commit('repo', 'implicit staging', all_files=True, prepare_only=True)
    assert git(root, 'rev-parse', 'HEAD') == before


def test_rest_prepare_sign_commit_and_denial_paths(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from agentporter.rest.routers.git import router
    root, backend, sandbox, key, manager, _ = configured(tmp_path)
    tools = create_git_tools(backend.backend.registry, sandbox, approved_commits=backend)
    app = FastAPI()
    app.include_router(router)
    app.state.tools = {'git_commit': tools.git_commit}
    with TestClient(app) as client:
        path = '/workspaces/repo/git/commit'
        assert client.post(path, json={'message': 'REST reviewed'}).status_code == 403
        assert client.post(path, json={'message': 'REST reviewed', 'ledger_path': '/attacker'}).status_code == 422
        response = client.post(path, json={'message': 'REST reviewed', 'prepare_only': True})
        assert response.status_code == 200
        proposal = json.loads(response.json())
        request = GitApprovalRequest.from_payload(proposal['request'])
        timestamp = request.to_payload()['parameters']['timestamp']
        signed = issue_git_approval(key, request)
        denied = client.post(path, json={'message': 'changed', 'approval_timestamp': timestamp,
                                        'approval_receipt': signed})
        assert denied.status_code == 403
        accepted = client.post(path, json={'message': 'REST reviewed', 'approval_timestamp': timestamp,
                                          'approval_receipt': signed})
        assert accepted.status_code == 200
        assert accepted.json() == git(root, 'rev-parse', 'HEAD')
    assert count(manager) == 0


@pytest.mark.parametrize('kind', ['public', 'symlink', 'hardlink'])
def test_untrusted_policy_files_cannot_enable_public_commits(tmp_path, kind):
    _, service, sandbox, _, manager, policy = configured(tmp_path)
    if kind == 'public':
        policy.chmod(0o666)
    elif kind == 'symlink':
        original = policy.with_suffix('.original')
        policy.rename(original)
        policy.symlink_to(original)
    else:
        import os
        os.link(policy, policy.with_suffix('.alias'))
    with pytest.raises((PermissionError, OSError)):
        load_approved_commits(policy.parent, service.backend.registry, sandbox, manager)


def test_missing_ledger_cannot_silently_reset_public_replay_protection(tmp_path):
    _, service, sandbox, _, manager, policy = configured(tmp_path)
    data = json.loads(policy.read_text())
    missing = Path(data['ledger_path']).with_name('missing.db')
    data['ledger_path'] = str(missing)
    policy.write_text(json.dumps(data))
    with pytest.raises(FileNotFoundError):
        load_approved_commits(policy.parent, service.backend.registry, sandbox, manager)
    assert not missing.exists()


def test_staging_scope_does_not_authorize_public_commit(tmp_path):
    import yaml
    from agentporter.client_policy import PublicClientPolicy, PRINCIPAL
    _, service, sandbox, _, _, policy = configured(tmp_path)
    path = policy.parent / 'public-client-policy.yaml'
    root = service.backend.registry.get('repo').path
    path.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'repo': {'path': root, 'operations': ['git_write']}}}))
    path.chmod(0o600)
    clients = PublicClientPolicy(policy.parent, sandbox.state_dir, service.backend.registry)
    token = PRINCIPAL.set('public')
    try:
        with pytest.raises(PermissionError):
            clients.check('git_commit', {'workspace_id': 'repo'})
    finally:
        PRINCIPAL.reset(token)


def test_authenticated_rest_and_mcp_commit_without_phone_receipts(tmp_path, monkeypatch):
    import os
    import yaml
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from agentporter.config import Config
    from agentporter import server
    from tests.security.test_closeout_client_policy import rpc
    from agentporter.tools.jobs import JobManager
    root, _, sandbox, key, _, policy = configured(tmp_path)
    config_dir = policy.parent
    public = config_dir / 'public-client-policy.yaml'
    public.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'repo': {'path': str(root), 'operations': ['write']}}}))
    public.chmod(0o600)
    monkeypatch.setenv('AGENTPORTER_API_KEY', 'synthetic-public-git-client')
    config = Config(config_dir=config_dir, state_dir=sandbox.state_dir, cache_dir=tmp_path / 'cache')
    config.workspaces = {'repo': {'path': str(root), 'writable': True}}
    config.sandbox.workspace_transactions = True
    config.security.allowed_hosts = ['testserver']
    resources = sandbox.resources
    resources.recover = lambda: None
    runtime = SimpleNamespace(_config=lambda: {'job_resources': {}})
    monkeypatch.setattr(server, 'AgentBroker', lambda *args, **kwargs:
        SimpleNamespace(development_runtime=runtime, list_agents=lambda: []))
    monkeypatch.setattr(server, 'JobResources', lambda settings: resources)
    managers = []
    def manager(*args, **kwargs):
        instance = JobManager(*args, **kwargs)
        managers.append(instance)
        return instance
    monkeypatch.setattr(server, 'JobManager', manager)
    try:
        with TestClient(server.create_asgi_app(config)) as client:
            headers = {'X-AgentPorter-Key': config.api_key}
            path = '/api/v1/workspaces/repo/git/commit'
            assert client.post(path, json={'message': 'unsigned'}).status_code == 401
            committed = rpc(client, config.api_key, 'git_commit',
                {'workspace_id': 'repo', 'message': 'Autonomous MCP commit'})
            assert not committed['result'].get('isError'), committed
            assert committed['result']['content'][0]['text'] == git(root, 'rev-parse', 'HEAD')
            (root / 'ordinary').write_text('Autonomous REST change')
            git(root, 'add', 'ordinary')
            result = client.post(path, json={'message': 'Autonomous REST commit'}, headers=headers)
            assert result.status_code == 200, result.text
            assert result.json() == git(root, 'rev-parse', 'HEAD')
            assert count(managers[0]) == 0
    finally:
        for instance in managers:
            if getattr(instance, '_supervisor_lock', None) is not None:
                os.close(instance._supervisor_lock)
