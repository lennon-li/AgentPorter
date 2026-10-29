"""Authenticated REST/MCP publication requires scope, policy and exact receipt."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agentporter import server
from agentporter.config import Config
from agentporter.git_approvals import GitApprovalRequest, issue_git_approval
from agentporter.rest.schemas import GitPushRequest
from agentporter.tools.git import create_git_tools
from agentporter.tools.jobs import JobManager
from tests.security.test_approved_git_push import configured
from tests.security.test_closeout_client_policy import rpc
from tests.security.test_git_admission import count
from tests.security.test_git_approval_state import git

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='Native BCC signed push required')


@pytest.mark.parametrize('field', ['verification_key', 'ledger_path', 'policy_path', 'url', 'force'])
def test_rest_cannot_supply_publication_authority(field):
    with pytest.raises(ValidationError):
        GitPushRequest(**{field: 'caller-selected authority'})


def test_shared_boundary_remains_locked_without_protected_backend(tmp_path, monkeypatch):
    _, service, sandbox, _, _, remote, _ = configured(tmp_path, monkeypatch)
    tools = create_git_tools(service.registry, sandbox)
    with pytest.raises(PermissionError, match='disabled'):
        tools.git_push('repo', branch='refs/heads/reviewed', prepare_only=True)
    assert remote['sent'] == []


@pytest.mark.parametrize('scope,locked', [('git_push', False), ('git_write', False), ('git_push', True)])
def test_authenticated_push_scope_and_exact_receipts_across_rest_mcp(tmp_path, monkeypatch, scope, locked):
    root, _, sandbox, key, _, remote, policy = configured(tmp_path, monkeypatch)
    config_dir = policy.parent
    public = config_dir / 'public-client-policy.yaml'
    public.write_text(yaml.safe_dump({'version': 1, 'workspaces': {
        'repo': {'path': str(root), 'operations': [scope]}}}))
    public.chmod(0o600)
    if locked:
        action = config_dir / 'action-policy.yaml'
        action.write_text('version: 1\naction_modes:\n  git_push: LOCKED\n')
        action.chmod(0o600)
    monkeypatch.setenv('AGENTPORTER_API_KEY', 'synthetic-public-push-client')
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
            path = '/api/v1/workspaces/repo/git/push'
            base = {'branch': 'refs/heads/reviewed'}
            assert client.post(path, json=base).status_code == 401
            assert client.post(path, json=base, headers=headers).status_code == 403
            args = {'workspace_id': 'repo', **base, 'prepare_only': True}
            prepared = rpc(client, config.api_key, 'git_push', args)
            assert prepared['result'].get('isError'), prepared
            assert client.post(path, json={**base, 'prepare_only': True}, headers=headers).status_code == 403
            assert client.post(path, json={**base, 'approval_receipt': 'legacy-receipt'}, headers=headers).status_code == 403
            assert remote['sent'] == []
            assert count(managers[0]) == 0
    finally:
        for instance in managers:
            if getattr(instance, '_supervisor_lock', None) is not None:
                os.close(instance._supervisor_lock)
