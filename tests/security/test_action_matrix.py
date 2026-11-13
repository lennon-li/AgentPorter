"""Exact protected action policy, without relaxing specialized backend gates."""
import pytest
import yaml

from agentporter.action_policy import DEFAULT_ACTION_MODES, OperatorActionPolicy
from agentporter.server import build_mcp_server, create_asgi_app


def policy(tmp_path, modes=None, rows=None):
    path = tmp_path / 'action-policy.yaml'
    path.write_text(yaml.safe_dump({'version': 1, 'action_modes': modes or {},
                                    'scoped_modes': rows or []}))
    path.chmod(0o600)
    return OperatorActionPolicy(tmp_path)


@pytest.mark.parametrize('action', sorted(DEFAULT_ACTION_MODES))
def test_all_actions_have_effective_snapshot_and_owner_denial(tmp_path, action):
    p = policy(tmp_path, {action: 'LOCKED'})
    rows = p.snapshot()
    assert len(rows) == len(DEFAULT_ACTION_MODES)
    assert {row['action'] for row in rows} == set(DEFAULT_ACTION_MODES)
    row = next(row for row in rows if row['action'] == action)
    assert row['mode'] == 'LOCKED' and row['backend_checks_required'] is True
    with pytest.raises(PermissionError):
        p.check(action, {'workspace_id': 'demo', 'agent': 'codex_review'})


def test_inbound_scope_and_separate_commit_approval(tmp_path):
    p = OperatorActionPolicy(tmp_path)
    for action in ('git_fetch', 'git_pull'):
        assert p.check(action, {'workspace_id': 'repo', 'agent': 'claude_agent'}) == 'SCOPE'
    assert p.check('git_commit', {'workspace_id': 'repo'}) == 'APPROVAL'
    assert len(DEFAULT_ACTION_MODES) == 35  # clone is typed git_pull, not a new public action.


def test_scoped_isolation_specificity_and_explicit_deny(tmp_path):
    p = policy(tmp_path, rows=[
        {'action': 'git_commit', 'agent': 'codex_review', 'mode': 'APPROVAL'},
        {'action': 'git_commit', 'workspace_id': 'one', 'agent': 'codex_review', 'mode': 'SCOPE'},
        {'action': 'git_commit', 'workspace_id': 'two', 'mode': 'LOCKED'},
        {'action': 'git_commit', 'workspace_id': 'two', 'agent': 'codex_review', 'mode': 'ALLOW'},
    ])
    assert p.effective_mode('git_commit', workspace_id='one', agent='codex_review') == 'SCOPE'
    assert p.effective_mode('git_commit', workspace_id='other', agent='codex_review') == 'APPROVAL'
    assert p.effective_mode('git_commit', workspace_id='one', agent='codex_impl') == 'APPROVAL'
    assert p.effective_mode('git_commit', workspace_id='two', agent='codex_review') == 'LOCKED'
    assert p.effective_mode('git_commit', workspace_id='other', agent='codex_impl') == 'APPROVAL'
    assert all('one' not in str(row) and 'two' not in str(row) for row in p.snapshot())
    assert next(row for row in p.snapshot() if row['action'] == 'git_commit')['scope_condition']


def test_global_deny_cannot_be_overridden_and_ties_deny(tmp_path):
    p = policy(tmp_path, {'read_file': 'LOCKED'}, [
        {'action': 'read_file', 'workspace_id': 'repo', 'mode': 'ALLOW'},
        {'action': 'git_commit', 'workspace_id': 'repo', 'mode': 'ALLOW'},
        {'action': 'git_commit', 'agent': 'codex_review', 'mode': 'APPROVAL'},
    ])
    assert p.effective_mode('read_file', workspace_id='repo') == 'LOCKED'
    assert p.effective_mode('git_commit', workspace_id='repo', agent='codex_review') == 'APPROVAL'


@pytest.mark.parametrize('row', [
    {'action': 'git_commit', 'mode': 'ALLOW'},
    {'action': 'git_commit', 'workspace_id': '*', 'mode': 'ALLOW'},
    {'action': 'git_commit', 'workspace_id': None, 'mode': 'ALLOW'},
    {'action': 'git_commit', 'agent': 'unknown-agent', 'mode': 'ALLOW'},
    {'action': 'git_commit', 'agent': 'CODEX_REVIEW', 'mode': 'ALLOW'},
    {'action': 'git_commit', 'agent': 'codex_review', 'path': '/tmp', 'mode': 'ALLOW'},
    {'action': 'root_shell', 'agent': 'codex_review', 'mode': 'ALLOW'},
    {'action': 'git_commit', 'agent': 'codex_review', 'mode': []},
])
def test_invalid_scoped_rules_fail_closed(tmp_path, row):
    with pytest.raises(ValueError):
        policy(tmp_path, rows=[row])


@pytest.mark.parametrize('change', ['content', 'replace', 'permissions', 'delete', 'hardlink'])
def test_runtime_control_drift_refuses_even_previously_allowed_reads(tmp_path, change):
    p = policy(tmp_path)
    path = tmp_path / 'action-policy.yaml'
    if change == 'content':
        path.write_text('version: 1\naction_modes: {read_file: LOCKED}\n')
    elif change == 'replace':
        raw = path.read_bytes(); path.unlink(); path.write_bytes(raw); path.chmod(0o600)
    elif change == 'permissions':
        path.chmod(0o666)
    elif change == 'delete':
        path.unlink()
    else:
        import os
        os.link(path, tmp_path / 'alias')
    with pytest.raises(PermissionError):
        p.check('read_file', {'workspace_id': 'repo'})


def test_new_control_file_requires_restart(tmp_path):
    p = OperatorActionPolicy(tmp_path)
    policy(tmp_path)
    with pytest.raises(PermissionError, match='changed'):
        p.snapshot()


@pytest.mark.parametrize('mode', ['ALLOW', 'SCOPE', 'APPROVAL', 'LOCKED'])
def test_push_never_authorized_by_overrides_or_receipt(tmp_path, mode):
    p = policy(tmp_path, {'git_push': mode}, [
        {'action': 'git_push', 'workspace_id': 'repo', 'agent': 'codex_review', 'mode': mode}])
    assert p.effective_mode('git_push', workspace_id='repo', agent='codex_review') == 'LOCKED'
    with pytest.raises(PermissionError):
        p.check('git_push', {'workspace_id': 'repo', 'agent': 'codex_review', 'receipt': 'signed'})


@pytest.mark.parametrize('mode', ['LOCKED', 'APPROVAL'])
def test_writable_delegation_is_independent_of_commit_approval(tmp_path, mode):
    p = policy(tmp_path, rows=[{'action': 'git_commit', 'workspace_id': 'repo',
                              'agent': 'claude_agent', 'mode': mode}])
    args = {'workspace_id': 'repo', 'agent': 'claude_agent'}
    assert p.check('dispatch_agent', dict(args, read_only=False)) == 'SCOPE'
    with pytest.raises(PermissionError, match='independent owner approval'):
        p.check('dispatch_agent', dict(args, read_only=False, allow_commit=True))
    assert p.check('dispatch_agent', dict(args, read_only=True)) == 'SCOPE'
    assert p.check('write_file', args) == 'SCOPE'
    assert p.check('dispatch_agent', dict(args, agent='codex_impl', read_only=False)) == 'SCOPE'
    for invalid in (0, 1, 'false', None):
        with pytest.raises(PermissionError, match='boolean'):
            p.check('dispatch_agent', dict(args, read_only=invalid))


def test_real_mcp_and_rest_refuse_before_delegated_launch(temp_config, monkeypatch):
    policy(temp_config.config_dir, {'git_commit': 'LOCKED'})
    _, context = build_mcp_server(temp_config)
    args = {'workspace_id': 'demo', 'agent': 'claude_agent', 'task': 'write then commit', 'read_only': False, 'allow_commit': True}
    with pytest.raises(PermissionError, match='independent owner approval'):
        context['tools']['dispatch_agent'](**args)
    app = create_asgi_app(temp_config).app
    with pytest.raises(PermissionError, match='independent owner approval'):
        app.state.tools['dispatch_agent'](**args)


def test_authenticated_http_scoped_read_and_writable_dispatch_denied(temp_config):
    from fastapi.testclient import TestClient
    policy(temp_config.config_dir, rows=[
        {'action': 'read_file', 'workspace_id': 'demo', 'mode': 'LOCKED'},
        {'action': 'git_commit', 'workspace_id': 'demo', 'agent': 'claude_agent', 'mode': 'LOCKED'},
    ])
    temp_config.security.allowed_hosts.append('testserver')
    with TestClient(create_asgi_app(temp_config), base_url='http://testserver') as client:
        headers = {'Authorization': f'Bearer {temp_config.api_key}'}
        response = client.post('/api/v1/workspaces/demo/files/read', headers=headers,
                               json={'path': 'README.md'})
        assert response.status_code == 403
        response = client.post('/api/v1/workspaces/demo/agents/dispatch', headers=headers,
                               json={'agent': 'claude_agent', 'task': 'write then commit', 'read_only': False, 'allow_commit': True})
        assert response.status_code == 403
        assert 'independent owner approval' in response.json()['detail']


def test_unknown_caller_agent_is_permission_denial_not_config_error(tmp_path):
    p = OperatorActionPolicy(tmp_path)
    with pytest.raises(PermissionError, match='Unapproved'):
        p.check('dispatch_agent', {'workspace_id': 'demo', 'agent': 'codex'})
    with pytest.raises(ValueError):
        p.snapshot(agent='codex')
