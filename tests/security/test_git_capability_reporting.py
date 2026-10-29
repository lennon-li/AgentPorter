"""Git capability discovery must not imply locked operations can run."""
from agentporter.server import build_mcp_server


def test_git_capabilities_report_backend_and_workspace_constraints(temp_config):
    _, context = build_mcp_server(temp_config)
    caps = context['tools']['get_capabilities']()
    status = caps['git_operations']
    for name in ('git_status', 'git_diff', 'git_log', 'git_show', 'git_branch'):
        assert status[name]['availability'] == 'conditional'
        assert status[name]['required_scope'] == 'git_read'
    for name in ('git_add', 'git_checkout'):
        assert status[name]['availability'] == 'conditional'
        assert status[name]['required_scope'] == 'git_write'
    for name in ('git_commit', 'git_push', 'git_fetch', 'git_pull'):
        assert status[name]['availability'] == 'unavailable'
        assert status[name]['reason']
    assert status['git_commit']['operation_mode'] == 'LOCKED'
    assert status['git_fetch']['operation_mode'] == 'APPROVAL'
    assert 'read-only' in caps['git_shell_metadata']


def test_git_capabilities_reflect_stricter_operator_override(temp_config):
    policy = temp_config.config_dir / 'action-policy.yaml'
    policy.write_text('version: 1\naction_modes:\n  git_add: LOCKED\n')
    policy.chmod(0o600)
    _, context = build_mcp_server(temp_config)
    status = context['tools']['get_capabilities']()['git_operations']['git_add']
    assert status['operation_mode'] == 'LOCKED'
    assert status['availability'] == 'unavailable'


def test_shared_default_fetch_is_scoped_and_explicit_stricter_override_is_preserved(tmp_path):
    import pytest
    from agentporter.action_policy import OperatorActionPolicy
    policy = OperatorActionPolicy(tmp_path, workspace_policy=object())
    assert policy.effective_mode('git_fetch') == 'SCOPE'
    assert policy.check('git_fetch', {'workspace_id': 'project'}) == 'SCOPE'
    path = tmp_path / 'action-policy.yaml'
    path.write_text('version: 1\naction_modes:\n  git_fetch: APPROVAL\n'); path.chmod(0o600)
    policy = OperatorActionPolicy(tmp_path, workspace_policy=object())
    with pytest.raises(PermissionError): policy.check('git_fetch', {'workspace_id': 'project'})
