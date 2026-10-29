"""Production planning must not silently inherit legacy broad grants."""
import copy
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[2] / 'scripts/prepare-bcc-gateway-policy.py'
spec = importlib.util.spec_from_file_location('bcc_gateway_policy_plan', path)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def inputs():
    return {'config.yaml': {'server': {'public_url': 'https://existing.example/mcp'},
                            'security': {'header_name': 'X-AgentPorter-Key'}},
            'workspaces.yaml': {'workspaces': {
                'repos': {'path': '/home/yeli/repos', 'writable': True},
                'agentporter': {'path': '/home/yeli/repos/AgentPorter', 'writable': True,
                                'allow_agent_dispatch': True}}}}


def test_only_explicit_grants_change_and_ingress_is_preserved():
    original = inputs(); before = copy.deepcopy(original)
    grants = {'agentporter': ['read', 'write', 'exec', 'git_read', 'dispatch', 'dispatch_write']}
    result = plan.prepare(original, grants=grants)
    assert original == before
    assert result['config.yaml']['server'] == original['config.yaml']['server']
    assert result['config.yaml']['security'] == original['config.yaml']['security']
    assert result['config.yaml']['sandbox'] == {'workspace_transactions': True, 'network': False}
    assert set(result['public-client-policy.yaml']['workspaces']) == {'agentporter'}
    assert result['workspaces.yaml'] == original['workspaces.yaml']
    assert 'delegation-upstream.yaml' not in result
    assert 'internal-client.key' not in result


@pytest.mark.parametrize('name, operations', [('repos', ['read']), ('*', ['read']),
    ('missing', ['read']), ('agentporter', ['write', 'dispatch_write']),
    ('agentporter', ['unknown']), ('agentporter', ['read', 'read'])])
def test_implicit_or_inconsistent_grants_are_rejected(name, operations):
    with pytest.raises((ValueError, PermissionError)):
        plan.prepare(inputs(), grants={name: operations})


@pytest.mark.parametrize('field, operations', [('writable', ['write']),
    ('allow_execute', ['exec']), ('allow_git', ['git_read']),
    ('allow_agent_dispatch', ['dispatch'])])
def test_registry_denials_cannot_be_overridden(field, operations):
    documents = inputs()
    documents['workspaces.yaml']['workspaces']['agentporter'][field] = False
    with pytest.raises(PermissionError):
        plan.prepare(documents, grants={'agentporter': operations})


@pytest.mark.parametrize('name', ['development-runtime.yaml', 'public-client-policy.yaml', 'gateway-job-resources.yaml'])
def test_existing_profiles_require_reconciliation(name):
    documents = inputs(); documents[name] = {}
    with pytest.raises(PermissionError):
        plan.prepare(documents, grants={'agentporter': ['read']})


def test_result_loads_in_real_registry_scope_and_budget_parsers(tmp_path, monkeypatch):
    import yaml
    from agentporter.client_policy import PublicClientPolicy, PRINCIPAL
    from agentporter.resources import load_gateway_job_resources
    from agentporter.workspaces.registry import WorkspaceRegistry
    workspace = tmp_path / 'projects' / 'fixture'; workspace.mkdir(parents=True)
    monkeypatch.setattr(plan, 'REPOS', workspace.parent)
    documents = inputs()
    documents['workspaces.yaml']['workspaces']['agentporter']['path'] = str(workspace)
    grants = {'agentporter': ['read', 'write', 'exec']}
    result = plan.prepare(documents, grants=grants)
    config = tmp_path / 'config'; config.mkdir(mode=0o700)
    state = tmp_path / 'state'; state.mkdir(mode=0o700)
    for name, document in result.items():
        target = config / name
        target.write_text(yaml.safe_dump(document)); target.chmod(0o600)
    registry = WorkspaceRegistry(result['workspaces.yaml']['workspaces'])
    policy = PublicClientPolicy(config, state, registry, required=True)
    assert load_gateway_job_resources(config) == plan.BUDGET
    token = PRINCIPAL.set('public')
    try:
        policy.check('write_file', {'workspace_id': 'agentporter'})
        with pytest.raises(PermissionError):
            policy.check('write_file', {'workspace_id': 'repos'})
        policy.check('git_commit', {'workspace_id': 'agentporter'})
    finally:
        PRINCIPAL.reset(token)
