import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('production_policy', Path(__file__).parents[2] / 'scripts/prepare-bcc-production-policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def documents():
    gateway = {'config.yaml': {}, 'workspaces.yaml': {'workspaces': {
        'repos': {'path': '/home/yeli/repos'},
        'project': {'path': '/home/yeli/repos/project', 'writable': True}}}}
    worker = {'config.yaml': {}, 'workspaces.yaml': {'workspaces': {}},
        'public-client-policy.yaml': {'version': 1, 'workspaces': {}},
        'development-runtime.yaml': {'profile': 'development', 'enabled': True,
            'network_enabled': True, 'egress_policy': 'provider_origin',
            'public_client_policy_required': True, 'allowed_workspace_roots': []}}
    return gateway, worker


def test_production_grants_commits_and_delegation_for_individual_projects_only():
    gateway, worker = documents()
    g, w = policy.prepare(gateway, worker)
    assert set(g['public-client-policy.yaml']['workspaces']) == {'project'}
    assert g['delegation-relay-write-scope.yaml'] == w['delegation-relay-write-scope.yaml']
    assert w['development-runtime.yaml']['production_relay_agents'] == policy.AGENTS
    assert g['action-policy.yaml']['action_modes'] == {'git_commit': 'SCOPE', 'git_push': 'LOCKED'}
    assert 'git_push' not in g['public-client-policy.yaml']['workspaces']['project']['operations']
    assert gateway['config.yaml'] == {}  # Pure transform; no caller data mutated.


@pytest.mark.parametrize('path', ['/home/yeli', '/etc', '/home/yeli/repos/../private', '/home/yeli/repos/project/child'])
def test_production_refuses_non_project_roots(path):
    g, w = documents()
    g['workspaces.yaml']['workspaces']['project']['path'] = path
    with pytest.raises(PermissionError):
        policy.prepare(g, w)


def test_production_refuses_existing_overlapping_worker_root():
    g, w = documents()
    w['development-runtime.yaml']['allowed_workspace_roots'] = [
        {'path': '/home/yeli/repos/project/child', 'writable': True}]
    with pytest.raises(PermissionError):
        policy.prepare(g, w)


def test_gateway_project_metadata_is_preserved_without_expanding_worker_special_caps():
    g,w=documents()
    g['workspaces.yaml']['workspaces']['project'].update(
        description='Existing scientific project',allow_venkata_ssh=True)
    planned,receiving=policy.prepare(g,w)
    assert planned['workspaces.yaml']['workspaces']['project']['description']=='Existing scientific project'
    assert planned['workspaces.yaml']['workspaces']['project']['allow_venkata_ssh'] is True
    assert 'allow_venkata_ssh' not in receiving['workspaces.yaml']['workspaces']['project']
