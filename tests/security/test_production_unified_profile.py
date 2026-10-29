"""Shared production references retain strict control-plane boundaries."""
import copy
import os
from pathlib import Path

import pytest
import yaml

from agentporter import workspace_policy
from agentporter.production_profile import load_production_profile
from test_production_profile import production, write


@pytest.fixture
def shared(production, tmp_path, monkeypatch):
    names = ['agentporter', 'repos', 'obsidian', 'asgard-hermes-review', 'cranary',
             'six', 'seven', 'eight', 'nine', 'ten', 'eleven']
    roots = {}
    for name in names:
        root = tmp_path / 'projects' / name
        root.mkdir(parents=True)
        roots[name] = {'path': str(root)}
    child = Path(roots['repos']['path']) / 'nested'
    child.mkdir()
    roots['six']['path'] = str(child)
    doc = {'version': 1,
           'workspace_defaults': dict(readable=True, writable=True, execute=True,
                                     git=True, artifacts=True, agent_dispatch=True),
           'delegation': dict(enabled_by_default=True, read_only_default=True,
                              writable_with_authorization=True),
           'approval': dict(commit='required', push='required', destructive_operations='required'),
           'workspaces': roots, 'workspace_overrides': {}}
    path = tmp_path / 'root-policy.yaml'
    monkeypatch.setattr(workspace_policy, 'SHARED_POLICY_PATH', path)
    monkeypatch.setattr(workspace_policy, 'TRUSTED_UID', os.getuid())
    ref = {'version': 2, 'policy_file': str(path)}

    def refresh():
        path.write_text(yaml.safe_dump(doc))
        path.chmod(0o600)
        production.workspace_policy = workspace_policy.load_workspace_policy(path)
        production.workspaces = copy.deepcopy(production.workspace_policy.workspaces)
    refresh()
    for name in ('workspaces.yaml', 'public-client-policy.yaml', 'delegation-upstream.yaml'):
        write(production, name, ref)
    write(production, 'action-policy.yaml', {'version': 1, 'action_modes': {'dispatch_agent': 'SCOPE'}})
    key = production.config_dir / 'delegation-relay.key'
    key.write_text('A' * 43 + '\n')
    key.chmod(0o600)
    return production, doc, path, refresh


def test_shared_all_eleven_writable_named_and_nested_roots(shared):
    config, _, _, _ = shared
    assert len(config.workspaces) == 11
    assert load_production_profile(config)['profile'] == 'production'


@pytest.mark.parametrize('filename', ['workspaces.yaml', 'public-client-policy.yaml', 'delegation-upstream.yaml'])
def test_shared_requires_identical_references(shared, filename):
    config, _, path, _ = shared
    write(config, filename, {'version': 2, 'policy_file': str(path) + '.other'})
    with pytest.raises(PermissionError):
        load_production_profile(config)


@pytest.mark.parametrize('stale', ['bindings', 'policy', 'missing_policy'])
def test_shared_rejects_stale_configuration(shared, stale):
    config, doc, path, _ = shared
    if stale == 'bindings':
        config.workspaces['cranary']['allow_execute'] = False
    elif stale == 'missing_policy':
        config.workspace_policy = None
    else:
        doc['workspace_defaults']['execute'] = False
        path.write_text(yaml.safe_dump(doc))
    with pytest.raises(PermissionError):
        load_production_profile(config)


def test_shared_rejects_untrusted_policy(shared):
    config, _, path, _ = shared
    path.chmod(0o666)
    with pytest.raises(PermissionError):
        load_production_profile(config)


@pytest.mark.parametrize('target', ['config', 'state', 'cache', 'active', 'policy'])
def test_shared_rejects_actual_control_path_overlap(shared, target):
    config, doc, path, refresh = shared
    targets = {'config': config.config_dir, 'state': config.state_dir,
               'cache': config.cache_dir, 'active': Path(__import__('agentporter.production_profile', fromlist=['x']).__file__).parent,
               'policy': path.parent}
    doc['workspaces']['agentporter']['path'] = str(targets[target])
    refresh()
    with pytest.raises(PermissionError):
        load_production_profile(config)


def test_shared_specialized_grants_never_spread(shared):
    config, doc, _, refresh = shared
    doc['workspaces']['cranary']['allow_scinet_diagnostic'] = True
    refresh()
    assert load_production_profile(config)['profile'] == 'production'
    doc['workspaces']['repos']['allow_scinet_diagnostic'] = True
    refresh()
    with pytest.raises(PermissionError):
        load_production_profile(config)


def test_legacy_protected_name_stays_readonly(production):
    production.workspaces['repos']['writable'] = True
    write(production, 'workspaces.yaml', {'workspaces': production.workspaces})
    with pytest.raises(PermissionError):
        load_production_profile(production)


@pytest.mark.parametrize('missing', ['write', 'dispatch', 'exec'])
def test_shared_dispatch_write_requires_all_public_grants(shared, monkeypatch, missing):
    config, _, _, _ = shared
    original = workspace_policy.WorkspacePolicy.public_scopes

    def scopes(self, registry):
        result = original(self, registry)
        result['cranary'].remove(missing)
        return result

    monkeypatch.setattr(workspace_policy.WorkspacePolicy, 'public_scopes', scopes)
    with pytest.raises(PermissionError):
        load_production_profile(config)


def test_shared_dispatch_requires_execute_permission(shared):
    config, doc, _, refresh = shared
    doc['workspace_overrides']['cranary'] = {
        'reason': 'Diagnostic-only fixture', 'capabilities': {'execute': False}}
    refresh()
    with pytest.raises(PermissionError):
        load_production_profile(config)


def test_shared_actual_protected_paths_reject_even_readonly_alias(shared):
    config, doc, _, refresh = shared
    doc['workspaces']['agentporter']['path'] = str(config.state_dir)
    doc['workspace_overrides']['agentporter'] = {
        'reason': 'Readonly control alias remains forbidden',
        'capabilities': dict(writable=False, execute=False, agent_dispatch=False)}
    refresh()
    with pytest.raises(PermissionError):
        load_production_profile(config)


@pytest.mark.parametrize('action', ['git_commit', 'git_push'])
def test_shared_keeps_commit_and_push_locked(shared, action):
    config, _, _, _ = shared
    write(config, 'action-policy.yaml', {'version': 1, 'action_modes': {
        'dispatch_agent': 'SCOPE', action: 'SCOPE'}})
    with pytest.raises(PermissionError):
        load_production_profile(config)
