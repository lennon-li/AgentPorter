import os
from pathlib import Path

import pytest
import yaml

from agentporter import workspace_policy as policy
from agentporter.workspaces.registry import WorkspaceRegistry


@pytest.fixture
def document(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, 'TRUSTED_UID', os.getuid())
    roots = {}
    for i in range(11):
        root = tmp_path / f'project-{i}'
        root.mkdir()
        roots[f'project-{i}'] = {'path': str(root)}
    doc = {
        'version': 1,
        'workspace_defaults': dict(readable=True, writable=True, execute=True,
                                   git=True, artifacts=True, agent_dispatch=True),
        'delegation': dict(enabled_by_default=True, read_only_default=True,
                           writable_with_authorization=True),
        'approval': dict(commit='required', push='required', destructive_operations='required'),
        'workspaces': roots,
        'workspace_overrides': {},
    }
    path = tmp_path / 'policy.yaml'
    def load():
        path.write_text(yaml.safe_dump(doc))
        path.chmod(0o600)
        return policy.load_workspace_policy(path)
    return doc, path, load


def test_all_eleven_and_new_registration_inherit_one_default(document, tmp_path):
    doc, _, load = document
    shared = load()
    registry = WorkspaceRegistry(shared.workspaces, workspace_policy=shared)
    assert len(registry.list_all()) == 11
    new = tmp_path / 'new'; new.mkdir()
    registry.register('new', str(new))
    for row in registry.list_all():
        assert all(row['permissions'][k] for k in ('execute', 'git', 'artifacts', 'agent_dispatch'))
        assert row['writable']
        assert not row['permissions']['scinet_training']
        assert not row['permissions']['venkata_ssh']
    scopes = shared.public_scopes(registry)
    assert set(scopes) == set(doc['workspaces']) | {'new'}
    assert all({'read','write','exec','git_read','git_fetch','dispatch','dispatch_write'} <= ops
               for ops in scopes.values())
    assert all('git_write' not in ops for ops in scopes.values())


def test_documented_exception_is_applied_and_auditable(document):
    doc, _, load = document
    doc['workspace_overrides']['project-0'] = {
        'reason': 'Protected control-plane fixture',
        'capabilities': {'writable': False, 'execute': False},
    }
    shared = load()
    assert not shared.workspaces['project-0']['writable']
    assert not shared.workspaces['project-0']['allow_execute']
    assert shared.exceptions()['project-0']['reason'] == 'Protected control-plane fixture'


def test_exception_requires_nonempty_reason(document):
    doc, _, load = document
    doc['workspace_overrides']['project-0'] = {'capabilities': {'writable': False}}
    with pytest.raises((PermissionError, ValueError)):
        load()


def test_no_implicit_specialized_infrastructure_access(document):
    doc, _, load = document
    doc['workspaces']['project-0']['allow_scinet_training'] = True
    shared = load()
    scopes = shared.public_scopes(WorkspaceRegistry(shared.workspaces, workspace_policy=shared))
    assert 'scinet_training' in scopes['project-0']
    assert all('scinet_training' not in scopes[k] for k in scopes if k != 'project-0')


@pytest.mark.parametrize('change', ['loose_mode','wrong_owner','symlink','duplicate','unknown_default','weaken_approval'])
def test_unsafe_policy_fails_closed(document, monkeypatch, change):
    doc, path, load = document
    if change == 'unknown_default': doc['workspace_defaults']['allow_scinet_training'] = True
    if change == 'weaken_approval': doc['approval']['push'] = 'optional'
    if change in ('unknown_default','weaken_approval'):
        with pytest.raises((PermissionError, ValueError)): load()
        return
    load()
    if change == 'loose_mode': path.chmod(0o666)
    if change == 'wrong_owner': monkeypatch.setattr(policy,'TRUSTED_UID',os.getuid()+1)
    if change == 'symlink':
        other=path.with_suffix('.real');path.rename(other);path.symlink_to(other)
    if change == 'duplicate': path.write_text(path.read_text()+'version: 1\n')
    with pytest.raises((PermissionError, ValueError)): policy.load_workspace_policy(path)


def test_parent_workspace_cannot_bypass_explicit_child_exception(document, tmp_path):
    doc, _, load = document
    parent=tmp_path/'parent'; child=parent/'child';child.mkdir(parents=True)
    doc['workspaces'].update(parent={'path':str(parent)},child={'path':str(child)})
    doc['workspace_overrides']['child']={'reason':'Owner explicitly denied edits','capabilities':{'writable':False}}
    shared=load()
    with pytest.raises(PermissionError): shared.check_path('parent',child/'file.txt','write')
    shared.check_path('parent',parent/'allowed.txt','write')


def test_protected_service_controls_are_not_workspace_writable(document, tmp_path):
    doc, _, load = document
    control=tmp_path/'control';control.mkdir()
    doc['protected_paths']=[str(control)]
    doc['workspaces']['parent']={'path':str(tmp_path)}
    shared=load()
    with pytest.raises(PermissionError):shared.check_path('parent',control/'policy.yaml','write')


@pytest.mark.parametrize('production_scinet', [False, True])
def test_explicit_shared_reference_loads_config_and_public_policy(document, tmp_path, monkeypatch, production_scinet):
    from agentporter.config import Config
    from agentporter.client_policy import PublicClientPolicy, PRINCIPAL
    doc, path, load = document
    doc['workspaces']['project-0']['allow_scinet_training'] = True
    shared = load()
    monkeypatch.setattr(policy, 'SHARED_POLICY_PATH', path)
    config_dir = tmp_path/'gateway';config_dir.mkdir(mode=0o700)
    ref={'version':2,'policy_file':str(path)}
    for filename in ('workspaces.yaml','public-client-policy.yaml'):
        f=config_dir/filename;f.write_text(yaml.safe_dump(ref));f.chmod(0o600)
    config=Config(config_dir=config_dir,state_dir=tmp_path/'state',cache_dir=tmp_path/'cache')
    registry=WorkspaceRegistry(config.workspaces,workspace_policy=config.workspace_policy)
    public=PublicClientPolicy(config_dir,config.state_dir,registry,required=True,
                              allow_production_scinet=production_scinet)
    assert len(public.scopes)==11
    assert ('scinet_training' in public.scopes['project-0']) is production_scinet
    assert shared.workspaces['project-0']['allow_scinet_training'] is True
    new=tmp_path/'later';new.mkdir();registry.register('later',str(new))
    assert 'dispatch_write' in public.scopes['later']
    token=PRINCIPAL.set('public')
    try:
        public.check('write_file',{'workspace_id':'later','path':'code.py'})
        result = {'job_id': 'rjob_' + 'a' * 32}
        for _ in range(2):
            assert public.result('dispatch_agent', {'workspace_id': 'project-0'}, result) == result
        with pytest.raises(PermissionError):
            public.result('dispatch_agent', {'workspace_id': 'project-1'}, result)
    finally: PRINCIPAL.reset(token)


def test_legacy_profile_dispatch_default_is_unchanged(tmp_path):
    registry=WorkspaceRegistry({'legacy':{'path':str(tmp_path)}})
    assert registry.get('legacy').allow_agent_dispatch is False


def test_other_services_private_control_paths_remain_protected_without_traversal(document, tmp_path):
    doc, _, load = document
    private = tmp_path / 'private-controls'; private.mkdir()
    child = private / 'nested'; child.mkdir()
    doc['protected_paths'] = [str(child)]
    private.chmod(0)
    try:
        shared = load()
        assert shared.protected_paths == (child,)
    finally: private.chmod(0o700)
