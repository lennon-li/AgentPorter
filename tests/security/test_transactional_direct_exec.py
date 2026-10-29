from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentporter.task_authorization import ACTIVE_GRANT
from agentporter.scoped_approvals import VerifiedGrant
from agentporter.tools import execution
from agentporter.workspaces.registry import WorkspaceRegistry


@pytest.fixture
def direct(tmp_path,monkeypatch):
    from agentporter.workspace_transactions import WorkspaceTransaction
    monkeypatch.setattr('agentporter.workspace_views.CowWorkspaceTransaction', WorkspaceTransaction)
    root=tmp_path/'source';root.mkdir();(root/'code.py').write_text('old')
    registry=WorkspaceRegistry({'project':{'path':str(root),'allow_execute':True}})
    registry.workspace_policy=SimpleNamespace(protected_paths=(),workspaces={'project':{'path':str(root)}},
        capabilities=lambda name:{'writable':True})
    state=tmp_path/'state';state.mkdir(mode=0o700)
    manager=SimpleNamespace(state_dir=state)
    calls=[]
    def run(**kw):
        calls.append(kw)
        target=Path(kw['workspace_path'])/'code.py'
        if kw['argv']==['edit'] and kw['writable']:target.write_text('new')
        if kw['argv']==['delete'] and kw['writable']:target.unlink()
        if kw['argv']==['edit-protected'] and kw['writable']:
            (Path(kw['workspace_path'])/'restricted'/'data').write_text('changed')
        return {'exit_code':0,'stdout':'ok','stderr':'','timed_out':False,'truncated':False}
    sandbox=SimpleNamespace(run=run,resources=object())
    monkeypatch.setattr(execution,'synchronous_slot',lambda _:nullcontext())
    return execution.create_execution_tools(registry,sandbox,manager)[0],root,calls,registry


def grant(root,operations=('write',)):
    return VerifiedGrant({'grant_id':'a'*32,'workspace_root':str(root),'operations':list(operations)})


def test_shared_execution_defaults_read_only(direct):
    run,root,calls,_=direct
    run('project',['edit'])
    assert calls[-1]['writable'] is False
    assert (root/'code.py').read_text()=='old'


def test_writable_command_requires_verified_grant(direct):
    run,root,_,_=direct
    with pytest.raises(PermissionError):run('project',['edit'],read_only=False)
    assert (root/'code.py').read_text()=='old'


def test_authorized_command_applies_transaction(direct):
    run,root,calls,_=direct;reset=ACTIVE_GRANT.set(grant(root))
    try:result=run('project',['edit'],read_only=False)
    finally:ACTIVE_GRANT.reset(reset)
    assert calls[-1]['workspace_path']!=str(root)
    assert (root/'code.py').read_text()=='new'
    assert result['workspace_changes']['written']==['code.py']


def test_unapproved_deletion_leaves_source_unchanged(direct):
    run,root,_,_=direct;reset=ACTIVE_GRANT.set(grant(root))
    try:
        with pytest.raises((ValueError,PermissionError)):run('project',['delete'],read_only=False)
    finally:ACTIVE_GRANT.reset(reset)
    assert (root/'code.py').read_text()=='old'


def test_unrelated_protected_control_root_does_not_block_authorized_edit(direct, tmp_path):
    run,root,_,registry=direct
    controls=tmp_path/'controls';controls.mkdir()
    registry.workspace_policy.protected_paths=(controls,)
    reset=ACTIVE_GRANT.set(grant(root))
    try:run('project',['edit'],read_only=False)
    finally:ACTIVE_GRANT.reset(reset)
    assert (root/'code.py').read_text()=='new'


@pytest.mark.parametrize('restriction',['protected_path','child_exception'])
def test_protected_descendant_edit_never_publishes(direct, restriction):
    run,root,_,registry=direct
    child=root/'restricted';child.mkdir();(child/'data').write_text('original')
    policy=registry.workspace_policy
    if restriction=='protected_path':
        policy.protected_paths=(child,)
    else:
        policy.workspaces['restricted']={'path':str(child)}
        policy.capabilities=lambda name:{'writable':name!='restricted'}
    reset=ACTIVE_GRANT.set(grant(root))
    try:
        with pytest.raises(PermissionError):run('project',['edit-protected'],read_only=False)
    finally:ACTIVE_GRANT.reset(reset)
    assert (child/'data').read_text()=='original'


@pytest.mark.parametrize('ancestor',[False,True])
def test_protected_workspace_or_ancestor_rejects_before_execution(direct, ancestor):
    run,root,calls,registry=direct
    registry.workspace_policy.protected_paths=(root.parent if ancestor else root,)
    reset=ACTIVE_GRANT.set(grant(root))
    try:
        with pytest.raises(PermissionError):run('project',['edit'],read_only=False)
    finally:ACTIVE_GRANT.reset(reset)
    assert not calls
    assert (root/'code.py').read_text()=='old'
