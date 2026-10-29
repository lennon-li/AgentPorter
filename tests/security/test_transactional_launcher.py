"""Production edits publish only after verified process cleanup and success."""
from pathlib import Path
from types import SimpleNamespace
import time
import pytest
from agentporter.agents.development import DevelopmentRuntime, PreparedLaunch
from agentporter.scoped_approvals import VerifiedGrant
from agentporter.task_authorization import ACTIVE_GRANT
from agentporter.workspace_policy import SHARED_POLICY_PATH
from agentporter.tools.jobs import JobManager

@pytest.fixture
def staged_runtime(tmp_path, monkeypatch):
    # These tests isolate JobManager finalization from the view service. Actual
    # copy-on-write mounts and namespace wiring have their own integration tests.
    from agentporter.workspace_transactions import WorkspaceTransaction
    monkeypatch.setattr('agentporter.workspace_views.CowWorkspaceTransaction', WorkspaceTransaction)
    source=tmp_path/'source'; source.mkdir(); (source/'file.txt').write_text('before')
    shared=SimpleNamespace(protected_paths=(), workspaces={'test':{'path':str(source)}},
        capabilities=lambda name: {'writable':True})
    registry=SimpleNamespace(workspace_policy=shared, list_all=lambda:[{'workspace_id':'test','path':str(source),'writable':True}])
    runtime=DevelopmentRuntime(tmp_path/'config',tmp_path/'state',registry)
    config={'service_unit':'agentporter-worker.service','workspace_policy_file':str(SHARED_POLICY_PATH)}
    monkeypatch.setattr(runtime,'_verified',lambda agent:(config,{}))
    monkeypatch.setattr(runtime,'_workspace',lambda *args:source)
    monkeypatch.setattr(runtime,'_build',lambda agent,config,spec,workspace,writable,cmd,**kwargs:
        PreparedLaunch([str(workspace)],lambda:None))
    return runtime,source

def grant(source, **overrides):
    claims={'workspace_root':str(source),'agent':'jax','operations':['write'],'grant_id':'testgrant','expires_at':int(time.time())+60}
    claims.update(overrides)
    return VerifiedGrant(claims)

def test_production_write_requires_verified_grant(staged_runtime):
    runtime,source=staged_runtime
    with pytest.raises(PermissionError,match='grant'):
        runtime.prepare('jax',str(source),True,['worker'])

@pytest.mark.parametrize('success',[False,True])
def test_staged_edit_only_publishes_on_success(staged_runtime,success):
    runtime,source=staged_runtime
    token=ACTIVE_GRANT.set(grant(source))
    try: prepared=runtime.prepare('jax',str(source),True,['worker'])
    finally: ACTIVE_GRANT.reset(token)
    stage=Path(prepared.command[0]); assert stage != source
    (stage/'file.txt').write_text('after')
    assert (source/'file.txt').read_text()=='before'
    prepared.finalize(success)
    assert (source/'file.txt').read_text()==('after' if success else 'before')
    assert not stage.exists()
    prepared.cleanup()

@pytest.mark.parametrize('override',[{'workspace_root':'/other'},{'agent':'liz'},{'operations':['read']}])
def test_mismatched_grant_denied(staged_runtime,override):
    runtime,source=staged_runtime; token=ACTIVE_GRANT.set(grant(source,**override))
    try:
        with pytest.raises(PermissionError,match='grant'):
            runtime.prepare('jax',str(source),True,['worker'])
    finally: ACTIVE_GRANT.reset(token)

def test_unapproved_deletion_rolls_back_and_cleans_stage(staged_runtime):
    runtime,source=staged_runtime; token=ACTIVE_GRANT.set(grant(source))
    try: prepared=runtime.prepare('jax',str(source),True,['worker'])
    finally: ACTIVE_GRANT.reset(token)
    stage=Path(prepared.command[0]); (stage/'file.txt').unlink()
    with pytest.raises(Exception,match='deletion'):
        prepared.finalize(True)
    assert (source/'file.txt').read_text()=='before'
    assert not stage.exists()

def test_read_only_and_legacy_do_not_stage(staged_runtime,monkeypatch):
    runtime,source=staged_runtime
    assert runtime.prepare('jax',str(source),False,['worker']).command==[str(source)]
    runtime.workspace_registry.workspace_policy=None
    assert runtime.prepare('jax',str(source),True,['worker']).command==[str(source)]

class Lease:
    def __init__(self,events,fail=False): self.events=events; self.fail=fail
    def command(self,command): return command
    def terminate(self): self.events.append('terminate')
    def close(self):
        self.events.append('lease-close')
        if self.fail: raise RuntimeError('cleanup unverified')

def wait_for_job(manager,job):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        status=manager.get_status(job)
        if status['status'] in {'completed','failed','cancelled','cleanup_failed','timed_out','output_limit_exceeded'}: return status
        time.sleep(.01)
    raise AssertionError('job did not finish')

@pytest.mark.parametrize('exit_code,raises,expected',[(0,False,'completed'),(2,False,'failed'),(0,True,'failed')])
def test_job_finalizes_only_after_cleanup(tmp_path,exit_code,raises,expected):
    import sys
    events=[]; manager=JobManager(tmp_path/'jobs')
    manager.resources=SimpleNamespace(create=lambda:Lease(events))
    def finalize(success):
        events.append(('finalize',success))
        if raises: raise ValueError('publication validation failed')
    job=manager._start_process_job(command=[sys.executable,'-c',f'raise SystemExit({exit_code})'],
        workspace_id='original',workspace_path=str(tmp_path),receipt=['test'],timeout_seconds=5,
        finalize=finalize,cleanup=lambda:events.append('stage-cleanup'))
    assert wait_for_job(manager,job)['status']==expected
    assert events==['lease-close',('finalize',exit_code==0),'stage-cleanup']

@pytest.mark.parametrize('cancel',[False,True])
def test_timeout_and_cancellation_do_not_publish(tmp_path,cancel):
    import sys
    events=[]; manager=JobManager(tmp_path/'jobs'); manager.resources=SimpleNamespace(create=lambda:Lease(events))
    job=manager._start_process_job(command=[sys.executable,'-c','import time; time.sleep(20)'],
        workspace_id='original',workspace_path=str(tmp_path),receipt=['test'],timeout_seconds=.05 if not cancel else 5,
        finalize=lambda success:events.append(('finalize',success)),cleanup=lambda:events.append('stage-cleanup'))
    if cancel: manager.cancel(job)
    assert wait_for_job(manager,job)['status']==('cancelled' if cancel else 'timed_out')
    assert ('finalize',False) in events
    assert events.index('lease-close')<events.index(('finalize',False))<events.index('stage-cleanup')

def test_unverified_cleanup_does_not_publish(tmp_path):
    import sys
    events=[]; manager=JobManager(tmp_path/'jobs'); manager.resources=SimpleNamespace(create=lambda:Lease(events,True))
    job=manager._start_process_job(command=[sys.executable,'-c','pass'],workspace_id='original',
        workspace_path=str(tmp_path),receipt=['test'],timeout_seconds=5,
        finalize=lambda success:events.append(('finalize',success)))
    assert wait_for_job(manager,job)['status']=='cleanup_failed'
    assert events==['lease-close',('finalize',False)]

def test_failed_start_discards_stage(tmp_path):
    events=[]; manager=JobManager(tmp_path/'jobs')
    with pytest.raises(FileNotFoundError):
        manager._start_process_job(command=['/missing-test-executable'],workspace_id='original',
            workspace_path=str(tmp_path),receipt=['test'],timeout_seconds=5,
            finalize=lambda success:events.append(('finalize',success)),cleanup=lambda:events.append('stage-cleanup'))
    assert events==[('finalize',False),'stage-cleanup']

def test_shared_defaults_and_parent_nested_workspace(staged_runtime,monkeypatch):
    runtime,source=staged_runtime; child=source/'nested'; child.mkdir()
    entries=[{'workspace_id':name,'path':str(path),'writable':True,
        'permissions':{'agent_dispatch':True,'execute':True}} for name,path in [('test',source),('child',child)]]
    runtime.workspace_registry.list_all=lambda:entries
    monkeypatch.undo()  # Exercise the real workspace validator.
    config={'service_unit':'agentporter-worker.service','workspace_policy_file':str(SHARED_POLICY_PATH),
        'workers':{'jax':{'credentials':{}}}}
    derived=runtime._shared_config(config)
    assert derived['allowed_workspace_roots']==[{'path':str(source),'writable':True},{'path':str(child),'writable':True}]
    assert derived['production_relay_agents']==['jax']
    assert runtime._workspace(str(source),True,config)==source
    assert runtime._workspace(str(child),True,config)==child
    config.pop('workspace_policy_file')
    with pytest.raises(PermissionError,match='shared workspace policy'):
        runtime._shared_config(config)

def test_original_git_metadata_is_pinned_read_only(tmp_path):
    source=tmp_path/'source'; source.mkdir(); stage=tmp_path/'stage';stage.mkdir()
    (source/'.git').mkdir(); (source/'nested').mkdir();(source/'nested/.git').mkdir()
    (source/'.env').write_text('secret')
    runtime=DevelopmentRuntime(tmp_path/'config',tmp_path/'state',SimpleNamespace())
    prepared=runtime._build('fixture',{}, {'executable':'/usr/bin/true','credentials':{}},stage,True,
        ['/usr/bin/true'],source_workspace=source)
    try:
        args=prepared.command
        for target in ['/workspace/.git','/workspace/nested/.git']:
            index=args.index(target)
            assert args[index-2]=='--ro-bind'
            assert Path(args[index-1]).resolve()==source/target.removeprefix('/workspace/')
        index=args.index('/workspace'); assert args[index-2]=='--bind'
        assert Path(args[index-1]).resolve()==stage
        index=args.index('/workspace/.env')
        assert args[index-2]=='--ro-bind'
        assert Path(args[index-1]).read_text()==''
    finally:prepared.cleanup()

def test_git_mount_placeholders_removed_before_publication(staged_runtime):
    runtime,source=staged_runtime
    (source/'.git').mkdir();(source/'.git/config').write_text('original-git')
    token=ACTIVE_GRANT.set(grant(source))
    try:prepared=runtime.prepare('jax',str(source),True,['worker'])
    finally:ACTIVE_GRANT.reset(token)
    stage=Path(prepared.command[0]);assert not (stage/'.git').exists()
    (stage/'.git').mkdir()  # Host-side empty target left by the namespace mount.
    (stage/'file.txt').write_text('after')
    prepared.finalize(True)
    assert (source/'file.txt').read_text()=='after'
    assert (source/'.git/config').read_text()=='original-git'

def test_real_staged_namespace_preserves_original_git(staged_runtime,monkeypatch):
    import subprocess
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE: pytest.skip('Bubblewrap unavailable')
    runtime,source=staged_runtime
    (source/'.git').mkdir();(source/'.git/config').write_text('original-git')
    (source/'nested').mkdir();(source/'nested/.git').mkdir();(source/'nested/.git/config').write_text('nested-git')
    config={'service_unit':'agentporter-worker.service','workspace_policy_file':str(SHARED_POLICY_PATH)}
    monkeypatch.setattr(runtime,'_verified',lambda agent:(config,{'executable':str(Path('/usr/bin/python3').resolve()),'credentials':{}}))
    monkeypatch.setattr(runtime,'_build',DevelopmentRuntime._build.__get__(runtime))
    code="""from pathlib import Path
assert Path('.git/config').read_text() == 'original-git'
assert Path('nested/.git/config').read_text() == 'nested-git'
for name in ['.git/config','nested/.git/config']:
    try: Path(name).write_text('forbidden')
    except OSError: pass
    else: raise AssertionError('Git metadata writable')
Path('file.txt').write_text('after')
"""
    token=ACTIVE_GRANT.set(grant(source,agent='fixture'))
    try:prepared=runtime.prepare('fixture',str(source),True,['/usr/bin/python3','-c',code])
    finally:ACTIVE_GRANT.reset(token)
    try:
        completed=subprocess.run(prepared.command,pass_fds=prepared.pass_fds,capture_output=True,text=True,timeout=10)
        assert completed.returncode==0,completed.stderr
        assert (source/'file.txt').read_text()=='before'
        prepared.finalize(True)
        assert (source/'file.txt').read_text()=='after'
        assert (source/'.git/config').read_text()=='original-git'
        assert (source/'nested/.git/config').read_text()=='nested-git'
    finally:prepared.cleanup()

@pytest.mark.parametrize('protected_by',['path','readonly-child'])
def test_parent_grant_cannot_edit_protected_descendants(staged_runtime,protected_by):
    runtime,source=staged_runtime
    child=source/'nested';child.mkdir();(child/'file.txt').write_text('protected')
    shared=runtime.workspace_registry.workspace_policy
    if protected_by=='path':shared.protected_paths=(child,)
    else:
        shared.workspaces['child']={'path':str(child)}
        shared.capabilities=lambda name:{'writable':name!='child'}
    token=ACTIVE_GRANT.set(grant(source))
    try:prepared=runtime.prepare('jax',str(source),True,['worker'])
    finally:ACTIVE_GRANT.reset(token)
    stage=Path(prepared.command[0]);(stage/'nested/file.txt').write_text('forbidden')
    with pytest.raises(Exception,match='writable policy'):prepared.finalize(True)
    assert (child/'file.txt').read_text()=='protected'
    assert not stage.exists()

def test_expired_verified_context_cannot_launch(staged_runtime):
    runtime,source=staged_runtime;token=ACTIVE_GRANT.set(grant(source,expires_at=int(time.time())-1))
    try:
        with pytest.raises(PermissionError,match='grant'):runtime.prepare('jax',str(source),True,['worker'])
    finally:ACTIVE_GRANT.reset(token)

def test_git_placeholder_ancestor_symlink_cannot_escape_stage(staged_runtime,tmp_path):
    runtime,source=staged_runtime
    nested=source/'nested';nested.mkdir();(nested/'.git').mkdir()
    outside=tmp_path/'outside';outside.mkdir();(outside/'.git').mkdir()
    token=ACTIVE_GRANT.set(grant(source))
    try:prepared=runtime.prepare('jax',str(source),True,['worker'])
    finally:ACTIVE_GRANT.reset(token)
    stage=Path(prepared.command[0]);(stage/'nested').rmdir();(stage/'nested').symlink_to(outside)
    with pytest.raises(OSError):prepared.finalize(True)
    assert (outside/'.git').is_dir()
    assert not stage.exists()
