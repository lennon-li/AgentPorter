"""Only one actually consumed signed tracking scope can extend private custody."""
import pytest

from agentporter.sandbox import git_metadata_custody as bridge,git_original_metadata as originals
from agentporter.sandbox.workspace_git_recovery import capture_git_baseline,_digest
from agentporter.git_pulls import validate_pull_authorization
from tests.security.test_approved_git_pull import backend,spent_authorization,git


def test_consumed_exact_tracking_ref_and_log_retain_original_inodes(tmp_path,monkeypatch):
    root,service,key,_,_=backend(tmp_path,monkeypatch)
    target='refs/remotes/origin/reviewed';git(root,'update-ref','--create-reflog',target,git(root,'rev-parse','HEAD'))
    _,authorization=spent_authorization(service,key)
    document=authorization.to_payload()
    paths=validate_pull_authorization(document,registry=service.registry,state_dir=service.sandbox.state_dir,
        owner_config_dir=service.authority._config_dir)
    storage=tmp_path/'tracking-custody';baseline=capture_git_baseline(root,tmp_path/'tracking-baseline')
    before={path:(root/'.git'/path).stat().st_ino for path in paths}
    originals.prepare(root,tmp_path/'tracking-baseline',baseline['sha256'],storage,
        approved_paths=paths,approval_sha256=_digest(document))
    for path in paths:
        originals.publish_before_copy(root,storage,path)
        assert (storage/('original-'+originals._key(path))/'captured').stat().st_ino==before[path]
        originals.restore_original(root,storage,path)
        assert (root/'.git'/path).stat().st_ino==before[path]
    with pytest.raises(PermissionError):originals.publish_before_copy(root,storage,'refs/remotes/other/reviewed')
    with pytest.raises(PermissionError):bridge._path('refs/remotes/other/reviewed',paths)
    assert bridge._path(target+'.lock',paths)==target+'.lock'


@pytest.mark.parametrize('paths',[
    ('refs/remotes/origin/*','logs/refs/remotes/origin/other'),
    ('refs/remotes/origin/*','logs/refs/remotes/origin/*'),
    ('refs/heads/main','logs/refs/heads/main'),
    ('refs/remotes/origin/../evil','logs/refs/remotes/origin/../evil'),
    ['refs/remotes/origin/main','logs/refs/remotes/origin/main'],
])
def test_tracking_scope_rejects_nonexact_or_mutable_allowlists(paths):
    with pytest.raises(PermissionError):bridge._approved_paths(paths)


@pytest.mark.parametrize('mode',['ff-only','merge','rebase'])
@pytest.mark.parametrize('stage',['refs_committed','head_published'])
def test_signed_tracking_native_crash_rolls_back_all_originals_and_exact_admission(tmp_path,monkeypatch,mode,stage):
    import os
    from tests.security.test_approved_git_pull import live_job,issue_git_approval
    from tests.security.custody.test_integration import stopped
    from agentporter.resources import ResourceCleanupError
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    root,service,key,manager,_=backend(tmp_path,monkeypatch)
    target='refs/remotes/origin/reviewed'
    git(root,'update-ref','--create-reflog',target,git(root,'rev-parse','HEAD'))
    baseline={str(path.relative_to(root/'.git')):path.stat().st_ino for path in (root/'.git').rglob('*')
              if path.is_file() and not path.is_relative_to(root/'.git/objects')}
    ordinary=(root/'ordinary').read_bytes();ordinary_inode=(root/'ordinary').stat().st_ino
    adapter,transaction=live_job(service)
    request=adapter.prepare('origin','refs/heads/reviewed',mode)
    result=adapter.pull('origin','refs/heads/reviewed',issue_git_approval(key,request),mode)
    assert result['candidate_status']=='integrated'
    marker="publication_event('"+stage+"')"
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
        with pytest.raises(ResourceCleanupError):transaction.publish_approved_pull()
    history=transaction.git_histories['.git'];stopped(transaction)
    connection=manager._get_db()
    try:
        with connection:connection.execute("UPDATE jobs SET status='cleanup_failed' WHERE job_id=?",(adapter.job_id,))
    finally:connection.close()
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    # Guard-selected configuration never substitutes for trusted caller context.
    refused=recovery.recover_workspace(service.sandbox.state_dir,root)
    assert not refused['git'][0]['inspection']['apply_supported']
    plan=recovery.recover_workspace(service.sandbox.state_dir,root,pull_registry=service.registry,
        pull_owner_config_dir=service.authority._config_dir)
    inspected=plan['git'][0]['inspection'];assert inspected['apply_supported'],inspected
    assert inspected['metadata_approved_paths']==[target,'logs/'+target]
    result=recovery.recover_workspace(service.sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'],pull_registry=service.registry,
        pull_owner_config_dir=service.authority._config_dir)
    assert result['status']=='recovered' and result['endpoint']=='before'
    assert (root/'ordinary').read_bytes()==ordinary and (root/'ordinary').stat().st_ino==ordinary_inode
    for path,inode in baseline.items():assert (root/'.git'/path).stat().st_ino==inode,path
    connection=manager._get_db()
    try:
        assert connection.execute('SELECT status FROM jobs WHERE job_id=?',(adapter.job_id,)).fetchone()[0]=='recovered'
        assert connection.execute('SELECT status FROM git_admissions WHERE token=?',(adapter.token,)).fetchone()[0]=='resolved'
        assert not connection.execute('SELECT 1 FROM job_admissions WHERE token=?',(adapter.token,)).fetchone()
    finally:connection.close()
    service.verifier.assert_consumed(inspected['approved_pull']['authorization']['approval_nonce'],request)
    assert not transaction._pending.exists() and not history.guard.exists()


@pytest.mark.parametrize('point',['after_guard_capture','after_admission_resolution'])
def test_signed_pull_missing_normal_guards_resume_before_bundle_done(tmp_path,monkeypatch,point):
    import os
    from tests.security.test_approved_git_pull import live_job,issue_git_approval
    from tests.security.custody.test_integration import stopped
    from agentporter.sandbox import workspace_recovery as recovery,recovery_guards
    from agentporter.git_pulls import _PullPublicationIntent
    root,service,key,manager,_=backend(tmp_path,monkeypatch)
    adapter,transaction=live_job(service)
    request=adapter.prepare('origin','refs/heads/reviewed','merge')
    adapter.pull('origin','refs/heads/reviewed',issue_git_approval(key,request),'merge')
    child=os.fork()
    if child==0:
        if point=='after_guard_capture':
            _PullPublicationIntent.resolve_after_publication=lambda self:os._exit(73)
        else:
            original=recovery_guards._write
            def write(base,name,value):
                if name=='done.json':os._exit(73)
                return original(base,name,value)
            recovery_guards._write=write
        try:transaction.publish_approved_pull()
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    stopped(transaction)
    connection=manager._get_db()
    try:
        with connection:connection.execute("UPDATE jobs SET status='cleanup_failed' WHERE job_id=?",(adapter.job_id,))
    finally:connection.close()
    assert not transaction._pending.exists()
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recovery.recover_workspace(service.sandbox.state_dir,root,pull_registry=service.registry,
        pull_owner_config_dir=service.authority._config_dir)
    assert plan['git'][0]['inspection']['apply_supported'],plan
    result=recovery.recover_workspace(service.sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'],pull_registry=service.registry,
        pull_owner_config_dir=service.authority._config_dir)
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    connection=manager._get_db()
    try:
        assert connection.execute('SELECT status FROM git_admissions WHERE token=?',(adapter.token,)).fetchone()[0]=='resolved'
        assert not connection.execute('SELECT 1 FROM job_admissions WHERE token=?',(adapter.token,)).fetchone()
    finally:connection.close()
