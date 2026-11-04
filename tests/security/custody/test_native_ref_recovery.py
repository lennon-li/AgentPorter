"""Actual native ref FD provenance, coherent original-inode crash recovery."""
import os
import stat

import pytest

from agentporter.sandbox import workspace_git_recovery as raw


def interrupted(tmp_path,monkeypatch,stage):
    from tests.security.custody.test_git_raw import unchanged_git_interruption
    return unchanged_git_interruption(tmp_path,monkeypatch,stage)


@pytest.mark.parametrize('stage',['refs_prepared','refs_commit_intent','refs_committed','index_published','head_published','cleanup_finished'])
def test_existing_branch_native_mutation_recovers_all_original_inodes(tmp_path,monkeypatch,stage):
    from agentporter.sandbox import workspace_recovery as recovery
    from tests.security.custody.test_integration import assert_jobs
    root,sandbox,tx,guard,manager,history=interrupted(tmp_path,monkeypatch,stage)
    baseline=history.raw_baseline['manifest']
    native=raw.inspect_native_git_phases(root,history.native_events,raw._digest(history.plan))
    assert history.plan['before']['branch'] in native['events'][-1]['bindings']
    original={path:record['identity'][1] for path,record in baseline['files'].items()}
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    inspection=plan['git'][0]['inspection']
    assert inspection['apply_supported'],inspection
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and result['endpoint']=='before'
    assert (root/'ordinary').read_text()=='initial'
    for path,inode in original.items():
        assert (root/'.git'/path).stat().st_ino==inode,path
    assert not guard.exists() and not tx._pending.exists()
    assert_jobs(manager)
    assert inspection['directory_timestamp_policy'].startswith('retain_current_times')


def test_native_ref_binding_is_retained_created_fd_not_after_observation(tmp_path):
    from tests.security.custody.test_git_raw import imported_history
    root,history=imported_history(tmp_path)
    try:
        phases=raw.inspect_native_git_phases(root,history.native_events,raw._digest(history.plan))
        prepared=next(event for event in phases['events'] if event['stage']=='refs_prepared')
        committed=next(event for event in phases['events'] if event['stage']=='refs_committed')
        path=history.plan['before']['branch']
        bound=prepared['bindings'][path]
        assert bound['source']==path+'.lock'
        assert bound['record']==prepared['files'][path+'.lock']
        assert bound['record']['signature'][1]==(root/'.git'/path).stat().st_ino
        assert committed['bindings'][path]['record']['signature'][1]==bound['record']['signature'][1]
        assert committed['bindings']['logs/'+path]['record']['signature'][1]==(root/'.git/logs'/path).stat().st_ino
    finally:history.close()


@pytest.mark.parametrize('kind',['ref','reflog'])
@pytest.mark.parametrize('change',['equal_byte_inode','bytes','mode','xattr'])
def test_recovery_preserves_later_owner_ref_and_reflog(tmp_path,monkeypatch,kind,change):
    from agentporter.sandbox import workspace_recovery as recovery
    root,sandbox,tx,guard,manager,history=interrupted(tmp_path,monkeypatch,'refs_committed')
    relative=history.plan['before']['branch']
    if kind=='reflog':relative='logs/'+relative
    target=root/'.git'/relative;before=target.stat()
    if change=='equal_byte_inode':
        later=target.with_name('owner-later');later.write_bytes(target.read_bytes())
        later.chmod(stat.S_IMODE(before.st_mode));os.utime(later,ns=(before.st_atime_ns,before.st_mtime_ns))
        later.replace(target)
    elif change=='bytes':target.write_bytes(b'owner later metadata')
    elif change=='mode':target.chmod(0o400)
    else:os.setxattr(target,'user.owner',b'later')
    inode=target.stat().st_ino;data=target.read_bytes();worktree=(root/'ordinary').read_bytes()
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert not plan['git'][0]['inspection']['apply_supported']
    with pytest.raises(PermissionError):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
            expected_plan_sha256=plan['plan_sha256'])
    assert target.stat().st_ino==inode and target.read_bytes()==data
    assert (root/'ordinary').read_bytes()==worktree and guard.exists() and tx._pending.exists()


@pytest.mark.parametrize('kind',['branch_create','branch_delete','nested_branch_create','stash_push','stash_clear'])
def test_native_namespace_change_recovers_original_files_retains_new_directories(tmp_path,monkeypatch,kind):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources,git
    from tests.security.custody.test_integration import stopped
    from agentporter.resources import ResourceCleanupError
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    from agentporter.tools.jobs import JobManager
    root,_,initial=setup(tmp_path)
    if kind=='branch_delete':git(root,'branch','delete-me')
    if kind=='stash_clear':
        (root/'ordinary').write_text('owner initial stash');git(root,'stash','push','-m','baseline')
    state=initial.state_dir;state.chmod(0o700);JobManager(state)
    sandbox=BubblewrapSandbox(state,transactional_writes=True);sandbox.resources=RecordingResources()
    original={str(path.relative_to(root/'.git')):path.stat().st_ino for path in (root/'.git').rglob('*')
              if path.is_file() and not path.is_relative_to(root/'.git/objects')}
    commands={'branch_create':'git branch added','branch_delete':'git branch -D delete-me',
        'nested_branch_create':'git branch new/nested',
        'stash_push':'printf "worker stash" > ordinary && git stash push -m worker',
        'stash_clear':'git stash clear'}
    marker="publication_event('head_published')"
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
        with pytest.raises(ResourceCleanupError):sandbox.run(str(root),['/bin/sh','-c',commands[kind]])
    tx=sandbox._unresolved_transactions[0];history=next(iter(tx.git_histories.values()));guard=history.guard
    stopped(tx);monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recovery.recover_workspace(state,root);inspection=plan['git'][0]['inspection']
    assert inspection['apply_supported'],inspection
    result=recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered'
    for path,inode in original.items():assert (root/'.git'/path).stat().st_ino==inode,path
    assert not guard.exists() and not tx._pending.exists()
    assert git(root,'status','--porcelain')==''
    if kind=='nested_branch_create':
        assert (root/'.git/refs/heads/new').is_dir() and not list((root/'.git/refs/heads/new').iterdir())


@pytest.mark.parametrize('point',['opened_after_receipt','closed_before_receipt','closed_after_receipt'])
def test_native_reflog_descriptor_process_death_inside_commit_resumes(tmp_path,monkeypatch,point):
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    marker={'opened_after_receipt':'    _native_expected[relative]=hashlib.sha256(expected).hexdigest()',
        'closed_before_receipt':'                        publication_ref_receipt(relative,descriptor)',
        'closed_after_receipt':'                        publication_ref_receipt(relative,descriptor)'}[point]
    # For opened death, stop only after the complete durable intent is linked.
    if point=='opened_after_receipt':
        marker='    finally:os.close(blobs);os.close(parent)'
        replacement=marker+"\n    os._exit(73)"
    elif point=='closed_before_receipt':replacement="                        if relative.startswith('logs/refs/'):os._exit(73)\n"+marker
    else:replacement=marker+"\n                        if relative.startswith('logs/refs/'):os._exit(73)"
    assert module._IMPORT.count(marker)==1
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,replacement))
        root,sandbox,tx,guard,manager,history=interrupted(tmp_path,patch,'head_published')
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['git'][0]['inspection']['apply_supported'],plan
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    for path,record in history.raw_baseline['manifest']['files'].items():
        assert (root/'.git'/path).stat().st_ino==record['identity'][1],path


@pytest.mark.parametrize('change',['bytes','mode','xattr'])
def test_owner_inplace_reflog_edit_before_native_close_cannot_be_adopted(tmp_path,monkeypatch,change):
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    marker='                        publication_ref_receipt(relative,descriptor)'
    injection="""                        if relative.startswith('logs/refs/'):
                            owner=os.open('/proc/self/fd/'+str(descriptor),os.O_WRONLY|os.O_CLOEXEC)
                            try:
                                os.ftruncate(owner,0);os.write(owner,b'owner late in-place reflog must survive\\n');os.fsync(owner)
                            finally:os.close(owner)
"""
    if change!='bytes':
        mutation="os.fchmod(descriptor,0o400)" if change=='mode' else "os.setxattr(descriptor,'user.owner',b'late')"
        injection="                        if relative.startswith('logs/refs/'):\n                            "+mutation+"\n"
    assert module._IMPORT.count(marker)==1
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,injection+marker))
        root,sandbox,tx,guard,manager,history=interrupted(tmp_path,patch,'head_published')
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    path=root/'.git/logs'/history.plan['before']['branch'];inode=path.stat().st_ino;data=path.read_bytes()
    if change=='bytes':assert data==b'owner late in-place reflog must survive\n'
    elif change=='mode':assert stat.S_IMODE(path.stat().st_mode)==0o400
    else:assert os.getxattr(path,'user.owner')==b'late'
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert not plan['git'][0]['inspection']['apply_supported'],plan
    with pytest.raises(PermissionError):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
            expected_plan_sha256=plan['plan_sha256'])
    assert path.stat().st_ino==inode and path.read_bytes()==data
    assert tx._pending.exists() and guard.exists()


def test_owner_same_length_reflog_edit_before_native_open_is_not_a_new_prefix(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    marker='    ref_environment, native_pass_fds = publication_ref_begin(ref_environment)'
    injection="""    owner_log=git_root+'/logs/'+before['branch']
    owner_stat=os.stat(owner_log)
    with open(owner_log,'r+b') as owner:
        owner.write(b'X'*owner_stat.st_size);owner.flush();os.fsync(owner.fileno())
    os.utime(owner_log,ns=(owner_stat.st_atime_ns,owner_stat.st_mtime_ns))
"""
    assert module._IMPORT.count(marker)==1
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,injection+marker))
        root,sandbox,tx,guard,manager,history=interrupted(tmp_path,patch,'head_published')
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    path=root/'.git/logs'/history.plan['before']['branch'];inode=path.stat().st_ino;data=path.read_bytes()
    assert data==b'X'*len(data)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert not plan['git'][0]['inspection']['apply_supported'],plan
    assert path.stat().st_ino==inode and path.read_bytes()==data
    assert guard.exists() and tx._pending.exists()


def test_packed_backed_branch_update_recovers_new_loose_ref_to_absence(tmp_path,monkeypatch):
    from tests.security.custody import test_native_history as native
    from agentporter.sandbox import workspace_recovery as recovery
    original=native.setup
    def packed_setup(path):
        root,other,sandbox=original(path)
        native.git(root,'pack-refs','--all','--prune')
        assert not (root/'.git'/native.git(root,'symbolic-ref','HEAD')).exists()
        return root,other,sandbox
    monkeypatch.setattr(native,'setup',packed_setup)
    root,sandbox,tx,guard,manager,history=interrupted(tmp_path,monkeypatch,'head_published')
    ref=history.plan['before']['branch'];packed=(root/'.git/packed-refs').stat().st_ino
    assert ref not in history.raw_baseline['manifest']['files'] and (root/'.git'/ref).is_file()
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['git'][0]['inspection']['apply_supported'],plan
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    assert not (root/'.git'/ref).exists() and (root/'.git/packed-refs').stat().st_ino==packed
    assert native.git(root,'rev-parse','HEAD')==history.plan['before']['head']
