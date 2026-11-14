"""Native new repository creation stays private, then publishes one checked tree."""
import hashlib,json,os
from pathlib import Path

import pytest
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.sandbox.workspace_delta import UnsafeWorkspaceDelta
from tests.security.test_git_approval_state import git,setup
from tests.security.test_workspace_transactions import RecordingResources


def fixture(tmp_path,outer_git=True,allow=True,existing=False,monkeypatch=None):
    if outer_git:
        root,_,initial=setup(tmp_path)
        (root/'staged-owner').write_text('owner staged\n');git(root,'add','staged-owner')
        (root/'ordinary').write_text('owner dirty\n')
        state=initial.state_dir
    else:
        root=tmp_path/'workspace';root.mkdir();(root/'ordinary').write_text('owner dirty\n');state=tmp_path/'state'
    if existing:
        (root/'existing').mkdir(mode=0o750)
        (root/'existing').chmod(0o750)  # Keep the mode-race fixture independent of umask.
    sandbox=BubblewrapSandbox(state,transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,state/'workspace-transactions',git_sandbox=sandbox,allow_git_birth=allow)
    if monkeypatch is not None:
        # Explicitly isolate birth mechanics beneath the owner-approval gate.
        from tests.security.custody.authorization_seams import allow_birth_for_recovery
        allow_birth_for_recovery(monkeypatch,tx)
    return root,state,sandbox,tx


def metadata(root):
    if not (root/'.git').exists():return None
    return {str(p.relative_to(root/'.git')):(p.stat().st_ino,p.read_bytes()) for p in (root/'.git').rglob('*') if p.is_file()}


def run(sandbox,root,tx,script):
    return sandbox._run_command(workspace_path=str(root),argv=['/bin/sh','-c',script],writable=True,
        network_access=False,workspace_transaction=tx,require_resources=True,timeout_seconds=30)


SCRIPT='''mkdir -p /workspace/new/fixture
cd /workspace/new/fixture
git init -q --template= --initial-branch=main
printf 'worker fixture\\n' > sample
git -c safe.directory=/workspace/new/fixture add sample
git -c safe.directory=/workspace/new/fixture -c user.name=Worker -c user.email=worker@example.invalid commit -qm born
'''


@pytest.mark.parametrize('outer_git',[True,False])
def test_new_repository_commit_publishes_only_new_checked_tree(tmp_path,monkeypatch,outer_git):
    root,state,sandbox,tx=fixture(tmp_path,outer_git,monkeypatch=monkeypatch)
    before=metadata(root)
    try:
        result=run(sandbox,root,tx,SCRIPT);assert result['exit_code']==0,result
        assert not (root/'new').exists()
        tx.publish()
        assert (root/'new/fixture/sample').read_text()=='worker fixture\n'
        assert git(root/'new/fixture','log','-1','--format=%s')=='born'
        assert git(root/'new/fixture','status','--porcelain')==''
        assert metadata(root)==before
        assert (root/'ordinary').read_text()=='owner dirty\n'
        receipt=json.loads((tx.directory/'publication-receipt.json').read_text())
        assert receipt['directories'][0]['intent']['schema']==2
        assert receipt['directories'][0]['intent']['repository_births'][0]['repository']=='fixture'
        assert not tx._pending.exists()
    finally:tx.close()


def test_default_path_still_refuses_new_git_metadata(tmp_path):
    root,state,sandbox,tx=fixture(tmp_path,False,allow=False)
    try:
        assert run(sandbox,root,tx,SCRIPT)['exit_code']==0
        with pytest.raises(PermissionError):tx.publish()
        assert not (root/'new').exists()
    finally:tx.close()


@pytest.mark.parametrize('attack',[
 "printf '[core]\\nrepositoryformatversion=0\\nbare=false\\nhooksPath=/workspace/evil\\n' > new/fixture/.git/config",
 "printf '[include]\\npath=/outside\\n' >> new/fixture/.git/config",
 "printf '/outside\\n' > new/fixture/.git/objects/info/alternates",
 "mkdir -p new/fixture/.git/hooks; printf 'evil' > new/fixture/.git/hooks/pre-commit",
 "ln new/fixture/.git/HEAD new/fixture/.git/HEAD-alias",
 "ln -s /etc/passwd new/fixture/.git/evil",
 "git -C new/fixture update-ref refs/replace/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HEAD",
])
def test_unsafe_new_metadata_is_refused_before_canonical_changes(tmp_path,monkeypatch,attack):
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    try:
        result=run(sandbox,root,tx,SCRIPT+'\ncd /workspace\n'+attack);assert result['exit_code']==0,result
        with pytest.raises(PermissionError):tx.publish()
        assert not (root/'new').exists()
        assert not tx._started
    finally:tx.close()


def test_existing_empty_target_retains_original_directory_then_publishes_birth(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir();(root/'existing').mkdir(mode=0o750);state=tmp_path/'state'
    original=(root/'existing').stat().st_ino
    sandbox=BubblewrapSandbox(state,transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,state/'workspace-transactions',git_sandbox=sandbox,allow_git_birth=True)
    from tests.security.custody.authorization_seams import allow_birth_for_recovery
    allow_birth_for_recovery(monkeypatch,tx)
    try:
        script=SCRIPT.replace('new/fixture','existing')
        assert run(sandbox,root,tx,script)['exit_code']==0
        tx.publish()
        assert git(root/'existing','log','-1','--format=%s')=='born'
        receipt=json.loads((tx.directory/'publication-receipt.json').read_text())
        assert receipt['directories'][0]['intent']['schema']==3
        assert (tx.directory/'directory-custody/0/original').stat().st_ino==original
        assert not list((tx.directory/'directory-custody/0/original').iterdir())
    finally:tx.close()


def test_existing_nonempty_target_refuses_without_replacing_owner_directory(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir();(root/'existing').mkdir();(root/'existing/owner').write_text('owner')
    sandbox=BubblewrapSandbox(tmp_path/'state',transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox,allow_git_birth=True)
    from tests.security.custody.authorization_seams import allow_birth_for_recovery
    allow_birth_for_recovery(monkeypatch,tx)
    try:
        assert run(sandbox,root,tx,SCRIPT.replace('new/fixture','existing'))['exit_code']==0
        with pytest.raises(PermissionError,match='empty existing'):tx.publish()
        assert (root/'existing/owner').read_text()=='owner' and not (root/'existing/.git').exists()
    finally:tx.close()


def test_copied_birth_cannot_adopt_metadata_changed_after_validation(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_directories as dirs
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    original=dirs._tree;changed=[]
    try:
        assert run(sandbox,root,tx,SCRIPT)['exit_code']==0
        def race(parent,name,**kwargs):
            if kwargs.get('copy_to') is not None and not changed:
                (tx.upper/'new/fixture/.git/config').write_text('[core]\nrepositoryformatversion=0\nbare=false\nhooksPath=/outside\n')
                changed.append(True)
            return original(parent,name,**kwargs)
        monkeypatch.setattr(dirs,'_tree',race)
        with pytest.raises(PermissionError,match='validated source'):tx.publish()
        assert changed and not (root/'new').exists() and not tx._started
    finally:tx.close()


def interrupted_birth(tmp_path,monkeypatch,point,existing=False):
    from agentporter.sandbox import workspace_directories as dirs,workspace_recovery as recovery
    from agentporter.tools.jobs import JobManager
    from tests.security.custody.test_integration import stopped
    root,state,sandbox,tx=fixture(tmp_path,False,existing=existing,monkeypatch=monkeypatch)
    manager=JobManager(state)
    tx._birth_original_inode=(root/'existing').stat().st_ino if existing else None
    assert run(sandbox,root,tx,SCRIPT.replace('new/fixture','existing') if existing else SCRIPT)['exit_code']==0
    db=manager._get_db()
    try:
        with db:
            db.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('birth-owned','fixture','cleanup_failed','[]',0,?)",(str(tx.directory),))
            db.execute("INSERT INTO job_admissions VALUES ('birth-token','birth-owned',0,0)")
    finally:db.close()
    child=os.fork()
    if child==0:
        try:
            if point in {'after_rename','after_original_capture'}:
                original=dirs._rename_noreplace
                def rename(source,name,destination,target):
                    original(source,name,destination,target)
                    if ((point=='after_rename' and name=='prepared')
                            or (point=='after_original_capture' and target=='original')):os._exit(73)
                dirs._rename_noreplace=rename
            else:
                original=tx._journal
                def journal(changes,**kwargs):
                    result=original(changes,**kwargs)
                    if not kwargs.get('update'):os._exit(73)
                    return result
                tx._journal=journal
            tx.publish()
            os._exit(74)
        except BaseException:os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    stopped(tx)
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    return root,state,tx,manager


@pytest.mark.parametrize('point',['after_intent','after_rename'])
def test_process_death_new_repository_rolls_back_whole_tree_and_admission(tmp_path,monkeypatch,point):
    from agentporter.sandbox import workspace_recovery as recovery
    root,state,tx,manager=interrupted_birth(tmp_path,monkeypatch,point)
    plan=recovery.recover_workspace(state,root)
    result=recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
                                    expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and result['endpoint']=='before'
    assert not (root/'new').exists()
    assert not tx._pending.exists()
    db=manager._get_db()
    try:
        assert db.execute("SELECT status FROM jobs WHERE job_id='birth-owned'").fetchone()[0]=='recovered'
        assert not db.execute("SELECT 1 FROM job_admissions WHERE token='birth-token'").fetchone()
    finally:db.close()
    if point=='after_rename':
        held=tx.directory/'directory-custody/0/captured'
        assert (held/'fixture/.git/HEAD').is_file()
        assert git(held/'fixture','log','-1','--format=%s')=='born'


@pytest.mark.parametrize('change',['newfile','gitbytes','gitinode'])
def test_later_owner_new_repository_changes_refuse_recovery_without_mutation(tmp_path,monkeypatch,change):
    from agentporter.sandbox import workspace_recovery as recovery
    root,state,tx,manager=interrupted_birth(tmp_path,monkeypatch,'after_rename')
    repo=root/'new/fixture';target=repo/'.git/HEAD'
    if change=='newfile':(repo/'owner-later').write_text('owner later\n')
    elif change=='gitbytes':target.write_text('owner changed\n')
    else:
        replacement=repo/'.git/replacement';replacement.write_bytes(target.read_bytes());replacement.replace(target)
    before={str(p.relative_to(root)):(p.stat().st_ino,p.read_bytes()) for p in (root/'new').rglob('*') if p.is_file()}
    plan=recovery.recover_workspace(state,root)
    with pytest.raises(PermissionError):
        recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
                                  expected_plan_sha256=plan['plan_sha256'])
    assert {str(p.relative_to(root)):(p.stat().st_ino,p.read_bytes()) for p in (root/'new').rglob('*') if p.is_file()}==before
    assert tx._pending.exists()


@pytest.mark.parametrize('point',['after_intent','after_original_capture','after_rename'])
def test_existing_empty_target_process_death_restores_exact_original_directory(tmp_path,monkeypatch,point):
    from agentporter.sandbox import workspace_recovery as recovery
    root,state,tx,manager=interrupted_birth(tmp_path,monkeypatch,point,existing=True)
    plan=recovery.recover_workspace(state,root)
    result=recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered'
    assert (root/'existing').stat().st_ino==tx._birth_original_inode
    assert not list((root/'existing').iterdir())
    assert not tx._pending.exists()


@pytest.mark.parametrize('location',['original','canonical'])
def test_empty_target_capture_recovery_preserves_owner_late_directory_work(tmp_path,monkeypatch,location):
    from agentporter.sandbox import workspace_recovery as recovery
    root,state,tx,manager=interrupted_birth(tmp_path,monkeypatch,'after_original_capture',existing=True)
    if location=='original':target=tx.directory/'directory-custody/0/original'
    else:target=root/'existing';target.mkdir()
    (target/'owner-later').write_text('owner later')
    before=(target.stat().st_ino,(target/'owner-later').stat().st_ino)
    plan=recovery.recover_workspace(state,root)
    with pytest.raises(PermissionError):recovery.recover_workspace(state,root,apply=True,
        restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert (target.stat().st_ino,(target/'owner-later').stat().st_ino)==before
    assert (target/'owner-later').read_text()=='owner later' and tx._pending.exists()


@pytest.mark.parametrize('algorithm',['sha1','sha256'])
@pytest.mark.parametrize('samples',[False,True])
def test_default_init_samples_and_both_object_formats_are_checked(tmp_path,monkeypatch,algorithm,samples):
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    script=SCRIPT.replace('git init -q --template= --initial-branch=main',
        'git init -q '+('' if samples else '--template= ')+'--initial-branch=main --object-format='+algorithm)
    try:
        result=run(sandbox,root,tx,script);assert result['exit_code']==0,result
        tx.publish()
        assert git(root/'new/fixture','rev-parse','--show-object-format')==algorithm
        assert git(root/'new/fixture','status','--porcelain')==''
    finally:tx.close()


def test_read_only_transaction_never_honors_birth_opt_in(tmp_path):
    root=tmp_path/'workspace';root.mkdir();state=tmp_path/'state'
    sandbox=BubblewrapSandbox(state,transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,state/'workspace-transactions',git_sandbox=sandbox,writable=False,allow_git_birth=True)
    try:
        (tx.upper/'new').mkdir()
        with pytest.raises(PermissionError,match='Read-only'):tx.publish()
        assert not (root/'new').exists()
    finally:tx.close()


@pytest.mark.parametrize('change',['bytes','inode','mode'])
def test_existing_empty_target_owner_change_after_job_start_is_not_adopted(tmp_path,monkeypatch,change):
    root,state,sandbox,tx=fixture(tmp_path,False,existing=True,monkeypatch=monkeypatch)
    try:
        assert run(sandbox,root,tx,SCRIPT.replace('new/fixture','existing'))['exit_code']==0
        target=root/'existing'
        if change=='bytes':(target/'owner-later').write_text('owner')
        elif change=='inode':
            target.rename(root/'original-target');target.mkdir()
        else:target.chmod(0o700)
        before=target.stat().st_ino
        with pytest.raises(PermissionError):tx.publish()
        assert target.stat().st_ino==before and not (target/'.git').exists()
        if change=='bytes':assert (target/'owner-later').read_text()=='owner'
    finally:tx.close()


def test_canonical_new_target_inserted_by_owner_is_never_replaced(tmp_path,monkeypatch):
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    try:
        assert run(sandbox,root,tx,SCRIPT)['exit_code']==0
        (root/'new/fixture').mkdir(parents=True);(root/'new/fixture/owner-later').write_text('owner')
        before=(root/'new/fixture').stat().st_ino
        with pytest.raises(PermissionError):tx.publish()
        assert (root/'new/fixture').stat().st_ino==before and (root/'new/fixture/owner-later').read_text()=='owner'
        assert not (root/'new/fixture/.git').exists()
    finally:tx.close()


def test_new_repository_cannot_publish_excluded_development_paths_in_history(tmp_path,monkeypatch):
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    try:
        script=SCRIPT+'''cd /workspace/new/fixture
mkdir .venv
printf forbidden > .venv/code
git -c safe.directory=/workspace/new/fixture add .venv/code
git -c safe.directory=/workspace/new/fixture -c user.name=Worker -c user.email=worker@example.invalid commit -qm excluded
'''
        assert run(sandbox,root,tx,script)['exit_code']==0
        with pytest.raises(PermissionError):tx.publish()
        assert not (root/'new').exists()
    finally:tx.close()


def test_owner_replaces_canonical_birth_parent_with_symlink_before_publication(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir();(root/'parent/repo').mkdir(parents=True)
    outside=tmp_path/'outside';(outside/'repo').mkdir(parents=True);(outside/'repo/owner').write_text('outside owner')
    sandbox=BubblewrapSandbox(tmp_path/'state',transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox,allow_git_birth=True)
    from tests.security.custody.authorization_seams import allow_birth_for_recovery
    allow_birth_for_recovery(monkeypatch,tx)
    try:
        assert run(sandbox,root,tx,SCRIPT.replace('new/fixture','parent/repo'))['exit_code']==0
        (root/'parent').rename(root/'retained-parent');(root/'parent').symlink_to(outside,target_is_directory=True)
        with pytest.raises(PermissionError,match='ordinary directory'):tx.publish()
        assert (outside/'repo/owner').read_text()=='outside owner' and not (outside/'repo/.git').exists()
        assert not list((root/'retained-parent/repo').iterdir())
    finally:tx.close()


@pytest.mark.parametrize('change',['repository_type','digest_type','remote_ref','branch_escape','mode','repeat'])
def test_durable_birth_evidence_rejects_malformed_or_expanded_scope(tmp_path,monkeypatch,change):
    from copy import deepcopy
    from agentporter.sandbox.repository_birth import discover,validate_payloads
    root,state,sandbox,tx=fixture(tmp_path,False,monkeypatch=monkeypatch)
    try:
        assert run(sandbox,root,tx,SCRIPT)['exit_code']==0
        records=discover(tx).for_tree(tx.upper/'new');records=deepcopy(records)
        if change=='repository_type':records[0]['repository']=1
        elif change=='digest_type':records[0]['metadata_manifest']['HEAD']['sha256']=1
        elif change=='remote_ref':records[0]['state']['refs']['refs/remotes/other/main']={'oid':'a'*40,'symref':None}
        elif change=='branch_escape':records[0]['state']['branch']='refs/heads/../evil'
        elif change=='mode':records[0]['metadata_manifest']['HEAD']['mode']=0o4755
        else:records.append(deepcopy(records[0]))
        with pytest.raises(PermissionError):validate_payloads(records)
    finally:tx.close()


def test_birth_preserves_existing_sibling_repository_and_outer_owner_history(tmp_path,monkeypatch):
    root,_,initial=setup(tmp_path)
    sibling=root/'sibling';sibling.mkdir()
    git(sibling,'init','-q','--template=','--initial-branch=main')
    git(sibling,'config','user.name','Sibling');git(sibling,'config','user.email','sibling@example.invalid')
    (sibling/'owner').write_text('sibling owner');git(sibling,'add','owner');git(sibling,'commit','-qm','sibling')
    (root/'ordinary').write_text('outer owner dirty')
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    tx=WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox,allow_git_birth=True)
    from tests.security.custody.authorization_seams import allow_birth_for_recovery
    allow_birth_for_recovery(monkeypatch,tx)
    before_outer,before_sibling=metadata(root),metadata(sibling)
    try:
        assert len(tx.git_histories)==2
        assert run(sandbox,root,tx,SCRIPT)['exit_code']==0
        tx.publish()
        assert metadata(root)==before_outer and metadata(sibling)==before_sibling
        assert (sibling/'owner').read_text()=='sibling owner' and (root/'ordinary').read_text()=='outer owner dirty'
        assert git(root/'new/fixture','log','-1','--format=%s')=='born'
    finally:tx.close()


@pytest.mark.parametrize('point',['after_candidate_capture','after_original_restore'])
def test_existing_empty_birth_recovery_itself_can_resume_after_process_death(tmp_path,monkeypatch,point):
    from agentporter.sandbox import workspace_recovery as recovery,workspace_directories as dirs
    root,state,tx,manager=interrupted_birth(tmp_path,monkeypatch,'after_rename',existing=True)
    plan=recovery.recover_workspace(state,root)
    child=os.fork()
    if child==0:
        try:
            original=dirs._rename_noreplace
            def rename(source,name,destination,target):
                original(source,name,destination,target)
                if ((point=='after_candidate_capture' and name=='existing' and target=='captured')
                        or (point=='after_original_restore' and name=='original' and target=='existing')):os._exit(73)
            dirs._rename_noreplace=rename
            recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])
            os._exit(74)
        except BaseException:os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    second=recovery.recover_workspace(state,root)
    result=recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
                                    expected_plan_sha256=second['plan_sha256'])
    assert result['status']=='recovered'
    assert (root/'existing').stat().st_ino==tx._birth_original_inode and not list((root/'existing').iterdir())
    assert not tx._pending.exists()
