import hashlib,json,os,sqlite3,stat
from pathlib import Path
import pytest
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox import workspace_transactions as txmod
from agentporter.sandbox import workspace_recovery as recovery
from agentporter.sandbox import workspace_custody as custody
from agentporter.sandbox import workspace_delta as delta
from agentporter.sandbox import workspace_directories as directories
from agentporter.tools.jobs import JobManager


def prepare(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir()
    (root/'a-replaced').write_bytes(b'old replacement');(root/'a-replaced').chmod(0o640)
    (root/'z-deleted').write_bytes(b'old deletion');(root/'z-deleted').chmod(0o600)
    identities={name:(root/name).stat().st_ino for name in ('a-replaced','z-deleted')}
    state=tmp_path/'state';manager=JobManager(state)
    tx=txmod.WorkspaceTransaction(root,state/'workspace-transactions')
    (tx.upper/'a-replaced').write_bytes(b'new replacement')
    (tx.upper/'b-created').write_bytes(b'new creation')
    (tx.upper/'z-deleted').touch()
    monkeypatch.setattr(txmod,'validate_workspace_delta',lambda *a,**kw:{'z-deleted'})
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    connection=manager._get_db()
    with connection:
        connection.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('owned','fixture','cleanup_failed','[]',0,?)",(str(tx.directory),))
        connection.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('foreign','other','cleanup_failed','[]',0,'/other')")
        connection.execute("INSERT INTO job_admissions VALUES ('own','owned',0,0)")
        connection.execute("INSERT INTO job_admissions VALUES ('other','foreign',0,0)")
        connection.execute("INSERT INTO job_admissions VALUES ('unbound',NULL,0,0)")
    connection.close()
    return root,state,tx,manager,identities


def stopped(tx):
    for history in tx.git_histories.values():history.close()
    for name in ('_publication_fd','_projection_fd','_root_fd','_lock'):
        fd=getattr(tx,name,None)
        if fd is not None:os.close(fd)
    tx._closed=True


def interrupted(tmp_path,monkeypatch):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    original=tx._journal
    def fail(changes,**kwargs):
        result=original(changes,**kwargs)
        if kwargs.get('update') and all(item.get('state')=='applied' for item in changes):
            raise OSError('after every ordinary operation before terminal receipt')
        return result
    monkeypatch.setattr(tx,'_journal',fail)
    with pytest.raises(ResourceCleanupError):tx.publish()
    stopped(tx)
    return root,state,tx,manager,identities


def restore(root,state):
    plan=recovery.recover_workspace(state,root)
    return recovery.recover_workspace(state,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])


def baseline(root,identities):
    assert {p.name for p in root.iterdir()}==set(identities)
    assert (root/'a-replaced').read_bytes()==b'old replacement'
    assert (root/'z-deleted').read_bytes()==b'old deletion'
    for name,ino in identities.items():assert (root/name).stat().st_ino==ino
    assert stat.S_IMODE((root/'a-replaced').stat().st_mode)==0o640


def assert_jobs(manager):
    connection=manager._get_db()
    try:
        assert dict(connection.execute('SELECT job_id,status FROM jobs'))=={'owned':'recovered','foreign':'cleanup_failed'}
        assert {row[0] for row in connection.execute('SELECT token FROM job_admissions')}=={'other','unbound'}
    finally:connection.close()


def test_publication_retains_original_inodes_and_close_archives_without_purge(tmp_path,monkeypatch):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    tx.publish()
    assert (root/'a-replaced').read_bytes()==b'new replacement'
    assert (root/'b-created').read_bytes()==b'new creation'
    assert not (root/'z-deleted').exists()
    assert (tx.directory/'custody/0/captured').stat().st_ino==identities['a-replaced']
    assert (tx.directory/'custody/2/captured').stat().st_ino==identities['z-deleted']
    archive=tx.directory
    tx.close()
    assert archive.exists() and (archive/'publication-receipt.json').is_file()
    assert (archive/'custody/0/captured').read_bytes()==b'old replacement'
    assert not tx._pending.exists()
    followup=txmod.WorkspaceTransaction(root,state/'workspace-transactions');followup.close()


def test_schema4_mixed_rollback_returns_exact_originals_and_retains_candidates(tmp_path,monkeypatch):
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    assert json.loads(tx._pending.read_text())['schema']==4
    candidates={name:(root/name).stat().st_ino for name in ('a-replaced','b-created')}
    result=restore(root,state)
    assert result['status']=='recovered' and result['endpoint']=='before'
    baseline(root,identities);assert_jobs(manager)
    assert not tx._pending.exists()
    assert (tx.directory/'rollback-custody/0/captured').stat().st_ino==candidates['a-replaced']
    assert (tx.directory/'rollback-custody/1/captured').stat().st_ino==candidates['b-created']
    followup=txmod.WorkspaceTransaction(root,state/'workspace-transactions');followup.close()


def test_atomic_capture_preserves_owner_substitution_in_integrated_delete(tmp_path,monkeypatch):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    original=custody._rename_noreplace;owner=[]
    def raced(source,name,destination,destname):
        if name=='z-deleted' and not owner:
            later=root/'owner-later';later.write_bytes(b'old deletion');later.replace(root/'z-deleted')
            owner.append((root/'z-deleted').stat().st_ino)
        return original(source,name,destination,destname)
    monkeypatch.setattr(custody,'_rename_noreplace',raced)
    with pytest.raises(ResourceCleanupError):tx.publish()
    assert owner and (root/'z-deleted').stat().st_ino==owner[0]
    assert (root/'z-deleted').read_bytes()==b'old deletion'
    assert tx._pending.exists()
    with pytest.raises(ResourceCleanupError):tx.close()
    assert (tx.directory/'custody/0/captured').stat().st_ino==identities['a-replaced']
    stopped(tx)
    plan=recovery.recover_workspace(state,root)
    with pytest.raises(PermissionError):
        recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert (root/'z-deleted').stat().st_ino==owner[0]


def test_all_mount_preflights_precede_first_workspace_mutation(tmp_path,monkeypatch):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    original=custody._mount_id
    def unsupported(fd):
        value=original(fd)
        return value+1 if os.readlink('/proc/self/fd/'+str(fd)).endswith('rollback-custody/1') else value
    monkeypatch.setattr(custody,'_mount_id',unsupported)
    with pytest.raises(PermissionError,match='mount'):tx.publish()
    baseline(root,identities)
    assert not (root/'b-created').exists() and not tx._pending.exists()
    tx.close()


def test_later_same_byte_candidate_inode_is_preserved_by_rollback(tmp_path,monkeypatch):
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    target=root/'a-replaced';later=root/'later';later.write_bytes(target.read_bytes())
    later.chmod(stat.S_IMODE(target.stat().st_mode));os.utime(later,ns=(target.stat().st_atime_ns,target.stat().st_mtime_ns));later.replace(target)
    owner=target.stat().st_ino
    plan=recovery.recover_workspace(state,root)
    with pytest.raises(PermissionError):
        recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert target.stat().st_ino==owner and tx._pending.exists()
    assert (tx.directory/'custody/0/captured').stat().st_ino==identities['a-replaced']


@pytest.mark.parametrize('when',['before_receipt','after_receipt','after_db_commit'])
def test_real_recovery_crash_receipt_database_guard_sequence(tmp_path,monkeypatch,when):
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    child=os.fork()
    if child==0:
        original=recovery._write_receipt
        def stop(path,data):
            if data.get('status')=='recovered':
                if when=='after_receipt':original(path,data)
                if when in {'before_receipt','after_receipt'}:os._exit(73)
            return original(path,data)
        recovery._write_receipt=stop
        if when=='after_db_commit':
            connect=recovery.sqlite3.connect
            class Crash(sqlite3.Connection):
                def __exit__(self,*args):super().__exit__(*args);os._exit(73)
            recovery.sqlite3.connect=lambda *a,**kw:connect(*a,**kw,factory=Crash)
        try:restore(root,state)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    assert tx._pending.exists()
    restore(root,state);baseline(root,identities);assert_jobs(manager)
    assert not tx._pending.exists()


def test_delete_helper_without_protected_custody_never_unlinks(tmp_path):
    root=tmp_path/'root';root.mkdir();target=root/'file';target.write_bytes(b'original')
    signature=list(delta._file_signature(target.stat()))
    with pytest.raises(PermissionError):
        delta.delete_workspace_file(root,'file',expected_signature=signature,
                                    expected_sha256=hashlib.sha256(b'original').hexdigest())
    assert target.read_bytes()==b'original'


def test_equal_byte_replacement_rolls_back_to_original_inode(tmp_path,monkeypatch):
    original_prepare=prepare
    def equal_bytes(*args):
        result=original_prepare(*args)
        root,state,tx,manager,identities=result
        (tx.upper/'a-replaced').write_bytes(b'old replacement')
        return result
    monkeypatch.setitem(globals(),'prepare',equal_bytes)
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    assert (root/'a-replaced').stat().st_ino!=identities['a-replaced']
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)


@pytest.mark.parametrize('checkpoint',range(1,7))
def test_publication_journal_process_deaths_restore_exact_baseline(tmp_path,monkeypatch,checkpoint):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    child=os.fork()
    if child==0:
        original=tx._journal
        count=0
        def die_after_journal(*args,**kwargs):
            nonlocal count
            result=original(*args,**kwargs)
            count+=1
            if count==checkpoint:os._exit(73)
            return result
        tx._journal=die_after_journal
        try:tx.publish()
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0)
    stopped(tx)
    assert os.waitstatus_to_exitcode(status)==73
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)
    assert not tx._pending.exists()


@pytest.mark.parametrize('target',['a-replaced','z-deleted'])
@pytest.mark.parametrize('phase',['after_rename','after_receipt'])
def test_publication_custody_process_death_preserves_originals(tmp_path,monkeypatch,target,phase):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    child=os.fork()
    if child==0:
        rename=custody._rename_noreplace
        write=custody._write_record
        def crash_rename(source,name,destination,destname):
            result=rename(source,name,destination,destname)
            if phase=='after_rename' and name==target:os._exit(73)
            return result
        def crash_receipt(directory,name,data):
            result=write(directory,name,data)
            if phase=='after_receipt' and name=='captured.json':
                intent=custody._read_record(directory,'intent.json')
                if intent['path']==target:os._exit(73)
            return result
        custody._rename_noreplace=crash_rename
        custody._write_record=crash_receipt
        try:tx.publish()
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0)
    stopped(tx)
    assert os.waitstatus_to_exitcode(status)==73
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)


def directory_fixture(tmp_path):
    root=tmp_path/'workspace';root.mkdir()
    private=tmp_path/'private';private.mkdir(mode=0o700)
    operation=private/'directory-0'
    intent=directories.prepare_directory(root,'new',operation)
    return root,operation,intent


def test_directory_create_rollback_retains_exact_inode_and_retries(tmp_path):
    root,operation,intent=directory_fixture(tmp_path)
    directories.publish_directory(root,'new',operation)
    directories.publish_directory(root,'new',operation)
    assert (root/'new').stat().st_ino==intent['directory']['identity'][1]
    directories.rollback_directory(root,'new',operation)
    directories.rollback_directory(root,'new',operation)
    assert not (root/'new').exists()
    assert (operation/'captured').stat().st_ino==intent['directory']['identity'][1]


def test_directory_nonempty_owner_entries_prevent_rollback(tmp_path):
    root,operation,intent=directory_fixture(tmp_path)
    directories.publish_directory(root,'new',operation)
    (root/'new/owner').write_text('preserve')
    with pytest.raises(PermissionError):directories.rollback_directory(root,'new',operation)
    assert (root/'new/owner').read_text()=='preserve'


@pytest.mark.parametrize('race',['nonempty','replacement','symlink','destination_recreated'])
def test_directory_capture_races_preserve_owner_entries(tmp_path,monkeypatch,race):
    root,operation,intent=directory_fixture(tmp_path)
    directories.publish_directory(root,'new',operation)
    original=directories._rename_noreplace
    sentinel=tmp_path/'sentinel';sentinel.mkdir();(sentinel/'file').write_text('unchanged')
    def replace(source,name,destination,destname):
        if name=='new':
            if race=='nonempty':(root/'new/owner').write_text('preserve')
            else:
                (root/'new').rename(root/'original-moved')
                if race=='symlink':(root/'new').symlink_to(sentinel,target_is_directory=True)
                else:
                    (root/'new').mkdir();(root/'new/owner').write_text('preserve')
        result=original(source,name,destination,destname)
        if name=='new' and race=='destination_recreated':
            (root/'new').mkdir();(root/'new/newer').write_text('newer')
        return result
    monkeypatch.setattr(directories,'_rename_noreplace',replace)
    with pytest.raises((PermissionError,OSError)):directories.rollback_directory(root,'new',operation)
    assert (sentinel/'file').read_text()=='unchanged'
    if race=='symlink':assert (root/'new').is_symlink()
    elif race=='destination_recreated':
        assert (root/'new/newer').read_text()=='newer'
        assert (operation/'captured/owner').read_text()=='preserve'
    else:assert (root/'new/owner').read_text()=='preserve'


@pytest.mark.parametrize('action',['publish','rollback'])
def test_directory_process_death_after_move_resumes(tmp_path,monkeypatch,action):
    root,operation,intent=directory_fixture(tmp_path)
    if action=='rollback':directories.publish_directory(root,'new',operation)
    child=os.fork()
    if child==0:
        original=directories._rename_noreplace
        def stop(*args):
            original(*args);os._exit(73)
        directories._rename_noreplace=stop
        try:
            if action=='publish':directories.publish_directory(root,'new',operation)
            else:directories.rollback_directory(root,'new',operation)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    if action=='publish':directories.publish_directory(root,'new',operation)
    directories.rollback_directory(root,'new',operation)
    assert (operation/'captured').stat().st_ino==intent['directory']['identity'][1]


def test_directory_mount_mismatch_refuses_before_workspace_mutation(tmp_path,monkeypatch):
    root=tmp_path/'workspace';root.mkdir()
    private=tmp_path/'private';private.mkdir(mode=0o700)
    original=custody._mount_id
    def different_mount(fd):
        return original(fd)+(1 if os.readlink('/proc/self/fd/'+str(fd)).endswith('directory-0') else 0)
    monkeypatch.setattr(custody,'_mount_id',different_mount)
    with pytest.raises(PermissionError,match='mount'):
        directories.prepare_directory(root,'new',private/'directory-0')
    assert list(root.iterdir())==[]


@pytest.mark.parametrize('mutation',['mode','xattr','substitute'])
def test_directory_owner_identity_or_metadata_prevents_rollback(tmp_path,mutation):
    root,operation,intent=directory_fixture(tmp_path)
    directories.publish_directory(root,'new',operation)
    if mutation=='mode':(root/'new').chmod(0o700)
    elif mutation=='xattr':os.setxattr(root/'new','user.owner',b'keep')
    else:
        (root/'new').rename(root/'original-moved');(root/'new').mkdir()
    inode=(root/'new').stat().st_ino
    with pytest.raises(PermissionError):directories.rollback_directory(root,'new',operation)
    assert (root/'new').stat().st_ino==inode
    if mutation=='xattr':assert os.getxattr(root/'new','user.owner')==b'keep'


def test_directory_prepared_destination_conflict_never_overwrites_owner(tmp_path):
    root,operation,intent=directory_fixture(tmp_path)
    (root/'new').mkdir();(root/'new/owner').write_text('preserve')
    with pytest.raises(PermissionError):directories.publish_directory(root,'new',operation)
    assert (root/'new/owner').read_text()=='preserve'
    assert (operation/'prepared').stat().st_ino==intent['directory']['identity'][1]


def test_directory_changed_parent_refuses_publication(tmp_path):
    root=tmp_path/'workspace';root.mkdir();(root/'parent').mkdir()
    private=tmp_path/'private';private.mkdir(mode=0o700)
    operation=private/'op'
    directories.prepare_directory(root,'parent/new',operation)
    (root/'parent').rename(root/'old-parent');(root/'parent').mkdir()
    with pytest.raises(PermissionError):directories.publish_directory(root,'parent/new',operation)
    assert list((root/'parent').iterdir())==[]
    assert list((root/'old-parent').iterdir())==[]


def add_tree_fixture(monkeypatch):
    original=prepare
    def tree_prepare(*args):
        result=original(*args)
        root,state,tx,manager,identities=result
        (tx.upper/'new/nested').mkdir(parents=True)
        (tx.upper/'new').chmod(0o750)
        os.setxattr(tx.upper/'new','user.root',b'root attribute')
        (tx.upper/'new/nested/file').write_bytes(b'nested content')
        (tx.upper/'new/nested/file').chmod(0o640)
        os.setxattr(tx.upper/'new/nested/file','user.fixture',b'attribute')
        (tx.upper/'empty').mkdir()
        return result
    monkeypatch.setitem(globals(),'prepare',tree_prepare)


def test_transaction_publishes_atomic_nested_tree_and_empty_directory(tmp_path,monkeypatch):
    add_tree_fixture(monkeypatch)
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    tx.publish()
    file=root/'new/nested/file'
    assert file.read_bytes()==b'nested content'
    assert stat.S_IMODE(file.stat().st_mode)==0o640
    assert os.getxattr(file,'user.fixture')==b'attribute'
    assert (root/'empty').is_dir()
    assert stat.S_IMODE((root/'new').stat().st_mode)==0o750
    assert os.getxattr(root/'new','user.root')==b'root attribute'
    assert not tx._pending.exists()
    tx.close()


def test_mixed_transaction_rolls_back_nested_tree_and_exact_files(tmp_path,monkeypatch):
    add_tree_fixture(monkeypatch)
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    inode=(root/'new').stat().st_ino
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)
    assert (tx.directory/'directory-custody/1/captured').stat().st_ino==inode
    assert (tx.directory/'directory-custody/1/captured/nested/file').read_bytes()==b'nested content'


@pytest.mark.parametrize('change',['add','same_bytes_inode','symlink'])
def test_tree_owner_changes_block_entire_recovery_before_file_rollback(tmp_path,monkeypatch,change):
    add_tree_fixture(monkeypatch)
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    file=root/'new/nested/file'
    if change=='add':(root/'new/owner').write_bytes(b'owner')
    elif change=='same_bytes_inode':
        substitute=root/'replacement';substitute.write_bytes(file.read_bytes());substitute.replace(file)
    else:file.unlink();file.symlink_to('/dev/null')
    original_candidate=(root/'a-replaced').stat().st_ino
    plan=recovery.recover_workspace(state,root)
    assert any(item['state']=='conflict' for item in plan['directories'])
    with pytest.raises(PermissionError):
        recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert (root/'a-replaced').stat().st_ino==original_candidate
    assert tx._pending.exists()


@pytest.mark.parametrize('stage',['journal','publication_move','rollback_move'])
def test_tree_transaction_process_death_resumes_coherent_baseline(tmp_path,monkeypatch,stage):
    add_tree_fixture(monkeypatch)
    if stage=='rollback_move':
        root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    else:root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    child=os.fork()
    if child==0:
        if stage=='journal':
            original=tx._journal
            def stop(*args,**kwargs):original(*args,**kwargs);os._exit(73)
            tx._journal=stop
        else:
            original=directories._rename_noreplace
            def stop(*args):original(*args);os._exit(73)
            directories._rename_noreplace=stop
        try:
            if stage=='rollback_move':restore(root,state)
            else:tx.publish()
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0)
    if stage!='rollback_move':stopped(tx)
    assert os.waitstatus_to_exitcode(status)==73
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)


def test_directory_only_transaction_recovers_without_file_operations(tmp_path,monkeypatch):
    add_tree_fixture(monkeypatch)
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    for name in ('a-replaced','b-created','z-deleted'):(tx.upper/name).unlink()
    original=recovery._write_receipt
    def fail(path,data):
        if data.get('status')=='published':raise OSError('before publication receipt')
        return original(path,data)
    with monkeypatch.context() as patch:
        patch.setattr(recovery,'_write_receipt',fail)
        with pytest.raises(ResourceCleanupError):tx.publish()
    assert json.loads(tx._pending.read_text())['changes']==[]
    stopped(tx)
    result=restore(root,state)
    assert result['status']=='recovered'
    baseline(root,identities);assert_jobs(manager)


@pytest.mark.parametrize('destination_recreated',[False,True])
def test_integrated_tree_capture_race_preserves_owner_content(tmp_path,monkeypatch,destination_recreated):
    add_tree_fixture(monkeypatch)
    root,state,tx,manager,identities=interrupted(tmp_path,monkeypatch)
    original=directories._rename_noreplace
    def race(source,name,destination,destname):
        if name=='new':(root/'new/owner').write_bytes(b'owner addition')
        result=original(source,name,destination,destname)
        if name=='new' and destination_recreated:
            (root/'new').mkdir();(root/'new/newer').write_bytes(b'newer')
        return result
    monkeypatch.setattr(directories,'_rename_noreplace',race)
    plan=recovery.recover_workspace(state,root)
    with pytest.raises((OSError,PermissionError)):
        recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert tx._pending.exists()
    retained=tx.directory/'directory-custody/1/captured' if destination_recreated else root/'new'
    assert (retained/'owner').read_bytes()==b'owner addition'
    assert (retained/'nested/file').read_bytes()==b'nested content'
    if destination_recreated:assert (root/'new/newer').read_bytes()==b'newer'
    assert_jobs_unchanged=manager._get_db()
    try:
        assert dict(assert_jobs_unchanged.execute('SELECT job_id,status FROM jobs'))['owned']=='cleanup_failed'
        assert assert_jobs_unchanged.execute("SELECT 1 FROM job_admissions WHERE token='own'").fetchone()
    finally:assert_jobs_unchanged.close()


def test_oversize_journal_refused_before_guard_or_workspace_changes(tmp_path,monkeypatch):
    root,state,tx,manager,identities=prepare(tmp_path,monkeypatch)
    tx._recovery_context={'oversize':'x'*(16*1024*1024)}
    with pytest.raises(PermissionError,match='offline recovery limit'):
        tx._journal([],version=4)
    assert not tx._pending.exists()
    baseline(root,identities)
    tx.close()
