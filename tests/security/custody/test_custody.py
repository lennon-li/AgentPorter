"""Real-file safety contract for private atomic capture, inspection and restore."""
import hashlib,json,os,stat
from pathlib import Path
import pytest


def module():
    from agentporter.sandbox import workspace_custody
    return workspace_custody


def fixture(tmp_path):
    root=tmp_path/'workspace';root.mkdir()
    target=root/'ordinary';target.write_bytes(b'original');target.chmod(0o640)
    private=tmp_path/'private';private.mkdir(mode=0o700)
    operation=private/'operation'
    from agentporter.sandbox.workspace_delta import _file_signature
    info=target.stat()
    record={'signature':list(_file_signature(info)), 'sha256':hashlib.sha256(b'original').hexdigest(),
            'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
            'mtime_ns':info.st_mtime_ns,'xattrs':{}}
    return root,target,operation,record


def test_expected_entry_is_retained_exactly_and_restored_create_only(tmp_path):
    api=module();root,target,operation,record=fixture(tmp_path);identity=target.stat().st_ino
    result=api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert result['state']=='captured_expected' and not target.exists()
    assert (operation/'captured').stat().st_ino==identity
    assert (operation/'captured').read_bytes()==b'original'
    result=api.restore_custody(root,operation)
    assert result['state']=='restored' and target.stat().st_ino==identity
    assert api.inspect_custody(root,operation)['state']=='restored'
    assert not (operation/'captured').exists()


@pytest.mark.parametrize('kind',['same_bytes','new_bytes','symlink','directory'])
def test_owner_substitution_at_atomic_capture_is_restored_not_destroyed(tmp_path,monkeypatch,kind):
    api=module();root,target,operation,record=fixture(tmp_path)
    original=api._rename_noreplace;injected=[]
    def raced(source,name,destination,destname):
        if name=='ordinary' and not injected:
            later=root/'later'
            if kind=='symlink':later.symlink_to('/owner-target-never-followed')
            elif kind=='directory':
                later.mkdir();(later/'owner-file').write_bytes(b'owner');target.rename(root/'owner-old')
            else:later.write_bytes(b'original' if kind=='same_bytes' else b'owner-later')
            later.replace(target);injected.append(target.lstat().st_ino)
        return original(source,name,destination,destname)
    monkeypatch.setattr(api,'_rename_noreplace',raced)
    with pytest.raises(PermissionError):api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert target.lstat().st_ino==injected[0]
    if kind=='directory':assert (target/'owner-file').read_bytes()==b'owner'
    if kind=='symlink':assert target.is_symlink() and os.readlink(target)=='/owner-target-never-followed'
    assert api.inspect_custody(root,operation)['state']=='restored_owner'


def test_restore_conflict_preserves_both_entries_and_custody(tmp_path):
    api=module();root,target,operation,record=fixture(tmp_path)
    api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    captured=(operation/'captured').stat().st_ino
    target.write_bytes(b'owner-later');owner=target.stat().st_ino
    with pytest.raises(PermissionError):api.restore_custody(root,operation)
    assert target.stat().st_ino==owner and target.read_bytes()==b'owner-later'
    assert (operation/'captured').stat().st_ino==captured
    assert (operation/'captured').read_bytes()==b'original'
    assert api.inspect_custody(root,operation)['state']=='captured_conflict'


def test_same_device_different_mount_is_refused_before_capture(tmp_path,monkeypatch):
    api=module();root,target,operation,record=fixture(tmp_path)
    real=api._mount_id
    def different(fd):
        # Deterministic unit control; the separate native mount test is required
        # before claiming actual bind/idmap behavior.
        return real(fd)+1 if os.readlink('/proc/self/fd/'+str(fd)).endswith('operation') else real(fd)
    monkeypatch.setattr(api,'_mount_id',different)
    with pytest.raises(PermissionError,match='mount'):
        api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert target.read_bytes()==b'original' and not (operation/'captured').exists()


def test_custody_inside_workspace_is_refused_before_capture(tmp_path):
    api=module();root,target,operation,record=fixture(tmp_path)
    operation=root/'custody'
    with pytest.raises(PermissionError):api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert target.read_bytes()==b'original'


@pytest.mark.parametrize('point',['intent','capture','captured_receipt','restore','restored_receipt'])
def test_actual_process_crash_retains_recoverable_entry(tmp_path,monkeypatch,point):
    api=module();root,target,operation,record=fixture(tmp_path)
    child=os.fork()
    if child==0:
        original_write=api._write_record;original_rename=api._rename_noreplace
        def write(directory,name,data):
            result=original_write(directory,name,data)
            if (point=='intent' and name=='intent.json') or (point=='captured_receipt' and name=='captured.json') or (point=='restored_receipt' and name=='restored.json'):
                os._exit(73)
            return result
        def rename(source,name,destination,destname):
            result=original_rename(source,name,destination,destname)
            if (point=='capture' and destname=='captured') or (point=='restore' and name=='captured'):
                os._exit(73)
            return result
        api._write_record=write;api._rename_noreplace=rename
        try:
            api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
            api.restore_custody(root,operation)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(status)==73
    before=api.inspect_custody(root,operation)
    assert before['state'] in {'uncaptured','captured_expected','restored'}
    if before['state']=='uncaptured':api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    api.restore_custody(root,operation)
    assert target.read_bytes()==b'original' and target.stat().st_ino==record['signature'][1]
    assert api.inspect_custody(root,operation)['state']=='restored'


def test_source_traversal_uses_the_pinned_workspace_root(tmp_path,monkeypatch):
    from contextlib import contextmanager
    api=module();root,target,operation,record=fixture(tmp_path)
    original=api._workspace_parent;changed=[]
    @contextmanager
    def raced(workspace,relative):
        if not changed:
            old=root.with_name('moved-root');root.rename(old);root.mkdir()
            (old/'ordinary').rename(root/'ordinary');changed.append(True)
        with original(workspace,relative) as value:yield value
    monkeypatch.setattr(api,'_workspace_parent',raced)
    with pytest.raises(PermissionError):
        api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert target.stat().st_ino==record['signature'][1]
    assert not (operation/'captured').exists()


def test_owner_source_created_at_restore_is_preserved_alongside_custody(tmp_path,monkeypatch):
    api=module();root,target,operation,record=fixture(tmp_path)
    api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    original=api._rename_noreplace
    def raced(source,name,destination,destname):
        if name=='captured':target.write_bytes(b'later-owner')
        return original(source,name,destination,destname)
    monkeypatch.setattr(api,'_rename_noreplace',raced)
    with pytest.raises(PermissionError):api.restore_custody(root,operation)
    assert target.read_bytes()==b'later-owner'
    assert (operation/'captured').read_bytes()==b'original'
    assert api.inspect_custody(root,operation)['state']=='captured_conflict'


@pytest.mark.parametrize('phase',['capture','restore'])
def test_retry_after_rename_before_sync_finishes_both_directory_syncs(tmp_path,monkeypatch,phase):
    api=module();root,target,operation,record=fixture(tmp_path)
    if phase=='restore':api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    child=os.fork()
    if child==0:
        original=api._rename_noreplace
        def stop(*args):original(*args);os._exit(73)
        api._rename_noreplace=stop
        try:
            if phase=='capture':api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
            else:api.restore_custody(root,operation)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    original=api.os.fsync;synced=[]
    def observe(fd):
        info=os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):synced.append((info.st_dev,info.st_ino))
        return original(fd)
    monkeypatch.setattr(api.os,'fsync',observe)
    if phase=='capture':api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    else:api.restore_custody(root,operation)
    for directory in (root,operation):
        assert (directory.stat().st_dev,directory.stat().st_ino) in synced
    assert (operation/('captured.json' if phase=='capture' else 'restored.json')).exists()


def test_source_recreation_during_receipt_retains_both_and_refuses_success(tmp_path,monkeypatch):
    api=module();root,target,operation,record=fixture(tmp_path)
    original=api._write_record
    def raced(directory,name,data):
        result=original(directory,name,data)
        if name=='captured.json':target.write_bytes(b'owner-after-capture')
        return result
    monkeypatch.setattr(api,'_write_record',raced)
    with pytest.raises(PermissionError):api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert target.read_bytes()==b'owner-after-capture'
    assert (operation/'captured').read_bytes()==b'original'
    assert api.inspect_custody(root,operation)['state']=='captured_conflict'


def test_retry_durably_acknowledges_existing_intent_before_source_capture(tmp_path,monkeypatch):
    api=module();root,target,operation,record=fixture(tmp_path)
    child=os.fork()
    if child==0:
        original=api._publish_restore_fd
        def stop(parent,source,destination):
            result=original(parent,source,destination)
            if destination=='intent.json':os._exit(73)
            return result
        api._publish_restore_fd=stop
        try:api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    synced=[];sync=api.os.fsync;rename=api._rename_noreplace
    identity=(operation.stat().st_dev,operation.stat().st_ino)
    def observe(fd):
        info=os.fstat(fd)
        if (info.st_dev,info.st_ino)==identity:synced.append(True)
        return sync(fd)
    def capture(*args):
        assert synced,'existing intent directory was not synced before capture'
        return rename(*args)
    monkeypatch.setattr(api.os,'fsync',observe);monkeypatch.setattr(api,'_rename_noreplace',capture)
    result=api.capture_workspace_entry(root,'ordinary',operation,expected_record=record)
    assert result['state']=='captured_expected'
