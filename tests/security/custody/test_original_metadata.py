import os,stat,subprocess
from pathlib import Path
import pytest
from tests.security.custody.test_git_raw import fixture
from agentporter.sandbox import workspace_git_recovery as raw,workspace_custody as custody
from agentporter.sandbox import git_original_metadata as originals


def setup(tmp_path):
    root,baseline_path=fixture(tmp_path)
    (root/'tracked').write_text('original tracked content')
    for arguments in (['add','tracked'],['update-index','--assume-unchanged','tracked']):
        subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',
                        '-C',str(root),*arguments],check=True,capture_output=True)
    (root/'.git/index').chmod(0o640)
    os.setxattr(root/'.git/index','user.original',b'preserved')
    baseline=raw.capture_git_baseline(root,baseline_path)
    directory=baseline_path.parent/'originals'
    originals.prepare(root,baseline_path,baseline['sha256'],directory)
    return root,directory,baseline


@pytest.mark.parametrize('path',['index','HEAD'])
def test_before_copy_and_rollback_return_exact_original_inode(tmp_path,path):
    root,directory,baseline=setup(tmp_path);target=root/'.git'/path
    inode=target.stat().st_ino;data=target.read_bytes()
    originals.publish_before_copy(root,directory,path)
    assert target.stat().st_ino!=inode and target.read_bytes()==data
    assert (directory/('original-'+path)/'captured').stat().st_ino==inode
    assert originals.publish_before_copy(root,directory,path)
    originals.restore_original(root,directory,path)
    originals.restore_original(root,directory,path)
    assert target.stat().st_ino==inode and target.read_bytes()==data
    if path=='index':
        assert stat.S_IMODE(target.stat().st_mode)==0o640
        assert os.getxattr(target,'user.original')==b'preserved'
        flags=subprocess.check_output(['/usr/bin/git','-c','core.fsmonitor=false','-C',str(root),'ls-files','-v'],
            env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'}).decode()
        assert flags.strip()=='h tracked'


@pytest.mark.parametrize('stage',['prepared','original_captured','copy_linked'])
def test_copy_publication_process_death_is_resumable(tmp_path,stage):
    root,directory,baseline=setup(tmp_path);inode=(root/'.git/index').stat().st_ino
    child=os.fork()
    if child==0:
        write=originals._write
        def prepared(parent,name,data):
            result=write(parent,name,data)
            if stage=='prepared' and name.startswith('index-attempt-'):os._exit(73)
            return result
        originals._write=prepared
        rename=custody._rename_noreplace
        def captured(source,name,destination,destname):
            result=rename(source,name,destination,destname)
            if stage=='original_captured' and name=='index':os._exit(73)
            return result
        custody._rename_noreplace=captured
        from agentporter.sandbox import workspace_delta as delta
        link=delta._publish_restore_fd
        def linked(parent,source,name):
            result=link(parent,source,name)
            if stage=='copy_linked' and name=='index':os._exit(73)
            return result
        delta._publish_restore_fd=linked
        try:originals.publish_before_copy(root,directory,'index')
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    originals.publish_before_copy(root,directory,'index')
    originals.restore_original(root,directory,'index')
    assert (root/'.git/index').stat().st_ino==inode


def test_later_equal_byte_owner_destination_is_preserved(tmp_path):
    root,directory,baseline=setup(tmp_path)
    originals.publish_before_copy(root,directory,'index')
    target=root/'.git/index';later=root/'.git/owner-index'
    info=target.stat();later.write_bytes(target.read_bytes());later.chmod(stat.S_IMODE(info.st_mode))
    os.utime(later,ns=(info.st_atime_ns,info.st_mtime_ns));later.replace(target);owner=target.stat().st_ino
    with pytest.raises(PermissionError,match='later owner destination'):
        originals.restore_original(root,directory,'index')
    assert target.stat().st_ino==owner
    assert (directory/'original-index/captured').stat().st_ino==baseline['manifest']['files']['index']['identity'][1]


def test_proven_after_entry_is_retained_and_original_inode_restored(tmp_path):
    root,directory,baseline=setup(tmp_path)
    originals.publish_before_copy(root,directory,'index')
    target=root/'.git/index';after=root/'.git/after'
    after.write_bytes(b'proven native output');after.replace(target)
    descriptor=os.open(target,os.O_RDONLY)
    try:
        from agentporter.sandbox.workspace_delta import _file_signature
        info=os.fstat(descriptor)
        import hashlib
        record={'signature':list(_file_signature(info)),'sha256':hashlib.sha256(b'proven native output').hexdigest(),
                'uid':info.st_uid,'gid':info.st_gid,'xattrs':{}}
        result=originals.restore_original(root,directory,'index',proven_after=record)
        assert result['state']=='restored'
        assert (directory/'displaced-index/captured').stat().st_ino==info.st_ino
    finally:os.close(descriptor)
    assert target.stat().st_ino==baseline['manifest']['files']['index']['identity'][1]


def test_owner_capture_then_process_death_restores_owner_before_original(tmp_path):
    root,directory,baseline=setup(tmp_path)
    originals.publish_before_copy(root,directory,'index')
    child=os.fork()
    if child==0:
        move=custody._rename_noreplace
        def owner(source,name,destination,destname):
            if name=='index':
                target=root/'.git/index';later=root/'.git/owner-new'
                later.write_bytes(b'owner entry must survive');later.replace(target)
                result=move(source,name,destination,destname);os._exit(73)
            return move(source,name,destination,destname)
        custody._rename_noreplace=owner
        try:originals.restore_original(root,directory,'index')
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    with pytest.raises(PermissionError,match='owner metadata restored'):
        originals.restore_original(root,directory,'index')
    assert (root/'.git/index').read_bytes()==b'owner entry must survive'
    assert (directory/'original-index/captured').stat().st_ino==baseline['manifest']['files']['index']['identity'][1]


@pytest.mark.parametrize('path',['config','refs/heads/main','packed-refs'])
def test_original_preservation_cannot_target_protected_or_ref_metadata(tmp_path,path):
    root,directory,baseline=setup(tmp_path)
    with pytest.raises(PermissionError):originals.publish_before_copy(root,directory,path)


def test_owner_swap_between_classification_and_displacement_is_not_blessed(tmp_path,monkeypatch):
    root,directory,baseline=setup(tmp_path)
    originals.publish_before_copy(root,directory,'index')
    original=originals._matches;owner=[]
    def raced(source,path,record):
        result=original(source,path,record)
        if result and not owner:
            target=root/'.git/index';info=target.stat();later=root/'.git/new-owner'
            later.write_bytes(target.read_bytes());later.chmod(stat.S_IMODE(info.st_mode))
            os.utime(later,ns=(info.st_atime_ns,info.st_mtime_ns));later.replace(target)
            owner.append(target.stat().st_ino)
        return result
    monkeypatch.setattr(originals,'_matches',raced)
    with pytest.raises(PermissionError,match='identity changed'):
        originals.restore_original(root,directory,'index')
    assert (root/'.git/index').stat().st_ino==owner[0]


def test_original_storage_inside_workspace_refuses_before_creation(tmp_path):
    root,directory,baseline=setup(tmp_path)
    forbidden=root/'unsafe-originals'
    with pytest.raises(PermissionError,match='entire workspace'):
        originals.prepare(root,directory.parent/'raw-before',baseline['sha256'],forbidden)
    assert not forbidden.exists()
