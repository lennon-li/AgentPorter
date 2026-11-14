"""Synthetic metadata/objects only; never inspect real repositories or credentials."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import zlib

import pytest

from agentporter.sandbox import git_snapshot as snapshots
from agentporter.sandbox.git_snapshot import SnapshotBudget, source_object, signature
from agentporter.sandbox.workspace_git import WorkspaceGitHistory
from agentporter.git_commits import _inspect_metadata, _mount_id
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from tests.security.test_git_approval_state import setup, git
from tests.security.test_workspace_transactions import RecordingResources


def tree(tmp_path, name='source', body=b'1234'):
    root = tmp_path/name; root.mkdir(); (root/'file').write_bytes(body)
    return root


def copy(budget, source, target):
    fd=os.open(source,snapshots.FLAGS)
    try:
        plan=budget.preflight(fd,target.parent)
        return budget.copy(fd,target,plan)
    finally:os.close(fd)


def test_base_budget_is_640MiB_and_counts_all_copies(tmp_path,monkeypatch):
    assert snapshots.BASE_SNAPSHOT_LIMIT == 640 * 1024 * 1024
    monkeypatch.setattr(snapshots,'BASE_SNAPSHOT_LIMIT',8)
    budget=SnapshotBudget();a=tree(tmp_path,'a');b=tree(tmp_path,'b');c=tree(tmp_path,'c',b'x')
    copy(budget,a,tmp_path/'first');copy(budget,b,tmp_path/'second')
    assert budget.bytes==0
    with pytest.raises(PermissionError,match='aggregate byte'):copy(budget,c,tmp_path/'third')
    assert not (tmp_path/'third').exists()


@pytest.mark.parametrize('kind',['bytes','entries','deadline','space'])
def test_preflight_refuses_before_any_destination_bytes(tmp_path,monkeypatch,kind):
    source=tree(tmp_path);budget=SnapshotBudget()
    if kind=='bytes':budget.bytes=3
    elif kind=='entries':budget.entries=0
    elif kind=='deadline':budget.deadline=0
    else:monkeypatch.setattr(snapshots.os,'statvfs',lambda _:SimpleNamespace(f_bavail=0,f_frsize=4096))
    with pytest.raises(PermissionError):copy(budget,source,tmp_path/'private')
    assert not (tmp_path/'private').exists()


@pytest.mark.parametrize('kind',['growth','replace','mode','deadline','space'])
def test_stream_refuses_source_races_deadline_and_space_loss(tmp_path,monkeypatch,kind):
    source=tree(tmp_path);budget=SnapshotBudget();fd=os.open(source,snapshots.FLAGS)
    try:
        plan=budget.preflight(fd,tmp_path);read=os.read;triggered=False
        def changed(fd,size):
            nonlocal triggered
            result=read(fd,size)
            if result and not triggered:
                triggered=True
                if kind=='growth':(source/'file').write_bytes(b'123456789')
                elif kind=='replace':(source/'file').rename(source/'retained');(source/'file').write_bytes(b'1234')
                elif kind=='mode':(source/'file').chmod(0o400)
                elif kind=='deadline':budget.deadline=0
                else:monkeypatch.setattr(snapshots.os,'fstatvfs',lambda _:SimpleNamespace(f_bavail=0,f_frsize=4096))
            return result
        monkeypatch.setattr(snapshots.os,'read',changed)
        with pytest.raises(PermissionError):budget.copy(fd,tmp_path/'private',plan)
        assert (source/'file').exists()
    finally:os.close(fd)


def test_preflight_then_growth_is_refused(tmp_path):
    source=tree(tmp_path);budget=SnapshotBudget();fd=os.open(source,snapshots.FLAGS)
    try:
        plan=budget.preflight(fd,tmp_path);(source/'file').write_bytes(b'12345')
        with pytest.raises(PermissionError,match='after preflight'):budget.copy(fd,tmp_path/'private',plan)
    finally:os.close(fd)


def test_source_exception_requires_object_shape_owner_mode(tmp_path):
    source=tree(tmp_path);p=source/'file';p.chmod(0o444);os.link(p,source/'other');i=p.stat();owner=(i.st_uid,i.st_gid)
    path='objects/aa/'+'b'*38
    assert source_object(path,i,owner)
    assert not source_object(path,i,(i.st_uid+1,i.st_gid))
    for bad in ['config','index','refs/heads/main','objects/info/alternates','objects/pack/pack-'+ 'b'*40+'.bitmap']:
        assert not source_object(bad,i,owner)
    p.chmod(0o644);assert not source_object(path,p.stat(),owner)
    p.chmod(0o555);assert not source_object(path,p.stat(),owner)
    changed=SimpleNamespace(**{name:getattr(i,name) for name in
        ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},st_atime_ns=i.st_atime_ns+1)
    assert signature(changed)==signature(i)  # atime is not authority


@pytest.fixture
def repository(tmp_path,monkeypatch,request):
    monkeypatch.setenv('GIT_CONFIG_GLOBAL','/dev/null');monkeypatch.setenv('GIT_CONFIG_NOSYSTEM','1')
    monkeypatch.setenv('GIT_DEFAULT_HASH',getattr(request,'param','sha1'))
    root,_,initial=setup(tmp_path)
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    (sandbox.state_dir/'workspace-transactions').mkdir(exist_ok=True)
    return root,sandbox


def share(root,outside,packed=False):
    if packed:git(root,'repack','-ad')
    outside.mkdir()
    before={}
    for n,p in enumerate((root/'.git/objects').rglob('*')):
        if p.is_file() and p.relative_to(root/'.git').parts[:2] != ('objects','info'):
            # Newer Git versions also write reverse indexes. The supported
            # shared-source exception covers object data and its pack index;
            # leave optional sidecars private to the source repository.
            if p.parent.name=='pack' and p.suffix not in {'.pack','.idx'}:
                continue
            p.chmod(0o444);os.link(p,outside/str(n));before[p]=signature(p.stat()),hashlib.sha256(p.read_bytes()).hexdigest()
    return before


@pytest.mark.parametrize('packed',[False,True])
@pytest.mark.parametrize('reverse_index',[False,True])
@pytest.mark.parametrize('repository',['sha1','sha256'],indirect=True)
def test_shared_source_objects_become_private_inodes_and_commit_safely(repository,tmp_path,packed,reverse_index):
    root,sandbox=repository
    git(root,'config','pack.writeReverseIndex','true' if reverse_index else 'false')
    before=share(root,tmp_path/'outside',packed)
    sidecars={p:(signature(p.stat()),hashlib.sha256(p.read_bytes()).hexdigest())
              for p in (root/'.git/objects/pack').glob('*.rev')}
    if packed and reverse_index:assert sidecars
    fd=os.open(root/'.git',snapshots.FLAGS)
    try:
        with pytest.raises(PermissionError):_inspect_metadata(fd,_mount_id(fd))
    finally:os.close(fd)
    item=WorkspaceGitHistory(root,tmp_path/'history',sandbox)
    try:
        assert item.shared_sources
        for source in before:
            private=item.private/source.relative_to(root/'.git')
            assert private.stat().st_nlink==1 and private.stat().st_ino!=source.stat().st_ino
        (root/'ordinary').write_text('changed')
        def private(*args):return git(root,'--git-dir='+str(item.private),'--work-tree='+str(root),*args)
        private('add','ordinary');private('-c','user.name=Fixture','-c','user.email=f@example.invalid','commit','-qm','private')
        item.prepare();item.guard_publication();item.publish();item.finish()
        assert git(root,'log','-1','--format=%s')=='private'
        for source,(record,digest) in before.items():
            assert signature(source.stat())==record and hashlib.sha256(source.read_bytes()).hexdigest()==digest
        for source,(record,digest) in sidecars.items():
            private=item.private/source.relative_to(root/'.git')
            assert source.stat().st_nlink==private.stat().st_nlink==1
            assert source.stat().st_ino!=private.stat().st_ino
            assert signature(source.stat())==record and hashlib.sha256(source.read_bytes()).hexdigest()==digest
    finally:item.close()


@pytest.mark.parametrize('kind',['plaintext_secret','wrong_oid','writable','sidecar','reverse_index','control','index'])
def test_bad_shared_sources_never_reach_worker(repository,tmp_path,kind):
    root,sandbox=repository;outside=tmp_path/'outside';outside.mkdir()
    if kind=='plaintext_secret':path=root/'.git/objects/aa'/('b'*38);body=b'SYNTHETIC_SECRET_NOT_A_GIT_OBJECT'
    elif kind=='wrong_oid':path=root/'.git/objects/aa'/('b'*38);body=zlib.compress(b'blob 7\0secret\n')
    elif kind=='sidecar':path=root/'.git/objects/pack'/('pack-'+'a'*40+'.bitmap');body=b'sidecar'
    elif kind=='reverse_index':path=root/'.git/objects/pack'/('pack-'+'a'*40+'.rev');body=b'reverse-index-sidecar'
    elif kind=='control':path=root/'.git/config';body=None
    elif kind=='index':path=root/'.git/index';body=None
    else:path=root/'.git/objects/aa'/('b'*38);body=b'writable'
    path.parent.mkdir(exist_ok=True)
    if body is not None:path.write_bytes(body)
    path.chmod(0o644 if kind=='writable' else 0o444);os.link(path,outside/'alias')
    before=signature(path.stat())
    with pytest.raises(PermissionError):WorkspaceGitHistory(root,tmp_path/'history',sandbox)
    assert signature(path.stat())==before


@pytest.mark.parametrize('kind',['idx_corrupt','missing_pair','private_alias','private_object_alias','source_changed'])
def test_private_validation_and_source_recheck_fail_closed(repository,tmp_path,kind):
    root,sandbox=repository;before=share(root,tmp_path/'outside',True)
    item=WorkspaceGitHistory(root,tmp_path/'history',sandbox)
    try:
        idx=next((item.private/'objects/pack').glob('*.idx'))
        if kind=='idx_corrupt':idx.write_bytes(b'bad index')
        elif kind=='missing_pair':idx.unlink()
        elif kind=='private_alias':os.link(item.private/'HEAD',tmp_path/'alias')
        elif kind=='private_object_alias':os.link(idx,tmp_path/'alias')
        else:
            source=next(iter(before));source.chmod(0o644);source.write_bytes(b'changed');source.chmod(0o444)
        with pytest.raises(PermissionError):
            if kind in {'idx_corrupt','missing_pair'}:item._validate_shared_objects()
            else:item.prepare()
    finally:item.close()


def test_whole_transaction_nested_histories_share_budget_and_cleanup(repository,tmp_path,monkeypatch):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root,sandbox=repository
    child=root/'child';child.mkdir();git(child,'init','-q','-b','main')
    (child/'ordinary').write_text('child');git(child,'add','ordinary')
    git(child,'-c','user.name=Fixture','-c','user.email=f@example.invalid','commit','-qm','child')
    totals=[sum(p.stat().st_size for p in d.rglob('*') if p.is_file()) for d in [root/'.git',child/'.git']]
    monkeypatch.setattr(snapshots,'BASE_SNAPSHOT_LIMIT',max(totals)+1)
    state=sandbox.state_dir/'workspace-transactions'
    with pytest.raises(PermissionError,match='aggregate byte'):
        WorkspaceTransaction(root,state,git_sandbox=sandbox)
    assert not [p for p in state.iterdir() if p.is_dir()]
    assert (root/'ordinary').read_text()=='initial' and (child/'ordinary').read_text()=='child'


def test_invalid_source_validation_releases_admission_and_partial_copy(repository,tmp_path):
    from agentporter.tools.jobs import JobManager
    from agentporter.agents.policy import ExecutionPolicy
    root,sandbox=repository
    invalid=root/'.git/objects/aa'/('b'*38);invalid.parent.mkdir();invalid.write_bytes(b'SYNTHETIC_SECRET')
    invalid.chmod(0o444);os.link(invalid,tmp_path/'external-alias')
    before=signature(invalid.stat())
    class Runtime:
        def status(self,*args):return {'delegatable':True}
        def prepare(self,*args,**kwargs):raise AssertionError('Worker launch must not be reached')
    manager=JobManager(tmp_path/'manager',transactional_writes=True)
    manager.development_runtime=Runtime();manager.git_sandbox=sandbox;manager.resources=RecordingResources()
    with pytest.raises(PermissionError):
        manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),cmd=['/usr/bin/true'],
            agent='copilot_agent',policy=ExecutionPolicy.for_workspace(True))
    with manager._get_db() as db:
        assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==0
    assert not [p for p in (manager.state_dir/'workspace-transactions').iterdir() if p.is_dir()]
    assert signature(invalid.stat())==before


def test_successful_publication_retains_custody_including_base_copy(repository):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root,sandbox=repository
    transaction=WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox)
    directory=transaction.directory
    (transaction.upper/'ordinary').write_text('changed')
    transaction.publish();transaction.close()
    assert transaction._applied and transaction._retain_directory
    assert directory.is_dir() and (directory/'git-0/metadata/objects').is_dir()
    assert (root/'ordinary').read_text()=='changed'


def test_generic_direct_mount_stays_strict(repository,tmp_path):
    from agentporter.git_commits import _MetadataMount
    root,sandbox=repository;share(root,tmp_path/'outside')
    item=WorkspaceGitHistory(root,tmp_path/'history',sandbox)
    try:
        i=root.stat()
        with pytest.raises(PermissionError):
            _MetadataMount({'repository_path':str(root),'repository_device':i.st_dev,
                'repository_inode':i.st_ino,'expected_tree':item.before['tree']})
    finally:item.close()


def test_actual_stream_budget_cannot_be_replaced_by_preflight(tmp_path):
    source=tree(tmp_path);budget=SnapshotBudget();fd=os.open(source,snapshots.FLAGS)
    try:
        plan=budget.preflight(fd,tmp_path);budget.bytes=3
        with pytest.raises(PermissionError,match='aggregate byte'):budget.copy(fd,tmp_path/'private',plan)
    finally:os.close(fd)


def test_two_preflights_cannot_bypass_decreasing_stream_headroom(tmp_path,monkeypatch):
    a=tree(tmp_path,'a',b'x'*131072);b=tree(tmp_path,'b',b'y'*131072)
    one=SnapshotBudget();two=SnapshotBudget();left=os.open(a,snapshots.FLAGS);right=os.open(b,snapshots.FLAGS)
    try:
        first=one.preflight(left,tmp_path);second=two.preflight(right,tmp_path)
        availability=iter([snapshots.FREE_HEADROOM+n for n in
            (4*65536,3*65536,2*65536,65536,65535)])
        monkeypatch.setattr(snapshots.os,'fstatvfs',lambda _:SimpleNamespace(f_bavail=next(availability),f_frsize=1))
        one.copy(left,tmp_path/'first',first)
        with pytest.raises(PermissionError,match='lost free-space'):two.copy(right,tmp_path/'second',second)
        assert (tmp_path/'first/file').stat().st_size==131072
        assert (tmp_path/'second/file').stat().st_size==0
    finally:os.close(left);os.close(right)


def test_unpublished_shared_source_transaction_abort_cleans_only_private_copy(repository,tmp_path):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root,sandbox=repository;before=share(root,tmp_path/'outside',True)
    transaction=WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox)
    directory=transaction.directory;(transaction.upper/'ordinary').write_text('unpublished')
    transaction.close()
    assert not directory.exists() and (root/'ordinary').read_text()=='initial'
    for source,(record,digest) in before.items():
        assert signature(source.stat())==record and hashlib.sha256(source.read_bytes()).hexdigest()==digest


def test_raw_before_chunks_guard_headroom_and_constructor_cleans_partial_state(repository,monkeypatch):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root,sandbox=repository
    log=root/'.git/synthetic-log';log.write_bytes(b'x'*200000)
    original=snapshots.os.fstatvfs
    def decreasing(fd):
        name=os.readlink('/proc/self/fd/'+str(fd))
        if '/raw-before/blobs/' in name and os.fstat(fd).st_size>=65536:
            return SimpleNamespace(f_bavail=snapshots.FREE_HEADROOM+65535,f_frsize=1)
        return original(fd)
    monkeypatch.setattr(snapshots.os,'fstatvfs',decreasing)
    state=sandbox.state_dir/'workspace-transactions'
    with pytest.raises(PermissionError,match='lost free-space'):
        WorkspaceTransaction(root,state,git_sandbox=sandbox)
    assert not [p for p in state.iterdir() if p.is_dir()]
    assert log.stat().st_size==200000


def test_initial_raw_budget_is_separate_aggregate_256MiB(tmp_path):
    assert snapshots.RAW_SNAPSHOT_LIMIT==256*1024*1024
    budget=SnapshotBudget();budget.raw_bytes=8
    target=tmp_path/'raw';fd=os.open(target,os.O_CREAT|os.O_RDWR,0o600)
    try:
        budget.guard_raw_write(fd,4);budget.guard_raw_write(fd,4)
        assert budget.raw_bytes==0 and budget.bytes==snapshots.BASE_SNAPSHOT_LIMIT
        with pytest.raises(PermissionError,match='raw Git snapshots'):budget.guard_raw_write(fd,1)
    finally:os.close(fd)
    source=tree(tmp_path);sourcefd=os.open(source,snapshots.FLAGS)
    try:
        with pytest.raises(PermissionError,match='raw Git snapshots'):budget.preflight(sourcefd,tmp_path)
    finally:os.close(sourcefd)
