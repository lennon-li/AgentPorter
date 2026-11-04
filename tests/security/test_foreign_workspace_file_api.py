"""Native descriptor reads/search; simulated UID boundary, never host mount setup."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentporter.sandbox import workspace_projections as projections
from agentporter.tools.files import create_file_tools
from agentporter.workspaces import bounded


@pytest.fixture
def foreign(tmp_path, monkeypatch):
    root=tmp_path/'foreign';root.mkdir(mode=0o700)
    (root/'ordinary.txt').write_bytes('one\u2028two\r\nthree\n'.encode())
    (root/'child').mkdir();(root/'child'/'nested.txt').write_text('needle ordinary')
    (root/'secrets.env').write_text('needle PRIVATE')
    original_open=os.open;original_fstat=os.fstat;seen=[]
    root_id=(root.stat().st_dev,root.stat().st_ino)
    def foreign_source(fd):
        info=original_fstat(fd)
        if (info.st_dev,info.st_ino)==root_id and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_PATH:
            fields={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
            fields['st_uid']=info.st_uid+1
            return SimpleNamespace(**fields)
        return info
    monkeypatch.setattr(bounded.os,'fstat',foreign_source)
    def deny_raw(path, flags, *args, **kwargs):
        if os.fspath(path)==str(root) and not flags&os.O_PATH:
            raise PermissionError(errno.EACCES,'synthetic foreign canonical root')
        return original_open(path,flags,*args,**kwargs)
    monkeypatch.setattr(bounded.os,'open',deny_raw)
    def lower(source):
        assert fcntl.fcntl(source,fcntl.F_GETFL)&os.O_PATH
        st=os.fstat(source);expected=root.stat()
        assert (st.st_dev,st.st_ino)==(expected.st_dev,expected.st_ino)
        # Root-only idmapped RO mount cannot be provisioned in this test.
        # Existing projection verifier has its own adversarial tests.
        fd=original_open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        seen.append(fd);return fd
    monkeypatch.setattr(projections,'open_workspace_projection',lower)
    monkeypatch.setattr(projections,'open_workspace_publication',lambda *a,**k:pytest.fail('RW publication view requested'))
    registry=SimpleNamespace(get=lambda name:SimpleNamespace(path=str(root),writable=False))
    return root,create_file_tools(registry),seen


def assert_closed(fds):
    assert fds
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)


def test_foreign_read_and_unicode_ranged_typed_contract_uses_ro_lower(foreign, monkeypatch):
    root,tools,seen=foreign
    monkeypatch.setattr(os.path,'isfile',lambda *a:pytest.fail('raw canonical isfile TOCTOU'))
    data=(root/'ordinary.txt').read_bytes()
    result=tools[2]('project','ordinary.txt',start_line=2,end_line=40)
    assert result=={'path':'ordinary.txt','content':'two\r\nthree\n',
                    'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data),
                    'total_lines':3,'range':{'start_line':2,'end_line':40}}
    assert_closed(seen)


def test_foreign_list_and_actual_native_rg_use_held_ro_fd(foreign):
    root,tools,seen=foreign
    assert tools[0]('project')==['child/nested.txt','ordinary.txt']
    assert tools[0]('project','child')==['child/nested.txt']
    assert tools[1]('project','needle')==[{'path':'child/nested.txt','line':1,'text':'needle ordinary'}]
    assert_closed(seen)


@pytest.mark.parametrize('operation',[0,1,2])
def test_missing_or_rejected_projection_never_falls_back_to_raw_access(foreign,monkeypatch,operation):
    root,tools,seen=foreign
    def refuse(fd):raise PermissionError('owner-provisioned projection denied')
    monkeypatch.setattr(projections,'open_workspace_projection',refuse)
    args=[('project',),('project','needle'),('project','ordinary.txt')][operation]
    with pytest.raises(PermissionError,match='projection denied'):tools[operation](*args)
    assert not seen


@pytest.mark.parametrize('kind',['symlink_leaf','symlink_parent','hardlink','fifo','sensitive','escape','budget'])
def test_foreign_lower_cannot_bypass_read_boundaries(foreign,kind):
    root,tools,seen=foreign;path='ordinary.txt'
    if kind=='symlink_leaf':
        (root/'alias').symlink_to('ordinary.txt');path='alias'
    elif kind=='symlink_parent':
        (root/'alias').symlink_to('child',target_is_directory=True);path='alias/nested.txt'
    elif kind=='hardlink':os.link(root/'ordinary.txt',root/'alias');path='alias'
    elif kind=='fifo':os.mkfifo(root/'pipe');path='pipe'
    elif kind=='sensitive':path='secrets.env'
    elif kind=='escape':path='../outside'
    else:
        with (root/'large').open('wb') as stream:stream.truncate(2**24)
        path='large'
    with pytest.raises((ValueError,OSError)):tools[2]('project',path)
    if seen:assert_closed(seen)


def test_search_does_not_return_sensitive_hardlink_alias(foreign):
    root,tools,seen=foreign
    os.link(root/'secrets.env',root/'innocent.txt')
    assert tools[1]('project','PRIVATE')==[]
    assert_closed(seen)


def test_capture_accepts_only_internal_rg_directory_fd_and_closes_child_lifetime(tmp_path):
    (tmp_path/'one').write_text('needle')
    fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    root=f'/proc/self/fd/{fd}/.'
    try:
        code,out,err=bounded.capture_bounded(['rg','--','needle',root],workspace_fd=fd)
        assert code==0 and out.endswith('/./one:needle\n') and not err
        for command in (['python3','-c','pass',root],['rg','--','needle',str(tmp_path)]):
            with pytest.raises(ValueError,match='descriptor'):bounded.capture_bounded(command,workspace_fd=fd)
    finally:os.close(fd)
    source=os.open(tmp_path,os.O_PATH|os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError,match='descriptor'):
            bounded.capture_bounded(['rg','needle',f'/proc/self/fd/{source}/.'],workspace_fd=source)
    finally:os.close(source)


@pytest.fixture
def foreign_writer(foreign,tmp_path,monkeypatch):
    from agentporter.workspaces import shared_access,leases
    from contextlib import contextmanager
    root,_,read_seen=foreign;state=tmp_path/'private-state';published=[];lease_calls=[]
    def publication(source,*,state_dir):
        assert Path(state_dir)==state
        assert fcntl.fcntl(source,fcntl.F_GETFL)&os.O_PATH
        fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=source)
        published.append(fd);return fd
    monkeypatch.setattr(projections,'open_workspace_publication',publication)
    monkeypatch.setattr(shared_access,'share',lambda *a,**k:pytest.fail('mapped writer must not add canonical ACL grants'))
    original_lease=leases.mutation_lease
    @contextmanager
    def once(*args,**kwargs):
        assert not lease_calls or lease_calls[-1]!='active','nested mutation lease'
        lease_calls.append('active')
        try:
            with original_lease(*args,**kwargs):yield
        finally:lease_calls.append('released')
    monkeypatch.setattr(leases,'mutation_lease',once)
    registry=SimpleNamespace(get=lambda name:SimpleNamespace(path=str(root),writable=True))
    return root,create_file_tools(registry,mutation_state_dir=state),state,published,lease_calls


def test_foreign_all_trusted_mutators_share_one_lease_and_preserve_canonical_scope(foreign_writer):
    root,tools,state,published,leases=foreign_writer
    metadata=(root.stat().st_uid,root.stat().st_gid,root.stat().st_mode)
    tools[5]('project','new/deep')
    tools[3]('project','new/deep/file.txt','before\n')
    before=(root/'new/deep/file.txt').stat().st_ino
    with pytest.raises(ValueError,match='Stale'):
        tools[3]('project','new/deep/file.txt','bad','0'*64)
    assert (root/'new/deep/file.txt').read_text()=='before\n'
    tools[3]('project','new/deep/file.txt','after\n',hashlib.sha256(b'before\n').hexdigest())
    assert (root/'new/deep/file.txt').stat().st_ino!=before
    patch='--- a/new/deep/file.txt\n+++ b/new/deep/file.txt\n@@ -1 +1 @@\n-after\n+patched\n--- /dev/null\n+++ b/patch/new.txt\n@@ -0,0 +1 @@\n+created\n'
    assert tools[4]('project',patch)['status']=='applied'
    assert (root/'new/deep/file.txt').read_text()=='patched\n'
    tools[6]('project','patch/new.txt','new/moved.txt')
    result=tools[7]('project','new/moved.txt')
    assert (root/result['trash_location']).read_text()=='created\n'
    assert tools[4]('project','--- a/new/deep/file.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-patched\n')['status']=='applied'
    assert not (root/'new/deep/file.txt').exists()
    assert (root.stat().st_uid,root.stat().st_gid,root.stat().st_mode)==metadata
    assert leases==['active','released']*8
    assert_closed(published)


@pytest.mark.parametrize('operation',[3,4,5,6,7])
def test_foreign_writer_projection_refusal_before_unscoped_publication(foreign_writer,monkeypatch,operation):
    root,tools,state,published,leases=foreign_writer
    def refuse(*a,**k):raise PermissionError('private state mount or selected inode mismatch')
    monkeypatch.setattr(projections,'open_workspace_publication',refuse)
    args={3:('project','new.txt','forbidden'),4:('project','--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+forbidden\n'),
          5:('project','newdir'),6:('project','ordinary.txt','moved.txt'),7:('project','ordinary.txt')}[operation]
    before=(root/'ordinary.txt').read_bytes()
    with pytest.raises(PermissionError,match='mismatch'):tools[operation](*args)
    assert (root/'ordinary.txt').read_bytes()==before and not (root/'new.txt').exists()
    assert not published and leases==['active','released']


def test_foreign_writer_keeps_pending_recovery_and_hardlink_symlink_denials(foreign_writer):
    from agentporter.workspaces.leases import workspace_key
    from agentporter.resources import ResourceCleanupError
    root,tools,state,published,leases=foreign_writer
    state.mkdir(mode=0o700)
    pending=state/(workspace_key(root.stat())+'.pending.json');pending.write_text('{}')
    with pytest.raises(ResourceCleanupError):tools[3]('project','new.txt','blocked')
    assert not published and pending.read_text()=='{}'
    pending.unlink()
    (root/'alias').symlink_to('ordinary.txt')
    os.link(root/'ordinary.txt',root/'hard')
    for path in ('alias','hard','secrets.env','../outside'):
        with pytest.raises((ValueError,OSError)):tools[3]('project',path,'blocked')
    for operation,args in ((6,('project','alias','moved')),(7,('project','hard')),(5,('project','alias/sub'))):
        with pytest.raises((ValueError,OSError)):tools[operation](*args)
    assert not (root/'moved').exists()
    assert_closed(published)


def test_native_search_colon_newline_and_blocked_hardlink_paths_are_unambiguous(tmp_path):
    root=tmp_path/'project';root.mkdir()
    (tmp_path/'owner-secret').write_text('SYNTHETIC-OWNER-SECRET\n')
    (root/'visible').write_text('harmless\n')
    os.link(tmp_path/'owner-secret',root/'visible:alias')
    (root/'ok:colon').write_text('needle colon\n')
    (root/'ok\nnewline').write_text('needle newline\n')
    (root/'secrets.env').write_text('needle SECRET\n')
    invalid=os.open(os.fsencode(root)+b'/invalid-\xff',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:os.write(invalid,b'needle invalid-encoding\n')
    finally:os.close(invalid)
    registry=SimpleNamespace(get=lambda name:SimpleNamespace(path=str(root),writable=False))
    tools=create_file_tools(registry)
    with pytest.raises(ValueError,match='hardlink'):tools[2]('p','visible:alias')
    assert tools[1]('p','SYNTHETIC-OWNER-SECRET')==[]
    assert sorted(tools[1]('p','needle'),key=lambda hit:hit['path'])==[
        {'path':'ok\nnewline','line':1,'text':'needle newline'},
        {'path':'ok:colon','line':1,'text':'needle colon'}]


def test_native_search_drops_file_replaced_after_rg_before_validated_read(tmp_path,monkeypatch):
    import agentporter.tools.files as files
    root=tmp_path/'project';root.mkdir()
    target=root/'visible';target.write_text('needle original\n')
    registry=SimpleNamespace(get=lambda name:SimpleNamespace(path=str(root),writable=False))
    tools=create_file_tools(registry);original=files.capture_bounded
    def replaced(*args,**kwargs):
        result=original(*args,**kwargs)
        replacement=root/'replacement';replacement.write_text('different bytes\n');os.replace(replacement,target)
        return result
    monkeypatch.setattr(files,'capture_bounded',replaced)
    assert tools[1]('p','needle')==[]
    assert target.read_text()=='different bytes\n'


def test_native_search_drops_replacement_hardlink_even_when_line_bytes_match(tmp_path,monkeypatch):
    import agentporter.tools.files as files
    root=tmp_path/'project';root.mkdir();target=root/'visible';target.write_text('needle\n')
    private=tmp_path/'private';private.write_text('needle\n')
    registry=SimpleNamespace(get=lambda name:SimpleNamespace(path=str(root),writable=False))
    tools=create_file_tools(registry);original=files.capture_bounded
    def replaced(*args,**kwargs):
        result=original(*args,**kwargs);target.unlink();os.link(private,target);return result
    monkeypatch.setattr(files,'capture_bounded',replaced)
    assert tools[1]('p','needle')==[]
