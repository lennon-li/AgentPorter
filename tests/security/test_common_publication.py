"""Real disposable topology, with only root seal/idmap provisioning simulated."""
from copy import deepcopy
import json
import os
from pathlib import Path
import pytest
from agentporter.sandbox import common_publication as api


@pytest.fixture
def domain(tmp_path,monkeypatch):
    root=tmp_path/'common';root.mkdir()
    project=root/'selected';project.mkdir();(project/'ordinary').write_bytes(b'original')
    state=root/'.private';state.mkdir(mode=0o700)
    def identity(path):
        fd=os.open(path,api.FLAGS)
        try:return api._identity(fd)
        finally:os.close(fd)
    fd=os.open(root,api.FLAGS)
    try:mount=api._mount(fd)
    finally:os.close(fd)
    value={'source_root':str(root),'source_identity':identity(root),'view_root':str(root),'view_identity':identity(root),
           'mount_id':mount,'mount_namespace':api._namespace('mnt'),'user_namespace':api._namespace('user'),'uid_map':[[0,0,1],[os.getuid(),os.getuid(),1]],
           'gid_map':[[0,0,1],[os.getgid(),os.getgid(),1]],
           'projects':[{'canonical':str(project),'identity':identity(project)}],
           'state':{'canonical':str(state),'mapped':str(state),'identity':identity(state)}}
    manifest={'version':1,'domains':[value]};manifest['manifest_sha256']=api._digest(manifest)
    monkeypatch.setattr(api,'_load',lambda:manifest)
    monkeypatch.setattr(api,'VIEW_ROOT',tmp_path)
    original=api._open
    monkeypatch.setattr(api,'_open',lambda path,**kw:original(path,path_only=kw.get('path_only',False)))
    return project,state,value


def selected(project,state):
    fd=os.open(project,api.FLAGS)
    try:return api.open_common_publication(fd,state_dir=state)
    finally:os.close(fd)


def test_absent_manifest_returns_no_override(tmp_path,monkeypatch):
    monkeypatch.setattr(api,'MANIFEST',tmp_path/'nonexistent/manifest.json')
    # Root sealing is separately tested; missing system parent must preserve old loader.
    original=api._open
    monkeypatch.setattr(api,'_open',lambda path,**kw:original(path))
    assert api.open_common_publication(-1,state_dir=None) is None


def test_common_domain_pins_only_selected_fd_and_preserves_original_inode(domain):
    project,state,value=domain;fd=selected(project,state)
    try:
        assert os.fstat(fd).st_ino==project.stat().st_ino
        assert not os.get_inheritable(fd)
        from agentporter.sandbox import workspace_custody as custody
        from agentporter.sandbox.workspace_delta import _file_signature
        import hashlib,stat
        target=project/'ordinary';info=target.stat()
        record={'signature':list(_file_signature(info)),'sha256':hashlib.sha256(b'original').hexdigest(),
                'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'xattrs':{}}
        pinned='/proc/self/fd/'+str(fd)+'/.'
        assert custody.capture_workspace_entry(pinned,'ordinary',state/'operation',expected_record=record)['state']=='captured_expected'
        assert (state/'operation/captured').stat().st_ino==info.st_ino
        assert custody.restore_custody(pinned,state/'operation')['state']=='restored'
        assert target.stat().st_ino==info.st_ino
    finally:os.close(fd)


@pytest.mark.parametrize('kind',['unlisted','duplicate','wrong_mount','wrong_project','wrong_ancestor','wrong_map','root_map',
                                  'state_alias','state_mode','state_identity','overlap','symlink','nested_mount'])
def test_manifest_cannot_broaden_or_replace_bound_domain(domain,monkeypatch,kind):
    project,state,value=domain
    if kind=='unlisted':value['projects'][0]['canonical']=str(project.parent/'other')
    elif kind=='duplicate':value['projects']*=26
    elif kind=='wrong_mount':value['mount_id']+=1
    elif kind=='wrong_project':value['projects'][0]['identity'][1]+=1
    elif kind=='wrong_ancestor':value['source_identity'][1]+=1
    elif kind=='wrong_map':value['uid_map'][1][1]+=1
    elif kind=='root_map':value['gid_map'][0]=[1,0,1]
    elif kind=='state_alias':state=state.parent/'other'
    elif kind=='state_mode':state.chmod(0o755)
    elif kind=='state_identity':value['state']['identity'][1]+=1
    elif kind=='overlap':value['state']['canonical']=str(project/'private');value['state']['mapped']=str(project/'private');state=project/'private'
    elif kind=='symlink':project.rename(project.with_name('old'));project.symlink_to(project.with_name('old'))
    elif kind=='nested_mount':
        original=api._mount
        monkeypatch.setattr(api,'_mount',lambda fd:original(fd)+(os.fstat(fd).st_ino==project.stat().st_ino))
    with pytest.raises((PermissionError,OSError)):selected(project,state)


def test_installed_manifest_requires_actual_passed_state(domain):
    project,_,_=domain
    with pytest.raises(PermissionError,match='actual transaction state'):selected(project,None)


@pytest.mark.parametrize('kind',['writable','foreign','hardlink','symlink','duplicates','hash'])
def test_manifest_file_must_be_root_sealed_and_exact_json(tmp_path,monkeypatch,kind):
    root=tmp_path/'sealed';root.mkdir();path=root/'manifest.json'
    data={'version':1,'domains':[{}]};data['manifest_sha256']=api._digest(data)
    path.write_text(json.dumps(data));path.chmod(0o644)
    monkeypatch.setattr(api,'MANIFEST',path)
    # Simulate ONLY a provisioned root directory and root file identity. All
    # file type/link/mode/hash and nofollow checks remain actual.
    original_open=api._open;monkeypatch.setattr(api,'_open',lambda p,**kw:original_open(p))
    original_fstat=api.os.fstat
    from types import SimpleNamespace
    def root_info(fd):
        value=original_fstat(fd)
        if os.readlink('/proc/self/fd/'+str(fd))==str(path):
            fields={name:getattr(value,name) for name in ['st_dev','st_ino','st_mode','st_nlink','st_size','st_uid','st_gid','st_mtime_ns','st_ctime_ns']}
            fields.update(st_uid=1 if kind=='foreign' else 0,st_gid=0)
            return SimpleNamespace(**fields)
        return value
    monkeypatch.setattr(api.os,'fstat',root_info)
    if kind=='writable':path.chmod(0o666)
    elif kind=='hardlink':os.link(path,root/'alias')
    elif kind=='symlink':path.rename(root/'target');path.symlink_to(root/'target')
    elif kind=='duplicates':path.write_text('{"version":1,"version":1}')
    elif kind=='hash':path.write_text(json.dumps({**data,'manifest_sha256':'0'*64}))
    with pytest.raises((PermissionError,OSError)):api._load()


def test_common_state_validation_precedes_any_transaction_state_write(domain,monkeypatch):
    project,state,value=domain
    state.chmod(0o777)
    uid=os.getuid();monkeypatch.setattr(os,"getuid",lambda:uid+1)
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    with pytest.raises(PermissionError):WorkspaceTransaction(project,state)
    assert list(state.iterdir())==[]


def test_private_intermediate_ancestor_must_also_be_owner_private(domain):
    project,state,value=domain
    child=state/'transactions';child.mkdir(mode=0o700)
    fd=os.open(child,api.FLAGS)
    try:value['state']={'canonical':str(child),'mapped':str(child),'identity':api._identity(fd)}
    finally:os.close(fd)
    state.chmod(0o755)
    with pytest.raises(PermissionError,match='private state ancestor'):selected(project,child)


def test_systemd_cloned_mount_namespace_pins_current_mount_without_same_device_fallback(domain):
    project,state,value=domain;value['mount_namespace'][1]+=1;value['mount_id']+=9000
    fd=selected(project,state)
    try:assert os.fstat(fd).st_ino==project.stat().st_ino
    finally:os.close(fd)


@pytest.mark.parametrize('target',['project','state'])
def test_other_namespace_still_refuses_different_current_child_mount(domain,monkeypatch,target):
    project,state,value=domain;value['mount_namespace'][1]+=1;value['mount_id']+=9000
    inode=(project if target=='project' else state).stat().st_ino;original=api._mount
    monkeypatch.setattr(api,'_mount',lambda fd:original(fd)+(os.fstat(fd).st_ino==inode))
    with pytest.raises(PermissionError,match='mount'):selected(project,state)


def test_user_namespace_mismatch_never_bypasses_mount_attestation(domain):
    project,state,value=domain;value['mount_namespace'][1]+=1;value['user_namespace'][1]+=1
    with pytest.raises(PermissionError,match='user namespace'):selected(project,state)


def test_dynamic_exact_27th_child_is_selected_without_wildcard(domain):
    project,state,value=domain
    for index in range(26):
        path=project.parent/f'new-project-{index}';path.mkdir()
        fd=os.open(path,api.FLAGS)
        try:identity=api._identity(fd)
        finally:os.close(fd)
        value['projects'].append({'canonical':str(path),'identity':identity})
    assert len(value['projects'])==27
    fd=selected(project,state)
    try:assert os.fstat(fd).st_ino==project.stat().st_ino
    finally:os.close(fd)
    unlisted=project.parent/'unlisted-new';unlisted.mkdir()
    with pytest.raises(PermissionError):selected(unlisted,state)


@pytest.mark.parametrize('count',[0,513])
def test_dynamic_common_selection_is_still_bounded(domain,count):
    project,state,value=domain
    value['projects']*=count
    with pytest.raises(PermissionError):selected(project,state)
