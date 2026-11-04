"""Optional root-sealed common publication domain; never a guest workspace grant.

The manifest is an owner provisioning attestation of the complete UID/GID map.
The loader also verifies observed source/mapped owners and pinned mount identities.
It does not provision mounts, create state, or infer authority from directory names.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

MANIFEST = Path('/etc/agentporter/common-publication-v1.json')
VIEW_ROOT = Path('/var/lib/agentporter/publication-domains')
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _require(value, message):
    if not value: raise PermissionError(message)


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _unique(pairs):
    result={}
    for key,value in pairs:
        _require(key not in result,'Duplicate common-domain manifest field');result[key]=value
    return result


def _path(value):
    _require(isinstance(value,str) and value.startswith('/') and value!='/'
             and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts and '\\' not in value,
             'Invalid common-domain absolute path')
    return Path(value)


def _open(path, *, trusted=False, path_only=False):
    path=_path(str(path));fd=os.open('/',FLAGS)
    try:
        for part in path.parts[1:]:
            child=os.open(part,(os.O_PATH if path_only else os.O_RDONLY)|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
            if trusted:
                info=os.fstat(fd)
                _require(info.st_uid==0 and not info.st_mode&0o022,'Unsealed common-domain ancestor')
        result,fd=fd,None;return result
    finally:
        if fd is not None:os.close(fd)


def _mount(fd):
    rows=[x.split(':',1)[1].strip() for x in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines() if x.startswith('mnt_id:')]
    _require(len(rows)==1 and rows[0].isdigit(),'Cannot bind common-domain mount');return int(rows[0])


def _namespace(kind):
    value=os.stat("/proc/self/ns/"+kind)
    return [value.st_dev,value.st_ino]


def _identity(fd):
    info=os.fstat(fd)
    return [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]


def _load():
    try:parent=_open(MANIFEST.parent,trusted=True)
    except FileNotFoundError:return None
    fd=None
    try:
        try:fd=os.open(MANIFEST.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        except FileNotFoundError:return None
        info=os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0
                 and info.st_nlink==1 and not info.st_mode&0o022 and info.st_size<=262144,
                 'Unsealed common-domain manifest')
        raw=os.pread(fd,262145,0)
        after=os.fstat(fd)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        _require(len(raw)==info.st_size and all(getattr(info,k)==getattr(after,k) for k in fields),'Common-domain manifest changed')
        value=json.loads(raw,object_pairs_hook=_unique)
        _require(set(value)=={'version','domains','manifest_sha256'} and value['version']==1
                 and value['manifest_sha256']==_digest({k:v for k,v in value.items() if k!='manifest_sha256'})
                 and isinstance(value['domains'],list) and 1<=len(value['domains'])<=2,'Invalid common-domain manifest')
        return value
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def _relative(root,path):
    value=_path(path)
    _require(value!=root and value.is_relative_to(root),'Common-domain entry escapes ancestor')
    return value.relative_to(root)


def open_common_publication(source_fd, *, state_dir):
    """Return only the selected child FD, or None when no manifest is installed.

    Once a manifest is installed, an unlisted source fails closed; there is no
    fallback that can bypass its state binding or mount checks.
    """
    manifest=_load()
    if manifest is None:return None
    _require(state_dir is not None,'Common publication requires actual transaction state path')
    source_path=_path(os.readlink('/proc/self/fd/'+str(source_fd)))
    state_path=_path(str(Path(state_dir).absolute()))
    matches=[]
    for domain in manifest['domains']:
        _require(set(domain)=={'source_root','source_identity','view_root','view_identity','mount_id',
                              'uid_map','gid_map','projects','state','mount_namespace','user_namespace'},'Unexpected common-domain field')
        projects=domain['projects']
        _require(isinstance(projects,list) and 1<=len(projects)<=512,'Common domain must bind a bounded exact project selection')
        canonical=[]
        for entry in projects:
            _require(set(entry)=={'canonical','identity'},'Invalid selected common-domain entry')
            canonical.append(entry['canonical'])
        _require(len(set(canonical))==len(canonical),'Duplicate selected common-domain entry')
        if str(source_path) in canonical:matches.append(domain)
    _require(len(matches)==1,'Workspace is not uniquely selected by sealed common domain')
    domain=matches[0];root=_path(domain['source_root']);view=_path(domain['view_root'])
    _require(view.is_relative_to(VIEW_ROOT) and view!=VIEW_ROOT,
             'Common view outside fixed protected publication prefix')
    for field,current in [('uid_map',os.getuid()),('gid_map',os.getgid())]:
        rows=domain[field]
        _require(isinstance(rows,list) and len(rows)==2 and rows[0]==[0,0,1]
                 and isinstance(rows[1],list) and len(rows[1])==3 and all(type(x)is int for x in rows[1])
                 and rows[1][0]>0 and rows[1][1]==current>0 and rows[1][2]==1,
                 'Common-domain map must preserve root and bind exact publisher')
    _require(type(domain['mount_id'])is int and domain['mount_id']>0,'Invalid provisioned mount audit identity')
    for field in ['mount_namespace','user_namespace']:
        _require(isinstance(domain[field],list) and len(domain[field])==2
                 and all(type(x)is int and x>=0 for x in domain[field]),'Invalid provisioned namespace identity')
    _require(_namespace('user')==domain['user_namespace'],'Common domain user namespace differs')
    state=domain['state']
    _require(set(state)=={'canonical','mapped','identity'} and state_path==_path(state['mapped'])
             and state_path==view/_relative(root,state['canonical']),'Actual transaction state alias differs')
    descriptors=[];selected=None
    try:
        canonical_fd=_open(root,path_only=True);descriptors.append(canonical_fd)
        _require(_identity(canonical_fd)==domain['source_identity'],'Common source ancestor drift')
        parent=_open(view.parent,trusted=True);descriptors.append(parent)
        common=os.open(view.name,FLAGS,dir_fd=parent);descriptors.append(common)
        _require(_identity(common)==domain['view_identity'] and _identity(common)[:2]==domain['source_identity'][:2]
                 and (_namespace('mnt')!=domain['mount_namespace'] or _mount(common)==domain['mount_id'])
                 and not os.fstatvfs(common).f_flag&os.ST_RDONLY,
                 'Common mapped ancestor identity or writable mount differs')
        _require(_identity(common)[2:4]==[os.getuid(),os.getgid()] and not _identity(common)[4]&0o022,'Common view publisher or private-parent mode differs')
        _require(domain['source_identity'][2:4]==[domain['uid_map'][1][0],domain['gid_map'][1][0]]
                 and domain['view_identity'][4]==domain['source_identity'][4], 'Common source ownership or mode differs')
        for entry in domain['projects']:
            relative=_relative(root,entry['canonical'])
            _require(not _path(state['canonical']).is_relative_to(_path(entry['canonical']))
                     and not _path(entry['canonical']).is_relative_to(_path(state['canonical'])),
                     'Common private state overlaps selected workspace')
            mapped=_open_relative(common,relative);descriptors.append(mapped)
            original=_open(entry['canonical'],path_only=True);descriptors.append(original)
            _require(_identity(original)==entry['identity'] and _identity(mapped)[:2]==entry['identity'][:2]
                     and _identity(mapped)[2:]==[os.getuid(),os.getgid(),entry['identity'][4]] and _mount(mapped)==_mount(common),
                     'Selected common-domain identity or mount drift')
            _require(entry['identity'][2:4]==[domain['uid_map'][1][0],domain['gid_map'][1][0]],
                     'Selected source ownership differs from sealed map')
            if entry['canonical']==str(source_path):
                _require(_identity(source_fd)==entry['identity'],'Pinned canonical source differs')
                selected=mapped
        private=_open_relative(common,_relative(root,state['canonical']),private=True);descriptors.append(private)
        identity=_identity(private)
        _require(identity[:2]==state['identity'][:2] and identity[2:]==[os.getuid(),os.getgid(),0o700]
                 and state['identity'][2:]==[domain['uid_map'][1][0],domain['gid_map'][1][0],0o700]
                 and _mount(private)==_mount(common),'Common private state identity, privacy or mount differs')
        configured=_open(state_path);descriptors.append(configured)
        _require(_identity(configured)==identity and _mount(configured)==_mount(common),'Configured state path differs from pinned common state')
        result=os.dup(selected);os.set_inheritable(result,False);return result
    finally:
        for fd in descriptors:os.close(fd)


def preflight_common_publication(workspace,state):
    """Read-only manifest/state validation before transaction mkdir or lock writes."""
    if Path(workspace).stat().st_uid==os.getuid():return
    if _load() is None:return
    canonical=_open(workspace,path_only=True)
    try:
        selected=open_common_publication(canonical,state_dir=state)
        if selected is not None:os.close(selected)
    finally:os.close(canonical)


def _open_relative(parent,relative,*,private=False):
    fd=os.dup(parent)
    try:
        for part in relative.parts:
            child=os.open(part,FLAGS,dir_fd=fd);os.close(fd);fd=child
            if private:
                value=_identity(fd)
                _require(value[2:]==[os.getuid(),os.getgid(),0o700],"Unprotected common private state ancestor")
        result,fd=fd,None;return result
    finally:
        if fd is not None:os.close(fd)
