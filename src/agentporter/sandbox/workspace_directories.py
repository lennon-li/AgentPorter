"""Journaled same-mount directory creation and non-destructive rollback.

The transaction owns the enclosing guard. No recursive removal is performed;
rollback retains the empty created directory in private storage. Child files
must be reconciled before parents, and a captured nonempty/foreign directory
is restored create-only or retained with a conflict.
"""
import base64
import json
import os
import stat

from agentporter.sandbox.workspace_delta import _workspace_parent, _read_deletion_file, _require_public_path, _file_signature
from agentporter.sandbox.workspace_custody import (
    _open, _intent, _support, _write_record, _read_record, _optional_record,
    _stat, _identity, _rename_noreplace, _FLAGS,
)


def _directory_record(parent,name):
    descriptor=os.open(name,_FLAGS,dir_fd=parent)
    try:
        info=os.fstat(descriptor)
        return {'identity':_identity(info),'mode':stat.S_IMODE(info.st_mode),
                'uid':info.st_uid,'gid':info.st_gid,'mtime_ns':info.st_mtime_ns,
                'xattrs':{key:base64.b64encode(os.getxattr(descriptor,key)).decode('ascii')
                          for key in os.listxattr(descriptor)}}
    finally:os.close(descriptor)


def _empty(parent,name):
    descriptor=os.open(name,_FLAGS,dir_fd=parent)
    try:
        with os.scandir(descriptor) as entries:
            return next(entries,None) is None
    finally:os.close(descriptor)


def _matches(parent,name,expected):
    try:return _directory_record(parent,name)==expected
    except OSError:return False


def _tree(parent,name,*,copy_to=None,metadata_prefixes=()):
    """Bounded no-follow tree snapshot, optionally copying to a private FD."""
    records={};budget=[100_000,256*1024*1024]
    descriptor=os.open(name,_FLAGS,dir_fd=parent)
    def walk(source,destination,prefix,depth):
        if depth>64:raise PermissionError('Directory tree exceeds depth limit')
        before=os.fstat(source)
        with os.scandir(source) as entries:
            names=sorted(entry.name for entry in entries)
        for entry in names:
            budget[0]-=1
            if budget[0]<0:raise PermissionError('Directory tree exceeds entry limit')
            relative=prefix+entry
            if not any(relative==p or relative.startswith(p+'/') for p in metadata_prefixes):
                _require_public_path(relative)
            info=os.stat(entry,dir_fd=source,follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child=os.open(entry,_FLAGS,dir_fd=source)
                output=None
                try:
                    if destination is not None:
                        os.mkdir(entry,0o700,dir_fd=destination)
                        output=os.open(entry,_FLAGS,dir_fd=destination)
                    records[relative]={'kind':'directory',**_directory_record(source,entry)}
                    walk(child,output,relative+'/',depth+1)
                    if output is not None:
                        _copy_metadata(child,output);os.fsync(output)
                finally:
                    os.close(child)
                    if output is not None:os.close(output)
            elif stat.S_ISREG(info.st_mode):
                file=os.open(entry,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=source)
                try:
                    data,actual,digest=_read_deletion_file(file)
                    budget[1]-=len(data)
                    if budget[1]<0:raise PermissionError('Directory tree exceeds byte limit')
                    attrs={key:base64.b64encode(os.getxattr(file,key)).decode('ascii') for key in os.listxattr(file)}
                    records[relative]={'kind':'file','identity':_identity(actual),'mode':stat.S_IMODE(actual.st_mode),
                        'uid':actual.st_uid,'gid':actual.st_gid,'mtime_ns':actual.st_mtime_ns,'sha256':digest,'xattrs':attrs}
                    if destination is not None:
                        out=os.open(entry,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=destination)
                        try:
                            with os.fdopen(os.dup(out),'wb') as stream:stream.write(data);stream.flush()
                            _copy_metadata(file,out);os.fsync(out)
                        finally:os.close(out)
                finally:os.close(file)
            else:raise PermissionError('Directory tree contains an unsupported entry')
        if _file_signature(before)!=_file_signature(os.fstat(source)):
            raise PermissionError('Directory tree changed during snapshot')
    try:walk(descriptor,copy_to,'',0)
    finally:os.close(descriptor)
    return records


def _copy_metadata(source,destination):
    info=os.fstat(source)
    if info.st_mode & 0o7000:raise PermissionError('Unsupported directory tree access mode')
    os.fchmod(destination,stat.S_IMODE(info.st_mode))
    for key in os.listxattr(source):os.setxattr(destination,key,os.getxattr(source,key))
    os.utime(destination,ns=(info.st_atime_ns,info.st_mtime_ns))


def _tree_matches(parent,name,intent):
    try:
        from agentporter.sandbox.repository_birth import validate_payloads
        prefixes=validate_payloads(intent['repository_births']) if intent['schema'] in (2,3) else ()
        return _tree(parent,name,metadata_prefixes=prefixes)==intent['tree']
    except (OSError,PermissionError):return False


def _load(root,parent,private):
    intent=_read_record(private,'directory-intent.json')
    if (not isinstance(intent,dict) or intent.get('schema') not in (1,2,3)
            or set(intent)!=({'schema','path','support','directory','tree'} | ({'repository_births'} if intent.get('schema') in (2,3) else set()) | ({'original_directory'} if intent.get('schema')==3 else set()))
            or not isinstance(intent['path'],str)):
        raise PermissionError('Invalid directory intent')
    if intent['schema'] in (2,3):
        from agentporter.sandbox.repository_birth import validate_payloads
        from agentporter.sandbox.repository_birth import validate_tree_records
        validate_tree_records(intent['repository_births'],intent['tree'])
    expected=intent['directory']
    if (not isinstance(expected,dict) or set(expected)!={'identity','mode','uid','gid','mtime_ns','xattrs'}
            or not isinstance(expected['identity'],list) or len(expected['identity'])!=2
            or any(type(v) is not int or v<0 for v in expected['identity'])
            or any(type(expected[k]) is not int or expected[k]<0 for k in ('mode','uid','gid','mtime_ns'))
            or expected['mode'] & ~0o777 or not isinstance(expected['xattrs'],dict)):
        raise PermissionError('Invalid created directory identity')
    if intent['schema']==3:
        original=intent['original_directory']
        if (not isinstance(original,dict) or set(original)!=set(expected) or original['identity']==expected['identity']
                or not isinstance(original['identity'],list) or len(original['identity'])!=2
                or any(type(v)is not int or v<0 for v in original['identity'])
                or any(type(original[k])is not int or original[k]<0 for k in ('mode','uid','gid','mtime_ns'))
                or original['mode'] & ~0o777 or not isinstance(original['xattrs'],dict)):
            raise PermissionError('Invalid original empty directory evidence')
    actual=_support(_intent(root,parent,private,intent['path'],None))
    if actual!=intent['support']:
        raise PermissionError('Directory parent or protected mount changed')
    if not isinstance(intent['tree'],dict):raise PermissionError('Invalid directory tree manifest')
    return intent


def prepare_directory(workspace,relative,operation,*,mode=0o755,source=None,repository_births=None):
    if type(mode) is not int or mode<0 or mode & ~0o777:
        raise PermissionError('Unsupported directory mode')
    birth_records=[];prefixes=();replacement_identity=None
    if repository_births is not None:
        from agentporter.sandbox.repository_birth import RepositoryBirths,validate_payloads
        if not isinstance(repository_births,RepositoryBirths):raise PermissionError('Git birth directory requires exact host capability')
        birth_records=repository_births.for_tree(source)
        prefixes=validate_payloads(birth_records)
        replacement_identity=repository_births.replacement_identity(source)
    with _open(workspace,operation,create=True) as (root,private):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            support=_support(_intent(root,parent,private,relative,None))
            old=_optional_record(private,'directory-intent.json')
            if old is not None:
                intent=_load(root,parent,private)
                if intent['path']!=relative or intent['directory']['mode']!=mode:
                    raise PermissionError('Directory preparation differs from existing intent')
                os.fsync(private)
                return intent
            original_directory=None
            if _stat(parent,name) is not None:
                if replacement_identity is None or not birth_records or not _empty(parent,name):
                    raise PermissionError('New directory destination already exists')
                original_directory=_directory_record(parent,name)
                if tuple(original_directory['identity'])!=replacement_identity:
                    raise PermissionError('Empty Git birth target identity changed')
            try:os.mkdir('prepared',0o700,dir_fd=private)
            except FileExistsError:pass
            descriptor=os.open('prepared',_FLAGS,dir_fd=private)
            try:
                if not _empty(private,'prepared'):
                    raise PermissionError('Prepared directory is not empty')
                if source is not None:
                    source_parent=os.open(os.path.dirname(os.fspath(source)),_FLAGS)
                    try:
                        source_name=os.path.basename(os.fspath(source))
                        _tree(source_parent,source_name,copy_to=descriptor,metadata_prefixes=prefixes)
                        source_root=os.open(source_name,_FLAGS,dir_fd=source_parent)
                        try:_copy_metadata(source_root,descriptor)
                        finally:os.close(source_root)
                    finally:os.close(source_parent)
                os.fchmod(descriptor,mode)
                os.fsync(descriptor)
            finally:os.close(descriptor)
            intent={'schema':1,'path':relative,'support':support,
                    'directory':_directory_record(private,'prepared'),
                    'tree':_tree(private,'prepared',metadata_prefixes=prefixes)}
            if birth_records:
                from agentporter.sandbox.repository_birth import validate_tree_records
                validate_tree_records(birth_records,intent['tree'])
                intent.update(schema=2,repository_births=birth_records)
            if original_directory is not None:
                intent.update(schema=3,original_directory=original_directory)
            if len(json.dumps(intent).encode())>1024*1024:
                raise PermissionError('Directory manifest exceeds durable record limit')
            _write_record(private,'directory-intent.json',intent)
            return intent


def _state(parent,name,private,intent):
    if intent['schema']==3:return _replacement_state(parent,name,private,intent)
    expected=intent['directory']
    locations=[(parent,name,'published'),(private,'prepared','prepared'),
               (private,'captured','rolled_back')]
    found=[]
    for descriptor,entry,state in locations:
        if _stat(descriptor,entry) is not None:
            found.append((state,_matches(descriptor,entry,expected)))
    if len(found)==1 and found[0][1]:return found[0][0]
    return 'conflict'


def _replacement_state(parent,name,private,intent):
    """Two retained exact directory inodes; never infer ownership from contents."""
    old,new=intent['original_directory'],intent['directory']
    current=_stat(parent,name);prepared=_stat(private,'prepared');original=_stat(private,'original');captured=_stat(private,'captured')
    old_here=current is not None and _matches(parent,name,old) and _empty(parent,name)
    new_here=current is not None and _matches(parent,name,new)
    old_held=original is not None and _matches(private,'original',old) and _empty(private,'original')
    new_prepared=prepared is not None and _matches(private,'prepared',new)
    new_captured=captured is not None and _matches(private,'captured',new)
    if old_here and new_prepared and original is None and captured is None:return 'prepared'
    if current is None and old_held and new_prepared and captured is None:return 'original_captured'
    if new_here and old_held and prepared is None and captured is None:return 'published'
    if current is None and old_held and new_captured and prepared is None:return 'candidate_captured'
    if old_here and new_captured and original is None and prepared is None:return 'rolled_back'
    return 'conflict'


def inspect_directory(workspace,relative,operation):
    with _open(workspace,operation) as (root,private):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            intent=_load(root,parent,private)
            if intent['path']!=relative:raise PermissionError('Directory intent path mismatch')
            state=_state(parent,name,private,intent)
            location={'published':(parent,name),'prepared':(private,'prepared'),
                      'rolled_back':(private,'captured'),'original_captured':(private,'prepared'),
                      'candidate_captured':(private,'captured')}.get(state)
            if location is not None and not _tree_matches(*location,intent):state='conflict'
            return {'state':state,'intent':intent}


def publish_directory(workspace,relative,operation):
    with _open(workspace,operation) as (root,private):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            intent=_load(root,parent,private)
            if intent['path']!=relative:raise PermissionError('Directory intent path mismatch')
            state=_state(parent,name,private,intent)
            os.fsync(private)  # acknowledge a previous process's durable intent
            if intent['schema']==3 and state=='prepared':
                _rename_noreplace(parent,name,private,'original')
                os.fsync(parent);os.fsync(private)
                state=_state(parent,name,private,intent)
                if state!='original_captured':
                    try:_rename_noreplace(private,'original',parent,name)
                    finally:os.fsync(parent);os.fsync(private)
                    raise PermissionError('Captured original directory changed; restored owner target')
            if state in {'prepared','original_captured'}:
                _rename_noreplace(private,'prepared',parent,name)
            elif state!='published':
                raise PermissionError('Directory publication conflicts with owner work')
            os.fsync(parent);os.fsync(private)
            if _state(parent,name,private,intent)!='published':
                raise PermissionError('Published directory identity changed')
            if not _tree_matches(parent,name,intent):
                raise PermissionError('Published directory tree differs from private manifest')
            return intent


def rollback_directory(workspace,relative,operation):
    with _open(workspace,operation) as (root,private):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            intent=_load(root,parent,private)
            if intent['path']!=relative:raise PermissionError('Directory intent path mismatch')
            state=_state(parent,name,private,intent)
            if intent['schema']==3:
                return _rollback_replacement(parent,name,private,intent,state)
            if state=='prepared':return {'state':'unpublished','intent':intent}
            if state=='published':
                if not _tree_matches(parent,name,intent):
                    raise PermissionError('Created directory contains unreconciled entries')
                os.fsync(private)
                _rename_noreplace(parent,name,private,'captured')
            # Inspect the actual moved object, including entries inserted after
            # the preflight. Owner content is never recursively removed.
            if _stat(private,'captured') is not None:
                valid=(_matches(private,'captured',intent['directory'])
                       and _tree_matches(private,'captured',intent))
                if not valid:
                    try:_rename_noreplace(private,'captured',parent,name)
                    finally:os.fsync(parent);os.fsync(private)
                    raise PermissionError('Captured owner directory restored; rollback refused')
            os.fsync(parent);os.fsync(private)
            if _state(parent,name,private,intent)!='rolled_back':
                raise PermissionError('Directory rollback conflict; private custody retained')
            return {'state':'rolled_back','intent':intent}


def _rollback_replacement(parent,name,private,intent,state):
    if state in {'prepared','rolled_back'}:return {'state':'unpublished' if state=='prepared' else state,'intent':intent}
    if state=='published':
        if not _tree_matches(parent,name,intent):raise PermissionError('Published Git birth tree changed')
        _rename_noreplace(parent,name,private,'captured')
        os.fsync(parent);os.fsync(private)
        if not _matches(private,'captured',intent['directory']) or not _tree_matches(private,'captured',intent):
            try:_rename_noreplace(private,'captured',parent,name)
            finally:os.fsync(parent);os.fsync(private)
            raise PermissionError('Captured Git birth owner changes restored')
        state=_state(parent,name,private,intent)
    if state not in {'original_captured','candidate_captured'}:
        raise PermissionError('Git birth directory rollback conflicts with owner work')
    _rename_noreplace(private,'original',parent,name)
    os.fsync(parent);os.fsync(private)
    result=_state(parent,name,private,intent)
    if result not in {'prepared','rolled_back'}:raise PermissionError('Git birth original directory restore unresolved')
    return {'state':'unpublished' if result=='prepared' else result,'intent':intent}
