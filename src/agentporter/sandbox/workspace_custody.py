"""Private same-mount atomic custody. No original-path unlink fallback exists.

The caller must hold the workspace mutation lease and keep its transaction
recovery guard. This primitive retains every captured entry; it does not retire
workspace/Git/job guards or authorize removing protected custody afterward.
"""
from contextlib import contextmanager
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat

from agentporter.sandbox.workspace_delta import (
    _workspace_parent, _file_signature, _read_deletion_file, _publish_restore_fd,
)

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _mount_id(descriptor):
    values = [line.split(':',1)[1].strip() for line in
              Path('/proc/self/fdinfo/'+str(descriptor)).read_text().splitlines()
              if line.startswith('mnt_id:')]
    if len(values) != 1 or not values[0].isdigit():
        raise PermissionError('Cannot establish pinned mount identity')
    return int(values[0])


def _rename_noreplace(source, name, destination, destination_name):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source,os.fsencode(name),destination,os.fsencode(destination_name),1):
        value = ctypes.get_errno()
        raise OSError(value,os.strerror(value),name)


def _private(descriptor):
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise PermissionError('Custody storage must be private to the publisher')
    return info


def _read_record(directory,name):
    descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 1024*1024):
            raise PermissionError('Untrusted custody record')
        data = os.read(descriptor,1024*1024+1)
        if len(data) > 1024*1024 or _file_signature(os.fstat(descriptor)) != _file_signature(info):
            raise PermissionError('Custody record changed during inspection')
        def unique(pairs):
            result = {}
            for key,value in pairs:
                if key in result:raise PermissionError('Duplicate custody record field')
                result[key]=value
            return result
        return json.loads(data,object_pairs_hook=unique)
    finally:
        os.close(descriptor)


def _write_record(directory,name,data):
    _private(directory)
    try:
        previous = _read_record(directory,name)
    except FileNotFoundError:
        pass
    else:
        if previous != data:raise PermissionError('Custody record already names another operation')
        # The previous process may have linked the complete record but died
        # before its parent fsync. A retry must make that intent durable now.
        os.fsync(directory)
        return
    output = os.open('.',os.O_RDWR|os.O_TMPFILE|os.O_CLOEXEC,0o600,dir_fd=directory)
    try:
        with os.fdopen(os.dup(output),'wb') as stream:
            stream.write(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
            stream.flush()
        os.fsync(output)
        _publish_restore_fd(directory,output,name)
        os.fsync(directory)
    finally:
        os.close(output)


def _stat(directory,name):
    try:return os.stat(name,dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError:return None


def _identity(info):
    return [info.st_dev,info.st_ino]


def _expected_record(record):
    required = {'signature','sha256','uid','gid','mode','mtime_ns','xattrs'}
    if not isinstance(record,dict) or not required <= set(record):
        raise PermissionError('Incomplete expected custody identity')
    result = {key:record[key] for key in required}
    signature = result['signature'];digest=result['sha256']
    if (not isinstance(signature,list) or len(signature)!=7
            or any(type(value) is not int or value<0 for value in signature)
            or not stat.S_ISREG(signature[2]) or signature[3]!=1
            or not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)
            or any(type(result[f]) is not int or result[f]<0 for f in ('uid','gid','mode','mtime_ns'))
            or result['mode']>0o777 or not isinstance(result['xattrs'],dict)):
        raise PermissionError('Invalid expected custody metadata')
    for key,value in result['xattrs'].items():
        if not isinstance(key,str) or not isinstance(value,str):raise PermissionError('Invalid custody xattr')
        base64.b64decode(value,validate=True)
    return result


def _matches_expected(directory,name,record,*,renamed):
    descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
    try:
        info = os.fstat(descriptor);actual=list(_file_signature(info));expected=record['signature']
        matches = actual[:-1]==expected[:-1] and actual[-1]>=expected[-1] if renamed else actual==expected
        if not matches:return False
        _read_deletion_file(descriptor,expected_signature=actual,expected_sha256=record['sha256'])
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_mtime_ns)!=(record['uid'],record['gid'],record['mode'],record['mtime_ns']):return False
        attrs={key:base64.b64encode(os.getxattr(descriptor,key)).decode('ascii') for key in os.listxattr(descriptor)}
        return attrs==record['xattrs'] and _file_signature(os.fstat(descriptor))==tuple(actual)
    finally:
        os.close(descriptor)


def _is_expected(directory,name,record,*,renamed):
    try:return _matches_expected(directory,name,record,renamed=renamed)
    except (OSError,PermissionError):return False


@contextmanager
def _open(workspace,operation,*,create=False):
    workspace_path=os.fspath(workspace);operation=Path(operation)
    canonical_root=Path(workspace_path).resolve(strict=True)
    canonical_operation=operation.resolve()
    if canonical_operation.is_relative_to(canonical_root) or canonical_root.is_relative_to(canonical_operation):
        raise PermissionError('Custody must be outside the workspace')
    parent=os.open(operation.parent,_FLAGS)
    custody=None;root=None
    try:
        _private(parent)
        if create:
            try:os.mkdir(operation.name,0o700,dir_fd=parent)
            except FileExistsError:pass
            os.fsync(parent)
        custody=os.open(operation.name,_FLAGS,dir_fd=parent)
        _private(custody)
        root=os.open(workspace_path,_FLAGS)
        yield root,custody
    finally:
        for descriptor in (root,custody,parent):
            if descriptor is not None:os.close(descriptor)


def _intent(root,parent,custody,relative,record):
    source_info=os.fstat(parent);private_info=os.fstat(custody)
    mount=_mount_id(parent)
    if source_info.st_dev!=private_info.st_dev or mount!=_mount_id(custody):
        raise PermissionError('Custody requires the exact same protected mount')
    return {'schema':1,'workspace':_identity(os.fstat(root)),
            'source_parent':_identity(source_info),'custody':_identity(private_info),
            'mount_id':mount,'path':relative,'expected':record}


def _validate_intent(root,parent,custody,intent):
    if (not isinstance(intent,dict) or set(intent)!={'schema','workspace','source_parent','custody','mount_id','path','expected'}
            or intent['schema']!=1 or not isinstance(intent['path'],str)):
        raise PermissionError('Invalid custody intent')
    expected=_expected_record(intent['expected'])
    current=_intent(root,parent,custody,intent['path'],expected)
    if current!=intent:raise PermissionError('Custody workspace, parent or mount identity changed')


def _optional_record(custody,name):
    try:return _read_record(custody,name)
    except FileNotFoundError:return None


def _inspect(root,parent,name,custody,intent):
    _validate_intent(root,parent,custody,intent)
    source=_stat(parent,name);held=_stat(custody,'captured')
    captured=_optional_record(custody,'captured.json')
    restored=_optional_record(custody,'restored.json')
    for receipt in (captured,restored):
        if receipt is not None and (not isinstance(receipt,dict) or set(receipt)!={'intent_sha256','identity','expected'}
                or receipt['intent_sha256']!=hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                or not isinstance(receipt['identity'],list) or len(receipt['identity'])!=2
                or any(type(v) is not int or v<0 for v in receipt['identity'])
                or type(receipt['expected']) is not bool):
            raise PermissionError('Invalid custody phase receipt')
    if held is not None:
        if restored is not None:raise PermissionError('Restored receipt conflicts with retained custody')
        if captured is not None and _identity(held)!=captured['identity']:
            raise PermissionError('Private custody entry changed identity')
        expected=_is_expected(custody,'captured',intent['expected'],renamed=True)
        return {'state':'captured_conflict' if source is not None else ('captured_expected' if expected else 'captured_owner'),
                'identity':_identity(held),'expected':expected}
    receipt=restored or captured
    if receipt is not None:
        if source is not None and _identity(source)==receipt['identity']:
            expected=_is_expected(parent,name,intent['expected'],renamed=True)
            return {'state':'restored' if expected else 'restored_owner','identity':_identity(source),'expected':expected}
        return {'state':'conflict','identity':None,'expected':False}
    if source is not None:
        expected=_is_expected(parent,name,intent['expected'],renamed=False)
        return {'state':'uncaptured' if expected else 'uncaptured_owner','identity':_identity(source),'expected':expected}
    return {'state':'missing','identity':None,'expected':False}


def _phase(intent,result):
    return {'intent_sha256':hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'identity':result['identity'],'expected':result['expected']}


def inspect_custody(workspace,operation):
    with _open(workspace,operation) as (root,custody):
        intent=_read_record(custody,'intent.json')
        with _workspace_parent(f'/proc/self/fd/{root}/.',intent['path']) as (parent,name):
            return _inspect(root,parent,name,custody,intent)


def capture_workspace_entry(workspace,relative,operation,*,expected_record,expected_support=None):
    record=_expected_record(expected_record)
    with _open(workspace,operation,create=True) as (root,custody):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            intent=_intent(root,parent,custody,relative,record)
            if expected_support is not None and _support(intent)!=expected_support:
                raise PermissionError('Custody preflight parent or mount identity changed')
            previous=_optional_record(custody,'intent.json')
            if previous is not None and previous!=intent:raise PermissionError('Custody intent differs from requested operation')
            _write_record(custody,'intent.json',intent)
            current=_inspect(root,parent,name,custody,intent)
            if current['state']=='uncaptured':
                _rename_noreplace(parent,name,custody,'captured')
                os.fsync(parent);os.fsync(custody)
                current=_inspect(root,parent,name,custody,intent)
            if current['state'] in {'captured_expected','captured_owner','captured_conflict'}:
                # A prior process may have died immediately after rename,
                # before either parent sync. Complete both on every retry.
                os.fsync(parent);os.fsync(custody)
                _write_record(custody,'captured.json',_phase(intent,current))
                current=_inspect(root,parent,name,custody,intent)
            if current['state']=='captured_expected':return current
    # Release FDs before the separately validated create-only restoration.
    if current['state']=='captured_owner':
        restore_custody(workspace,operation)
    raise PermissionError('Captured entry belongs to later owner work; custody recovery required')


def restore_custody(workspace,operation):
    with _open(workspace,operation) as (root,custody):
        intent=_read_record(custody,'intent.json')
        with _workspace_parent(f'/proc/self/fd/{root}/.',intent['path']) as (parent,name):
            current=_inspect(root,parent,name,custody,intent)
            if current['state'] in {'restored','restored_owner'}:
                # captured.json proves the exact returned inode even when the
                # previous process died before restored.json or directory sync.
                os.fsync(parent);os.fsync(custody)
                _write_record(custody,'restored.json',_phase(intent,current))
                result=_inspect(root,parent,name,custody,intent)
                if result['state'] not in {'restored','restored_owner'}:
                    raise PermissionError('Restored entry changed during durable recovery')
                return result
            if current['state']=='uncaptured':return current
            if current['state'] not in {'captured_expected','captured_owner'}:
                raise PermissionError('Custody restoration conflicts with later source work')
            _write_record(custody,'captured.json',_phase(intent,current))
            try:_rename_noreplace(custody,'captured',parent,name)
            except FileExistsError as error:
                raise PermissionError('Later source entry preserved; original remains in custody') from error
            os.fsync(parent);os.fsync(custody)
            _write_record(custody,'restored.json',_phase(intent,current))
            result=_inspect(root,parent,name,custody,intent)
            if result['state'] not in {'restored','restored_owner'}:
                raise PermissionError('Restored entry changed; custody guard must remain')
            return result


def _support(intent):
    return {key:intent[key] for key in ('workspace','source_parent','custody','mount_id')}


def preflight_workspace_custody(workspace,relative,operation):
    """Prove protected capture/undo storage before any workspace mutation."""
    with _open(workspace,operation,create=True) as (root,custody):
        with _workspace_parent(f'/proc/self/fd/{root}/.',relative) as (parent,name):
            return _support(_intent(root,parent,custody,relative,None))
