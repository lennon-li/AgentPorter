"""Retained custody for recovery guard retirement and restart discovery."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

from agentporter.sandbox import workspace_custody as custody
from agentporter.sandbox.workspace_delta import _read_deletion_file, _file_signature, _publish_restore_fd


def location(state,key,transaction_name):
    return Path(state)/'workspace-recovery'/key/transaction_name


def _read(path):
    parent=os.open(path.parent,custody._FLAGS)
    try:
        custody._private(parent)
        return custody._read_record(parent,path.name)
    finally:os.close(parent)


def load(base):
    try:bundle=_read(Path(base)/'active.json')
    except FileNotFoundError:return None
    if (not isinstance(bundle,dict) or set(bundle)!={'schema','workspace','transaction','journal_sha256','guards'}
            or bundle['schema']!=1 or not isinstance(bundle['guards'],list) or not bundle['guards']):
        raise PermissionError('Invalid recovery guard bundle')
    for index,item in enumerate(bundle['guards']):
        slot='workspace' if index==len(bundle['guards'])-1 else 'git-'+str(index)
        if not isinstance(item,dict) or set(item)!={'path','record','slot','support'} or item['slot']!=slot:
            raise PermissionError('Invalid recovery guard slot')
        custody._expected_record(item['record'])
    return bundle


def _write(base,name,value):
    if len(json.dumps(value).encode())>1024*1024:
        raise PermissionError('Recovery guard bundle exceeds durable record limit')
    descriptor=os.open(base,custody._FLAGS)
    try:custody._write_record(descriptor,name,value)
    finally:os.close(descriptor)


def _guard_record(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        _,info,digest=_read_deletion_file(descriptor)
        return {'signature':list(_file_signature(info)),'sha256':digest,'mode':stat.S_IMODE(info.st_mode),
            'uid':info.st_uid,'gid':info.st_gid,'mtime_ns':info.st_mtime_ns,
            'xattrs':{name:base64.b64encode(os.getxattr(descriptor,name)).decode('ascii') for name in os.listxattr(descriptor)}}
    finally:os.close(descriptor)


def _backup_guard(journal,base,record):
    source=os.open(journal,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    parent=None;output=None
    try:
        data,_,_=_read_deletion_file(source,expected_signature=record['signature'],expected_sha256=record['sha256'])
        parent=os.open(base,custody._FLAGS);custody._private(parent)
        output=os.open('.',os.O_RDWR|os.O_TMPFILE|os.O_CLOEXEC,0o600,dir_fd=parent)
        with os.fdopen(os.dup(output),'wb') as stream:stream.write(data);stream.flush()
        os.fsync(output)
        _publish_restore_fd(parent,output,'workspace-backup.json')
        os.fsync(parent)
    finally:
        for descriptor in (output,parent,source):
            if descriptor is not None:os.close(descriptor)


def prepare(base,*,state,workspace,transaction,journal,journal_hash,journal_signature,git_guards):
    base=Path(base)
    for path in (Path(state)/'workspace-recovery',base.parent,base):
        path.mkdir(mode=0o700,exist_ok=True)
        descriptor=os.open(path,custody._FLAGS)
        try:custody._private(descriptor);os.fsync(descriptor)
        finally:os.close(descriptor)
        descriptor=os.open(path.parent,custody._FLAGS)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    previous=load(base)
    if previous is not None:
        if (previous['workspace']!=str(workspace) or previous['transaction']!=str(transaction)
                or previous['journal_sha256']!=journal_hash):
            raise PermissionError('Recovery guard bundle differs from current journal')
        paths=[str(item['path']) for item in git_guards]+[str(journal)]
        if [item['path'] for item in previous['guards']]!=paths:
            raise PermissionError('Recovery guard paths differ from bound transaction')
        if (previous['guards'][-1]['record']['signature']!=journal_signature
                or previous['guards'][-1]['record']['sha256']!=journal_hash):
            raise PermissionError('Workspace guard bundle identity differs from reviewed plan')
        for index,item in enumerate(git_guards):
            if custody._expected_record(previous['guards'][index]['record'])!=custody._expected_record(item['record']):
                raise PermissionError('Git guard bundle identity differs from bound lifecycle')
        for item in previous['guards']:
            path=Path(item['path'])
            actual=custody.preflight_workspace_custody(path.parent,path.name,base/item['slot'])
            if actual!=item['support']:raise PermissionError('Recovery guard custody mount or parent changed')
        return previous
    record=_guard_record(journal)
    if record['sha256']!=journal_hash or record['signature']!=journal_signature:
        raise PermissionError('Workspace guard changed before recovery preparation')
    _write(base,'workspace-expected.json',record)
    backup=base/'workspace-backup.json'
    if not os.path.lexists(backup):
        _backup_guard(journal,base,record)
    if _guard_record(backup)['sha256']!=journal_hash:raise PermissionError('Recovery journal backup changed')
    guards=[]
    for index,item in enumerate(git_guards):
        guards.append({'path':str(item['path']),'record':item['record'],'slot':'git-'+str(index)})
    guards.append({'path':str(journal),'record':record,'slot':'workspace'})
    for item in guards:
        path=Path(item['path'])
        item['support']=custody.preflight_workspace_custody(path.parent,path.name,base/item['slot'])
    bundle={'schema':1,'workspace':str(workspace),'transaction':str(transaction),
            'journal_sha256':journal_hash,'guards':guards}
    _write(base,'active.json',bundle)
    return bundle


def retired_slot(base,index):
    return Path(base)/('git-'+str(index))


def retire(base,bundle):
    # Git guards precede the workspace guard. The durable active bundle and
    # original journal backup make either missing pathname resumable.
    for item in bundle['guards']:
        path=Path(item['path'])
        result=custody.capture_workspace_entry(path.parent,path.name,Path(base)/item['slot'],
            expected_record=item['record'],expected_support=item['support'])
        if result['state']!='captured_expected' or not result['expected']:
            raise PermissionError('Recovery guard custody conflicts with later work')
    _write(base,'done.json',{'schema':1,'workspace':bundle['workspace'],
        'transaction':bundle['transaction'],'journal_sha256':bundle['journal_sha256']})


def find_unfinished(state,key,workspace):
    root=Path(state)/'workspace-recovery'/key
    if not os.path.lexists(root):return None
    descriptor=os.open(root,custody._FLAGS)
    try:
        custody._private(descriptor)
        with os.scandir(descriptor) as entries:names=[entry.name for entry in entries]
        if len(names)>10000:raise PermissionError('Recovery guard discovery exceeds limit')
    finally:os.close(descriptor)
    pending=[]
    for name in names:
        if not name.startswith(key[:12]+'-') or '/' in name:
            raise PermissionError('Unexpected recovery guard transaction name')
        base=root/name
        bundle=load(base)
        if bundle is None:continue  # preparation stopped before any recovery mutation
        if bundle.get('schema')!=1 or bundle.get('workspace')!=str(workspace):
            raise PermissionError('Recovery guard discovery workspace mismatch')
        if Path(bundle['transaction']).name!=name:
            raise PermissionError('Recovery guard transaction storage mismatch')
        try:done=_read(base/'done.json')
        except FileNotFoundError:done=None
        if done is None:pending.append((base,bundle))
        elif any(done.get(k)!=bundle.get(k) for k in ('workspace','transaction','journal_sha256')):
            raise PermissionError('Recovery guard completion receipt differs from active bundle')
    if len(pending)>1:raise PermissionError('Multiple unfinished guard retirements require inspection')
    return pending[0] if pending else None
