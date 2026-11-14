"""Private immutable raw Git baselines; no canonical mutation API.

Logical Git trees cannot identify owner-replaced raw metadata. These records
retain exact file identities and bytes outside every worker-visible mount.
They are evidence for recovery, not permission to replay raw refs.
"""
import base64
import hashlib
import fcntl
import json
import os
import stat
import re
from pathlib import Path

from agentporter.sandbox.workspace_custody import (
    _open, _read_record, _write_record, _identity, _mount_id, _FLAGS, _private,
)
from agentporter.sandbox.workspace_delta import _read_deletion_file, _file_signature


def _metadata(fd):
    info=os.fstat(fd)
    return {'identity':_identity(info),'mode':stat.S_IMODE(info.st_mode),
            'uid':info.st_uid,'gid':info.st_gid,'mtime_ns':info.st_mtime_ns,
            'ctime_ns':info.st_ctime_ns,
            'xattrs':{key:base64.b64encode(os.getxattr(fd,key)).decode('ascii')
                      for key in os.listxattr(fd)}}


def _snapshot(root,*,blobs=None,allow_locks=False,copy_guard=None):
    git=os.open('.git',_FLAGS,dir_fd=root)
    git_mount=_mount_id(git)
    budget=[100_000,256*1024*1024];files={};directories={}
    def walk(fd,prefix,depth):
        if depth>64:raise PermissionError('Raw Git baseline exceeds depth limit')
        before=os.fstat(fd)
        with os.scandir(fd) as entries:names=sorted(entry.name for entry in entries)
        for name in names:
            # Content-addressed objects are retained by the existing pack path;
            # they are never authority for identifying mutable metadata.
            if prefix=='' and name=='objects':continue
            info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            # The root agent-dispatch namespace contains run telemetry only.
            # Keep it out of raw baselines and their durable blob copies so
            # append-only output cannot invalidate capture or enter workers.
            # This excludes no Git control path; nested same-named paths are
            # still covered by the complete metadata baseline.
            if prefix=='' and name=='agent-dispatch':
                if not stat.S_ISDIR(info.st_mode):
                    raise PermissionError('Git telemetry namespace must be a real directory')
                child=os.open(name,_FLAGS,dir_fd=fd)
                try:
                    if (_file_signature(os.fstat(child))!=_file_signature(info)
                            or _mount_id(child)!=git_mount):
                        raise PermissionError('Git telemetry namespace changed or crosses a mount')
                finally:os.close(child)
                continue
            if name.endswith('.lock') and not allow_locks:
                raise PermissionError('Raw Git baseline conflicts with a native lock')
            budget[0]-=1
            if budget[0]<0:raise PermissionError('Raw Git baseline exceeds entry limit')
            relative=prefix+name
            if stat.S_ISDIR(info.st_mode):
                child=os.open(name,_FLAGS,dir_fd=fd)
                try:
                    directories[relative]=_metadata(child)
                    walk(child,relative+'/',depth+1)
                finally:os.close(child)
            elif stat.S_ISREG(info.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                try:
                    data,actual,digest=_read_deletion_file(child)
                    budget[1]-=len(data)
                    if budget[1]<0:raise PermissionError('Raw Git baseline exceeds byte limit')
                    record=_metadata(child)
                    if _file_signature(actual)!=_file_signature(os.fstat(child)):
                        raise PermissionError('Raw Git metadata changed during capture')
                    files[relative]={**record,'sha256':digest,'size':len(data)}
                    if blobs is not None:
                        try:out=os.open(digest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=blobs)
                        except FileExistsError:
                            existing=os.open(digest,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=blobs)
                            try:_read_deletion_file(existing,expected_sha256=digest)
                            finally:os.close(existing)
                        else:
                            try:
                                with os.fdopen(os.dup(out),'wb') as stream:
                                    if copy_guard is None:
                                        stream.write(data)
                                    else:
                                        copy_guard(out,0)
                                        for offset in range(0,len(data),65536):
                                            chunk=data[offset:offset+65536]
                                            copy_guard(out,len(chunk))
                                            stream.write(chunk)
                                    stream.flush()
                                os.fsync(out)
                            finally:os.close(out)
                finally:os.close(child)
            else:raise PermissionError('Raw Git baseline rejects aliases and special files')
        if _file_signature(before)!=_file_signature(os.fstat(fd)):
            raise PermissionError('Raw Git directory changed during capture')
    try:
        walk(git,'',0)
        return {'schema':1,'workspace':_identity(os.fstat(root)),
                'git':_identity(os.fstat(git)),'mount_id':_mount_id(git),
                'files':files,'directories':directories}
    finally:os.close(git)


def _digest(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def capture_git_baseline(workspace,operation,*,copy_guard=None):
    """Capture before delegation. Reusing a baseline requires exact live identity."""
    with _open(workspace,operation,create=True) as (root,private):
        try:old=_read_record(private,'baseline.json')
        except FileNotFoundError:old=None
        if old is not None:
            if old!=_snapshot(root):raise PermissionError('Raw Git baseline conflicts with owner changes')
            os.fsync(private)
            return {'sha256':_digest(old),'manifest':old}
        try:os.mkdir('blobs',0o700,dir_fd=private)
        except FileExistsError:pass
        blobs=os.open('blobs',_FLAGS,dir_fd=private)
        try:
            _private(blobs)
            captured=_snapshot(root,blobs=blobs,copy_guard=copy_guard)
            if captured!=_snapshot(root):raise PermissionError('Raw Git baseline changed during capture')
            if len(json.dumps(captured).encode())>1024*1024:
                raise PermissionError('Raw Git manifest exceeds durable record limit')
            os.fsync(blobs)
            _write_record(private,'baseline.json',captured)
            return {'sha256':_digest(captured),'manifest':captured}
        finally:os.close(blobs)


def read_git_baseline(workspace,operation,expected_sha256):
    """Verify saved baseline integrity without accepting current mutations."""
    with _open(workspace,operation) as (root,private):
        captured=_read_record(private,'baseline.json')
        if _digest(captured)!=expected_sha256:
            raise PermissionError('Raw Git baseline digest differs from bound journal')
        blobs=os.open('blobs',_FLAGS,dir_fd=private)
        try:
            _private(blobs)
            for record in captured['files'].values():
                descriptor=os.open(record['sha256'],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=blobs)
                try:_read_deletion_file(descriptor,expected_sha256=record['sha256'])
                finally:os.close(descriptor)
        finally:os.close(blobs)
        return captured


def verify_git_baseline(workspace,operation,expected_sha256):
    captured=read_git_baseline(workspace,operation,expected_sha256)
    with _open(workspace,operation) as (root,private):
        actual=_snapshot(root)
        if captured!=actual:
            # Only explicit restored-original custody permits the rename ctime
            # difference. An equal-byte replacement inode never qualifies.
            storage=Path(operation).parent/'preserved-metadata'
            from agentporter.sandbox import git_original_metadata as originals
            for path in captured['files']:
                if not originals._admitted(path):continue
                before=captured['files'].get(path);now=actual['files'].get(path)
                if before is None or now is None or before==now:continue
                if not os.path.lexists(storage/'plan.json'):continue
                info=originals.describe(workspace,storage,path)
                if info['state']=='restored' and _same_native(_native_record(now),_native_record(before),renamed=True):
                    actual['files'][path]=before
            if os.path.lexists(storage/'plan.json'):
                preserved=originals._read(storage,'plan.json')
                states=[originals.describe(workspace,storage,path)['state'] for path in preserved['entries']]
                if 'restored' in states and all(state in {'restored','untouched'} for state in states):
                    for path,record in list(actual['directories'].items()):
                        original=captured['directories'].get(path)
                        if original is None:
                            actual['directories'].pop(path);continue
                        if all(record[key]==original[key] for key in ('identity','uid','gid','mode','xattrs')):
                            record['mtime_ns']=original['mtime_ns'];record['ctime_ns']=original['ctime_ns']
            if captured!=actual:raise PermissionError('Canonical raw Git metadata changed')
    return captured


_PHASES={'guarded','import_started','import_returned'}


def _events(private):
    with os.scandir(private) as entries:
        names=sorted(entry.name for entry in entries if entry.name.startswith('phase-'))
    previous=None;result=[]
    for index,name in enumerate(names):
        if name!=f'phase-{index:08d}.json':raise PermissionError('Git phase sequence is incomplete')
        item=_read_record(private,name)
        if (not isinstance(item,dict) or set(item)!={'sequence','previous','phase','payload'}
                or type(item['sequence']) is not int or item['sequence']!=index
                or item['previous']!=previous or item['phase'] not in _PHASES
                or not isinstance(item['payload'],dict)):
            raise PermissionError('Git phase hash chain is invalid')
        if index==0 and item['phase']!='guarded':raise PermissionError('Git phase chain lacks its guard binding')
        if index>0:
            expected={'guarded':'import_started','import_started':'import_returned'}.get(result[-1]['phase'])
            if item['phase']!=expected:raise PermissionError('Git phase transition is invalid')
        previous=_digest(item);result.append(item)
    return result,previous


def inspect_git_phases(workspace,operation):
    with _open(workspace,operation) as (root,private):
        events,digest=_events(private)
        return {'events':events,'sha256':digest}


def record_git_phase(workspace,operation,phase,payload):
    """Single-writer, create-only, hash-linked coarse import lifecycle evidence."""
    if phase not in _PHASES or not isinstance(payload,dict):raise PermissionError('Invalid Git phase')
    with _open(workspace,operation) as (root,private):
        lock=os.open('phase.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=private)
        try:
            info=os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or info.st_mode&0o077:
                raise PermissionError('Untrusted Git phase lock')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            events,previous=_events(private)
            # Retrying the same exposure after process death acknowledges its
            # directory durability without duplicating a mutation intent.
            if events and events[-1]['phase']==phase and events[-1]['payload']==payload:
                os.fsync(private);return previous
            expected='guarded' if not events else {'guarded':'import_started','import_started':'import_returned'}.get(events[-1]['phase'])
            if phase!=expected:raise PermissionError('Git phase transition is invalid')
            event={'sequence':len(events),'previous':previous,'phase':phase,'payload':payload}
            if len(json.dumps(event).encode())>1024*1024:raise PermissionError('Git phase event exceeds record limit')
            _write_record(private,f'phase-{len(events):08d}.json',event)
            return _digest(event)
        finally:os.close(lock)


_NATIVE_STAGES={'before_locks','guard_created','index_staged','refs_prepare_intent',
    'refs_prepared','refs_commit_intent','refs_committed','stash_guard_created',
    'stash_publish_intent','stash_delete_intent','stash_published','index_publish_intent',
    'index_published','head_publish_intent','head_published','cleanup_intent','cleanup_finished'}


def inspect_native_git_phases(workspace,operation,expected_plan_sha256):
    """Verify raw phase evidence without applying or retiring any metadata."""
    from agentporter.sandbox.workspace_custody import _expected_record
    with _open(workspace,operation) as (root,private):
        git=os.open('.git',_FLAGS,dir_fd=root)
        try:git_identity=_identity(os.fstat(git))
        finally:os.close(git)
        with os.scandir(private) as entries:
            names=sorted(entry.name for entry in entries if entry.name.startswith('event-'))
        if len(names)>128:raise PermissionError('Native Git phase count exceeds limit')
        if not names:return {'status':'inspection_only','last_stage':None,'events':[],
                             'sha256':None,'reconciliation_supported':False}
        blobs=os.open('blobs',_FLAGS,dir_fd=private)
        events=[];previous=None;verified=set()
        try:
            _private(blobs)
            for index,name in enumerate(names):
                if name!=f'event-{index:08d}.json':raise PermissionError('Native Git phase sequence is incomplete')
                event=_read_record(private,name)
                if (not isinstance(event,dict) or set(event)!={'schema','sequence','previous','stage','plan_sha256','git','files','directories','bindings'}
                        or event['schema']!=2 or type(event['sequence']) is not int or event['sequence']!=index
                        or event['previous']!=previous or event['stage'] not in _NATIVE_STAGES
                        or event['plan_sha256']!=expected_plan_sha256 or event['git']!=git_identity
                        or not isinstance(event['files'],dict) or not isinstance(event['directories'],dict)
                        or not isinstance(event['bindings'],dict)):
                    raise PermissionError('Native Git phase binding is invalid')
                if index==0 and event['stage']!='before_locks':raise PermissionError('Native Git phase chain lacks its baseline')
                for relative,record in event['files'].items():
                    if (not isinstance(relative,str) or any(part in {'','.','..'} for part in relative.split('/'))
                            or not isinstance(record,dict) or set(record)!={'signature','sha256','uid','gid','xattrs'}):
                        raise PermissionError('Native Git phase file identity is invalid')
                    signature=record['signature']
                    if (not isinstance(signature,list) or len(signature)!=7
                            or any(type(value) is not int for value in signature)
                            or any(value<0 for value in signature[:5])
                            or not stat.S_ISREG(signature[2]) or signature[3]!=1
                            or not isinstance(record['xattrs'],dict)
                            or any(type(record[key]) is not int or record[key]<0 for key in ('uid','gid'))):
                        raise PermissionError('Native Git phase file signature is invalid')
                    digest=record['sha256']
                    if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                        raise PermissionError('Native Git phase blob digest is invalid')
                    if digest not in verified:
                        descriptor=os.open(digest,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=blobs)
                        try:_read_deletion_file(descriptor,expected_sha256=digest)
                        finally:os.close(descriptor)
                        verified.add(digest)
                for relative,identity in event['directories'].items():
                    if (not isinstance(relative,str) or any(part in {'','.','..'} for part in relative.split('/'))
                            or not isinstance(identity,list) or len(identity)!=2
                            or any(type(value) is not int or value<0 for value in identity)):
                        raise PermissionError('Native Git phase directory identity is invalid')
                for target,binding in event['bindings'].items():
                    if (not isinstance(target,str) or any(part in {'','.','..'} for part in target.split('/'))
                            or not isinstance(binding,dict) or set(binding)!={'source','record'}
                            or not isinstance(binding['source'],str)
                            or any(part in {'','.','..'} for part in binding['source'].split('/'))
                            or not isinstance(binding['record'],dict)
                            or set(binding['record'])!={'signature','sha256','uid','gid','xattrs'}):
                        raise PermissionError('Native Git descriptor binding is invalid')
                previous=_digest(event);events.append(event)
        finally:os.close(blobs)
        receipts=[]
        with os.scandir(private) as entries:
            names=sorted(entry.name for entry in entries if entry.name.startswith('descriptor-'))
        if len(names)>512:raise PermissionError('Native descriptor receipt count exceeds limit')
        for index,name in enumerate(names):
            if name!=f'descriptor-{index:08d}.json':raise PermissionError('Native descriptor receipt sequence is incomplete')
            item=_read_record(private,name)
            if (not isinstance(item,dict) or set(item)!={'schema','sequence','plan_sha256','git','target','binding'}
                    or item['schema']!=1 or type(item['sequence']) is not int or item['sequence']!=index
                    or item['plan_sha256']!=expected_plan_sha256 or item['git']!=git_identity):
                raise PermissionError('Native descriptor receipt binding is invalid')
            target=item['target'];binding=item['binding']
            if (not isinstance(target,str) or any(part in {'','.','..'} for part in target.split('/'))
                    or not isinstance(binding,dict) or set(binding)!={'source','record'}
                    or binding['source'] not in {target,target+'.lock'}):
                raise PermissionError('Native descriptor receipt namespace is invalid')
            from agentporter.sandbox.workspace_custody import _expected_record
            record=binding['record']
            try:_expected_record({**record,'mode':stat.S_IMODE(record['signature'][2]),'mtime_ns':record['signature'][5]})
            except (TypeError,KeyError,IndexError,ValueError) as error:
                raise PermissionError('Native descriptor receipt record is invalid') from error
            with _open(workspace,operation) as (_,storage):
                blobs=os.open('blobs',_FLAGS,dir_fd=storage)
                try:
                    descriptor=os.open(record['sha256'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=blobs)
                    try:_read_deletion_file(descriptor,expected_sha256=record['sha256'])
                    finally:os.close(descriptor)
                finally:os.close(blobs)
            receipts.append(item)
        opened=[]
        with os.scandir(private) as entries:
            names=sorted(entry.name for entry in entries if entry.name.startswith('opened-'))
        if len(names)>512:raise PermissionError('Native opened receipt count exceeds limit')
        for index,name in enumerate(names):
            if name!=f'opened-{index:08d}.json':raise PermissionError('Native opened receipt sequence is incomplete')
            item=_read_record(private,name)
            if (not isinstance(item,dict) or set(item)!={'schema','sequence','plan_sha256','git','target','before','after_sha256','after_size'}
                    or item['schema']!=1 or type(item['sequence']) is not int or item['sequence']!=index
                    or item['plan_sha256']!=expected_plan_sha256 or item['git']!=git_identity
                    or not isinstance(item['target'],str) or not item['target'].startswith('logs/refs/')
                    or any(part in {'','.','..'} for part in item['target'].split('/'))
                    or type(item['after_size']) is not int or not 0<=item['after_size']<=67108864):
                raise PermissionError('Native opened receipt binding is invalid')
            record=item['before']
            try:_expected_record({**record,'mode':stat.S_IMODE(record['signature'][2]),'mtime_ns':record['signature'][5]})
            except (TypeError,KeyError,IndexError,ValueError) as error:
                raise PermissionError('Native opened descriptor identity is invalid') from error
            digest=item['after_sha256']
            if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):
                raise PermissionError('Native opened mutation digest is invalid')
            blobs=os.open('blobs',_FLAGS,dir_fd=private)
            try:
                descriptor=os.open(digest,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=blobs)
                try:
                    data,_,_=_read_deletion_file(descriptor,expected_sha256=digest)
                    if len(data)!=item['after_size']:raise PermissionError('Native opened mutation size differs')
                finally:os.close(descriptor)
            finally:os.close(blobs)
            opened.append(item)
        last=events[-1]['stage']
        return {'status':'inspection_only','last_stage':last,'events':events,'sha256':previous,
                # Even cleanup can run after a failed/partial native mutation.
                # A stage label is never proof of one coherent endpoint.
                'outcome_uncertain':True,'terminal_endpoint_verified':False,'descriptor_receipts':receipts,'opened_receipts':opened,
                'reconciliation_supported':False}


def _native_record(record):
    """Normalize a saved host baseline observation to native record format."""
    return {'signature':[record['identity'][0],record['identity'][1],stat.S_IFREG|record['mode'],
                         1,record['size'],record['mtime_ns'],record['ctime_ns']],
            'sha256':record['sha256'],'uid':record['uid'],'gid':record['gid'],'xattrs':record['xattrs']}


def _same_native(actual,expected,*,renamed=False):
    left=actual['signature'];right=expected['signature']
    identity=(left[:-1]==right[:-1] and left[-1]>=right[-1]) if renamed else left==right
    return identity and all(actual[key]==expected[key] for key in ('sha256','uid','gid','xattrs'))


def _mutable_git_path(path):
    return (path in {'index','HEAD','packed-refs','refs/stash','logs/HEAD','logs/refs/stash'}
            or path.startswith(('refs/heads/','refs/tags/','logs/refs/heads/','logs/refs/tags/')))


def _approved_pull_scope(workspace,history,guard,plan,*,registry,state_dir,owner_config_dir):
    """Validate spent authority against independently supplied operator context."""
    approved=plan.get('approved_pull')
    if approved is None:return (),None
    if registry is None or state_dir is None or owner_config_dir is None:
        raise PermissionError('Approved pull recovery requires trusted registry and owner configuration context')
    if (not isinstance(approved,dict) or set(approved) not in ({'authorization','consumed_guard_record',
            'consumed_guard_custody','admission_token','candidate_directory'},
            {'authorization','consumed_guard_record','consumed_guard_custody','admission_token',
             'candidate_directory','workspace_guard_path'})
            or approved['candidate_directory']!=str(history.parent)
            or approved['consumed_guard_custody']!=str(guard.parent.parent/'pull-guard-custody'/history.parent.name)
            or not isinstance(approved['admission_token'],str) or not approved['admission_token']):
        raise PermissionError('Approved pull recovery evidence is not bound to its transaction')
    from agentporter.git_pulls import validate_pull_authorization
    paths=validate_pull_authorization(approved['authorization'],registry=registry,state_dir=state_dir,
                                      owner_config_dir=owner_config_dir)
    authority=approved['authorization'];tracking=authority['tracking'];ref=paths[0]
    before=plan['before']['refs'].get(ref);after=plan['after']['refs'].get(ref)
    expected_before=None if set(tracking['old_oid'])=={'0'} else {'oid':tracking['old_oid'],'symref':None}
    if before!=expected_before or after!={'oid':tracking['new_oid'],'symref':None}:
        raise PermissionError('Native tracking transition differs from exact consumed pull request')
    # Signed logical path is independently validated against protected registry
    # above. Physical recovery may use its verified publication FD alias.
    observed=Path(workspace).stat();request=authority['request']
    if (observed.st_dev,observed.st_ino)!=(request['repository_device'],request['repository_inode']):
        raise PermissionError('Consumed pull authority names another recovery repository')
    from agentporter.sandbox import workspace_custody as custody
    slot=Path(approved['consumed_guard_custody'])
    held=custody.inspect_custody(guard.parent,slot)
    if held['state'] not in {'captured_expected','captured_conflict'} or not held['expected']:
        raise PermissionError('Original consumed pull guard custody is unresolved')
    workspace_guard=guard
    params=authority['request']['parameters']
    if 'repository_relative' in params:
        from types import SimpleNamespace
        from agentporter.workspaces.leases import workspace_key
        parent=params['workspace_identity']
        workspace_guard=guard.parent/(workspace_key(SimpleNamespace(st_dev=parent['device'],st_ino=parent['inode']))+'.git-pending.json')
        if approved.get('workspace_guard_path')!=str(workspace_guard):
            raise PermissionError('Nested pull guard differs from its signed parent workspace identity')
    elif 'workspace_guard_path' in approved:
        raise PermissionError('Unexpected separate workspace guard')
    descriptor=os.open(slot,_FLAGS)
    try:
        intent=custody._read_record(descriptor,'intent.json')
        if (intent['path']!=workspace_guard.name or intent['expected']!=custody._expected_record(approved['consumed_guard_record'])
                or not custody._matches_expected(descriptor,'captured',intent['expected'],renamed=True)):
            raise PermissionError('Consumed pull guard custody differs from exact descriptor record')
    finally:os.close(descriptor)
    from agentporter.sandbox.workspace_recovery import _read_private_json
    original,_=_read_private_json(slot/'captured')
    kinds=({'private-job-fetch-candidate'} if authority['request']['operation']=='fetch'
           else {'private-pull-candidate','private-job-pull-candidate'})
    if (original.get('kind') not in kinds
            or original.get('tracking_authorization')!=authority
            or original.get('request')!=authority['request']
            or original.get('request_sha256')!=authority['request_sha256']
            or original.get('approval_nonce')!=authority['approval_nonce']
            or original.get('admission_token')!=approved['admission_token']
            or original.get('candidate_directory')!=str(history.parent)
            or original.get('canonical_published') is not False):
        raise PermissionError('Captured consumed guard does not bind exact pull authorization')
    return paths,approved


def inspect_git_reconciliation(workspace,history_directory,guard,*,retired_guard=None,
                               pull_registry=None,pull_state_dir=None,pull_owner_config_dir=None):
    """Classify raw state; descriptor provenance never comes from after bytes.

    This returns no mutation authority. Native refs/reflogs without an actual
    pre-mutation descriptor binding remain explicitly unproven.
    """
    from agentporter.sandbox.workspace_recovery import _read_private_json
    from agentporter.sandbox.workspace_custody import _matches_expected
    history=Path(history_directory).resolve(strict=True);guard=Path(guard)
    guard_source=guard
    guard_state='held'
    if not os.path.lexists(guard) and retired_guard is not None:
        from agentporter.sandbox.workspace_custody import inspect_custody
        held=inspect_custody(guard.parent,retired_guard)
        if held['state']!='captured_expected' or not held['expected']:
            raise PermissionError('Git recovery guard custody is unresolved')
        guard_source=Path(retired_guard)/'captured';guard_state='captured'
    payload,guard_hash=_read_private_json(guard_source)
    required={'version','workspace','plan','exchange','raw_baseline','native_journal'}
    version=payload.get('version') if isinstance(payload,dict) else None
    if version in (6,7):required.add('original_metadata')
    if (not isinstance(payload,dict) or set(payload)!=required or version not in (5,6,7)
            or payload['workspace']!=str(Path(workspace).resolve(strict=True))
            or payload['exchange']!=str(history/'exchange')
            or payload['native_journal']!=str(history/'native-events')
            or not isinstance(payload['raw_baseline'],dict)
            or set(payload['raw_baseline'])!={'directory','sha256'}
            or payload['raw_baseline']['directory']!=str(history/'raw-before')):
        raise PermissionError('Git reconciliation guard binding is invalid')
    before=read_git_baseline(workspace,history/'raw-before',payload['raw_baseline']['sha256'])
    approved_paths,approved_pull=_approved_pull_scope(workspace,history,guard,payload['plan'],
        registry=pull_registry,state_dir=pull_state_dir,owner_config_dir=pull_owner_config_dir)
    if (version==7)!=(approved_pull is not None):raise PermissionError('Pull recovery guard version differs from approved authority')
    preservation={};preservation_directory=history/'preserved-metadata'
    if version in (6,7):
        from agentporter.sandbox import git_original_metadata as originals
        pinned=payload['original_metadata']
        preserved=originals._read(preservation_directory,'plan.json')
        if (not isinstance(pinned,dict) or set(pinned)!={'directory','sha256'}
                or pinned['directory']!=str(preservation_directory) or pinned['sha256']!=_digest(preserved)
                or preserved['baseline_directory']!=str(history/'raw-before')
                or preserved['baseline_sha256']!=payload['raw_baseline']['sha256']
                or any(not originals._admitted(path,approved_paths) for path in preserved['entries'])):
            raise PermissionError('Original metadata preservation differs from bound Git guard')
        if (tuple(preserved.get('approved_paths',()))!=approved_paths
                or preserved.get('approval_sha256')!=(_digest(approved_pull['authorization']) if approved_pull else None)):
            raise PermissionError('Preserved tracking metadata lacks its exact verified authorization digest')
        for path,entry in preserved['entries'].items():
            original=_native_record(before['files'][path])
            if entry['original']!=originals._record(original):
                raise PermissionError('Preserved original identity differs from immutable baseline')
            preservation[path]=originals.describe(workspace,preservation_directory,path)
    coarse=inspect_git_phases(workspace,history/'raw-before')
    if not coarse['events']:raise PermissionError('Git reconciliation lacks its guard lifecycle')
    binding=coarse['events'][0]['payload']
    if binding.get('guard_sha256')!=guard_hash or binding.get('baseline_sha256')!=payload['raw_baseline']['sha256']:
        raise PermissionError('Git reconciliation guard hash differs from lifecycle')
    if not isinstance(binding.get('guard_record'),dict):
        raise PermissionError('Git reconciliation lacks descriptor-bound guard provenance')
    descriptor=os.open(guard_source.parent,_FLAGS)
    try:
        if not _matches_expected(descriptor,guard_source.name,binding['guard_record'],renamed=guard_state=='captured'):
            raise PermissionError('Git reconciliation guard identity conflicts with owner work')
    finally:os.close(descriptor)
    native=inspect_native_git_phases(workspace,history/'native-events',_digest(payload['plan']))
    anchored=False
    if coarse['events'][-1]['phase']=='import_returned':
        if coarse['events'][-1]['payload'].get('native_events_sha256')!=native['sha256']:
            raise PermissionError('Native Git phase tail differs from returned lifecycle')
        anchored=True
    with _open(workspace,history) as (root,private):
        current=_snapshot(root,allow_locks=True)
    if any(before[key]!=current[key] for key in ('workspace','git','mount_id')):
        raise PermissionError('Git reconciliation workspace or metadata root changed')
    directory_conflicts=[];directory_time_drift=[]
    for path,original in before['directories'].items():
        actual=current['directories'].get(path)
        if actual is None or any(actual[k]!=original[k] for k in ('identity','uid','gid','mode','xattrs')):
            directory_conflicts.append(path)
        elif any(actual[k]!=original[k] for k in ('mtime_ns','ctime_ns')):
            directory_time_drift.append(path)
    original_files={path:_native_record(record) for path,record in before['files'].items()}
    current_files={path:_native_record(record) for path,record in current['files'].items()}
    descriptor_bindings={};observed={}
    for event in native['events']:
        for target,item in event['bindings'].items():
            descriptor_bindings.setdefault(target,[]).append(item['record'])
        for path,record in event['files'].items():observed.setdefault(path,[]).append(record)
    for receipt in native.get('descriptor_receipts',[]):
        descriptor_bindings.setdefault(receipt['target'],[]).append(receipt['binding']['record'])
    for receipt in native.get('opened_receipts',[]):
        actual=current_files.get(receipt['target']);initial=receipt['before']
        # Authority is the descriptor retained before native append, plus exact
        # authorized bytes. The current raw observation supplies no ownership.
        if (actual is not None and actual['signature'][:4]==initial['signature'][:4]
                and actual['signature'][6]>=initial['signature'][6]
                and all(actual[key]==initial[key] for key in ('uid','gid','xattrs'))
                and actual['sha256']==receipt['after_sha256'] and actual['signature'][4]==receipt['after_size']):
            descriptor_bindings.setdefault(receipt['target'],[]).append(actual)
    entries=[]
    for path in sorted(set(original_files)|set(current_files)):
        actual=current_files.get(path);original=original_files.get(path)
        held=preservation.get(path)
        if any(path==p or path.startswith(p+'/') for p in directory_conflicts):
            state='owner_directory_conflict'
        elif held is not None and held['state'] in {'conflict','owner_custody_conflict'}:
            state='owner_custody_conflict'
        elif held is not None and held['state']=='restored' and actual is not None and _same_native(actual,original,renamed=True):
            state='baseline_restored'
        elif actual is None and held is not None and held['state']=='held':
            state='original_retained_restore_pending'
        elif held is not None and held['current']=='before_copy':
            state='verified_before_copy'
        elif actual is None:
            state='missing_original_unproven' if original is not None else 'absent'
        elif original is not None and _same_native(actual,original):state='baseline'
        elif any(_same_native(actual,record,renamed=True) for record in descriptor_bindings.get(path,[])):
            state='descriptor_bound_candidate'
        elif any(_same_native(actual,record,renamed=True) for record in observed.get(path,[])):
            state='native_observation_unproven'
        else:state='owner_or_unrecorded_conflict'
        # Protected config/hooks/remote metadata cannot gain mutation authority
        # from a record in a native journal or a convenient equal-byte hash.
        mutable=_mutable_git_path(path) or path in approved_paths
        transient=path in descriptor_bindings and (path.endswith('.lock') or path.startswith('.agentporter-')
                       or path.startswith('logs/refs/.agentporter-'))
        if state=='descriptor_bound_candidate' and not (mutable or transient):state='protected_metadata_conflict'
        entries.append({'path':path,'state':state,'mutable_metadata':mutable,
                        'actual':actual,'before':original})
    new_directories=sorted(set(current['directories'])-set(before['directories']))
    baseline_states={'baseline','baseline_restored'}
    unchanged=(not directory_conflicts and all(item['state'] in baseline_states for item in entries))
    capture_plan=[]
    for entry in entries:
        path=entry['path']
        allowed=(path in {'index.lock','HEAD.lock','refs/stash.lock','index'}
                 or re.fullmatch(r'[.]agentporter-(?:index|head)-[a-f0-9]{32}',path)
                 or re.fullmatch(r'logs/refs/[.]agentporter-stash-[a-f0-9]{32}',path)
                 or path.startswith(('refs/heads/','refs/tags/','logs/refs/heads/','logs/refs/tags/'))
                 or path in {'refs/stash','logs/refs/stash'}
                 or path in approved_paths or (approved_paths and path==approved_paths[0]+'.lock'))
        if entry['before'] is None and entry['state']=='descriptor_bound_candidate' and allowed:
            record=entry['actual']
            capture_plan.append({'path':path,'record':{**record,'mode':stat.S_IMODE(record['signature'][2]),
                'mtime_ns':record['signature'][5]},'slot':hashlib.sha256(path.encode()).hexdigest()})
    capture_paths={item['path'] for item in capture_plan}
    restore_plan=[]
    for entry in entries:
        path=entry['path'];held=preservation.get(path)
        if held is None or held['state']!='held':continue
        if entry['state'] in {'verified_before_copy','original_retained_restore_pending'}:
            restore_plan.append({'path':path,'proven_after':None})
        elif entry['state']=='descriptor_bound_candidate':
            proven=next(record for record in descriptor_bindings.get(path,[]) if _same_native(entry['actual'],record,renamed=True))
            restore_plan.append({'path':path,'proven_after':proven})
    restore_paths={item['path'] for item in restore_plan}
    safe_before=(not directory_conflicts
                 and all(item['state'] in baseline_states or item['path'] in capture_paths or item['path'] in restore_paths for item in entries))
    metadata_identity={key:before[key] for key in ('workspace','git')}
    metadata_parents={key:value['identity'] for key,value in current['directories'].items()}
    custody_states=[]
    storage=history/'metadata-rollback'
    if os.path.lexists(storage):
        from agentporter.sandbox import git_metadata_custody as bridge
        descriptor=os.open(storage,_FLAGS)
        try:
            _private(descriptor)
            with os.scandir(descriptor) as children:names=sorted(child.name for child in children)
        finally:os.close(descriptor)
        if len(names)>100000:raise PermissionError('Metadata rollback custody exceeds limit')
        for name in names:
            if len(name)!=64 or any(c not in '0123456789abcdef' for c in name):
                raise PermissionError('Invalid metadata rollback custody slot')
            parent=os.open(storage/name,_FLAGS)
            try:
                _private(parent)
                try:intent=_read_record(parent,'intent.json')
                except FileNotFoundError:
                    with os.scandir(parent) as items:
                        if next(items,None) is not None:raise PermissionError('Unbound metadata custody contents require inspection')
                    continue
            finally:os.close(parent)
            relative=intent['path']
            if hashlib.sha256(relative.encode()).hexdigest()!=name:raise PermissionError('Metadata custody slot path mismatch')
            held=bridge.inspect_git_entry(workspace,relative,storage/name,identity=metadata_identity,parents=metadata_parents,approved_paths=approved_paths)
            custody_states.append({'path':relative,'state':held['state'],'expected':held['expected']})
            if held['state']!='captured_expected' or not held['expected']:safe_before=False
    plan={'status':'inspection_only','guard_sha256':guard_hash,'baseline_sha256':payload['raw_baseline']['sha256'],
          'native_tail_sha256':native['sha256'],'native_tail_anchored':anchored,
          'native_descriptor_receipts_sha256':_digest(native.get('descriptor_receipts',[])),
          'native_opened_receipts_sha256':_digest(native.get('opened_receipts',[])),
          'last_stage':native['last_stage'],'files':entries,'directory_conflicts':directory_conflicts,
          'directory_time_drift':directory_time_drift,
          'directory_timestamp_policy':'retain_current_times_verify_inode_access_and_complete_children',
          'new_metadata_directories':new_directories,
          'new_metadata_directory_policy':'retain_current_directories_never_delete_or_restore_times',
          'guard_state':guard_state,
          'before_endpoint_verified':unchanged and safe_before,'apply_supported':safe_before,
          'metadata_capture_plan':capture_plan,'metadata_identity':metadata_identity,
          'metadata_parents':metadata_parents,'metadata_custody':custody_states,
          'metadata_approved_paths':list(approved_paths),
          'approved_pull':approved_pull,
          'original_preservation':preservation,'original_restore_plan':restore_plan,
          'preserved_originals_directory':str(preservation_directory) if version in (6,7) else None,
          'guards_retained':True}
    plan['plan_sha256']=_digest(plan)
    return plan
