"""Retain exact original index/HEAD inodes while exposing verified before copies.

The trusted importer exposes before copies while custody retains physical
originals. Callers hold maintenance/workspace leases and transaction guards.
"""
import os
import hashlib
import json
from pathlib import Path
import stat

from agentporter.sandbox import workspace_custody as custody,git_metadata_custody as bridge
from agentporter.sandbox.workspace_delta import restore_workspace_deletion,_file_signature,_read_deletion_file
from agentporter.sandbox.workspace_git_recovery import read_git_baseline,_native_record


def _read(directory,name):
    fd=os.open(directory,custody._FLAGS)
    try:custody._private(fd);return custody._read_record(fd,name)
    finally:os.close(fd)


def _write(directory,name,value):
    if len(json.dumps(value).encode())>1024*1024:
        raise PermissionError('Original metadata record exceeds durable reader limit')
    fd=os.open(directory,custody._FLAGS)
    try:custody._write_record(fd,name,value)
    finally:os.close(fd)


def _record(value):
    result=dict(value);signature=list(result['signature']);signature[3]=1
    result.update(signature=signature,mode=stat.S_IMODE(signature[2]),mtime_ns=signature[5])
    return custody._expected_record(result)


def _admitted(path,approved_paths=()):
    return path in bridge._approved_paths(approved_paths) or path in {'index','HEAD','refs/stash','logs/refs/stash'} or path.startswith(
        ('refs/heads/','refs/tags/','logs/refs/heads/','logs/refs/tags/'))


def _key(path):
    return path if path in {'index','HEAD'} else hashlib.sha256(path.encode()).hexdigest()


def prepare(workspace,baseline_directory,baseline_sha256,directory,*,approved_paths=(),approval_sha256=None):
    approved_paths=bridge._approved_paths(approved_paths)
    if bool(approved_paths)!=(isinstance(approval_sha256,str) and len(approval_sha256)==64 and all(c in '0123456789abcdef' for c in approval_sha256)):
        raise PermissionError('Tracking metadata custody requires its exact authorization digest')
    directory=Path(directory)
    if directory.resolve().is_relative_to(Path(workspace).resolve(strict=True)):
        raise PermissionError('Original metadata storage must be outside the entire workspace')
    directory.mkdir(mode=0o700,exist_ok=True)
    baseline=read_git_baseline(workspace,baseline_directory,baseline_sha256)
    identity={key:baseline[key] for key in ('workspace','git')}
    parents={key:value['identity'] for key,value in baseline['directories'].items()}
    entries={}
    for path in sorted(baseline['files']):
        if not _admitted(path,approved_paths):continue
        original=baseline['files'].get(path)
        if original is None:continue
        entries[path]={'original':_record(_native_record(original)),
            'support':bridge.preflight_git_entry(workspace,path,directory/('original-'+_key(path)),identity=identity,parents=parents,approved_paths=approved_paths),
            'displaced_support':bridge.preflight_git_entry(workspace,path,directory/('displaced-'+_key(path)),identity=identity,parents=parents,approved_paths=approved_paths)}
    record={'schema':1,'baseline_directory':str(Path(baseline_directory)),
            'baseline_sha256':baseline_sha256,'identity':identity,'parents':parents,'entries':entries}
    if approved_paths:record.update(schema=2,approved_paths=list(approved_paths),approval_sha256=approval_sha256)
    _write(directory,'plan.json',record)
    return record


def _plan(directory,path):
    plan=_read(directory,'plan.json')
    if not _admitted(path,tuple(plan.get('approved_paths',()))):raise PermissionError('Original custody only admits bounded mutable metadata')
    if path not in plan['entries']:raise PermissionError('No original inode was captured in the baseline')
    return plan,plan['entries'][path]


def _attempts(directory,path):
    prefix=_key(path)+'-attempt-'
    fd=os.open(directory,custody._FLAGS)
    try:
        custody._private(fd)
        with os.scandir(fd) as entries:names=sorted(entry.name for entry in entries if entry.name.startswith(prefix))
        if len(names)>1000:raise PermissionError('Original metadata attempt limit exceeded')
        result=[]
        for index,name in enumerate(names):
            if name!=prefix+f'{index:04d}.json':raise PermissionError('Original metadata attempt sequence invalid')
            result.append(custody._read_record(fd,name))
        return result
    finally:os.close(fd)


def _matches(source,path,record):
    fd=os.open(source,custody._FLAGS)
    try:return custody._is_expected(fd,path,_record(record),renamed=True)
    finally:os.close(fd)


def publish_before_copy(workspace,directory,path):
    directory=Path(directory);plan,entry=_plan(directory,path)
    # The full saved-blob verification remains strict even after the original
    # has moved; current canonical metadata is classified separately below.
    read_git_baseline(workspace,plan['baseline_directory'],plan['baseline_sha256'])
    with bridge._view(workspace,path,directory/('original-'+_key(path)),plan['identity'],plan['parents'],tuple(plan.get('approved_paths',()))) as (source,name):
        attempts=_attempts(directory,path)
        for candidate in attempts:
            if _matches(source,path,candidate):return _record(candidate)
        target=Path(source)/path
        if os.path.lexists(target):
            if not _matches(source,path,entry['original']):
                raise PermissionError('Original metadata destination contains later owner work')
            replace=entry['original']
        else:
            retained=bridge.inspect_git_entry(workspace,path,directory/('original-'+_key(path)),
                identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
            if retained['state']!='captured_expected' or not retained['expected']:
                raise PermissionError('Missing canonical original has no verified custody')
            replace=None
        blob=Path(plan['baseline_directory'])/'blobs'/entry['original']['sha256']
        info=blob.stat()
        copied={**entry['original'],'backup_signature':list(_file_signature(info)),
                'atime_ns':entry['original']['mtime_ns']}
        def prepared(candidate):
            _write(directory,_key(path)+'-attempt-'+f'{len(attempts):04d}.json',candidate)
        restore_workspace_deletion(source,path,blob,record=copied,replace_record=replace,
            on_prepared=prepared,custody_operation=directory/('original-'+_key(path)),expected_support=entry['support'])
        return _record(_attempts(directory,path)[-1])


def restore_original(workspace,directory,path,*,proven_after=None):
    directory=Path(directory);plan,entry=_plan(directory,path)
    original_slot=directory/('original-'+_key(path))
    with bridge._view(workspace,path,original_slot,plan['identity'],plan['parents'],tuple(plan.get('approved_paths',()))) as (source,name):
        displaced=directory/('displaced-'+_key(path))
        try:displaced_intent=_read(displaced,'intent.json')
        except FileNotFoundError:displaced_intent=None
        if displaced_intent is not None:
            held=bridge.inspect_git_entry(workspace,path,displaced,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
            if not held['expected']:
                bridge.restore_git_entry(workspace,path,displaced,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
                raise PermissionError('Captured owner metadata restored; original remains retained')
            if held['state']=='captured_expected':
                bridge.capture_git_entry(workspace,path,displaced,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())),
                    expected_record=displaced_intent['expected'],expected_support=entry['displaced_support'])
        retained=bridge.inspect_git_entry(workspace,path,original_slot,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
        if retained['state']=='restored' and retained['expected']:return retained
        if not retained['expected'] or retained['state'] not in {'captured_expected','captured_conflict'}:
            raise PermissionError('Original metadata custody is not verifiable')
        if os.path.lexists(Path(source)/path):
            candidates=_attempts(directory,path)
            if proven_after is not None:candidates.append(proven_after)
            matched=next((candidate for candidate in candidates if _matches(source,path,candidate)),None)
            if matched is None:raise PermissionError('Metadata restore preserves later owner destination')
            fd=os.open(Path(source)/path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                actual=list(_file_signature(os.fstat(fd)));known=_record(matched)['signature']
                if actual[:-1]!=known[:-1] or actual[-1]<known[-1]:
                    raise PermissionError('Metadata identity changed before displacement')
                _read_deletion_file(fd,expected_signature=actual,expected_sha256=matched['sha256'])
            finally:os.close(fd)
            expected={**_record(matched),'signature':actual}
            bridge.capture_git_entry(workspace,path,directory/('displaced-'+_key(path)),identity=plan['identity'],
                parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())),expected_record=expected,expected_support=entry['displaced_support'])
        return bridge.restore_git_entry(workspace,path,original_slot,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))


def describe(workspace,directory,path):
    directory=Path(directory);plan,entry=_plan(directory,path)
    original=directory/('original-'+_key(path))
    try:_read(original,'intent.json')
    except FileNotFoundError:return {'state':'untouched','current':'original'}
    held=bridge.inspect_git_entry(workspace,path,original,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
    displaced=directory/('displaced-'+_key(path))
    try:_read(displaced,'intent.json')
    except FileNotFoundError:displaced_state=None
    else:displaced_state=bridge.inspect_git_entry(workspace,path,displaced,identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
    if not held['expected'] or (displaced_state is not None and not displaced_state['expected']):
        return {'state':'owner_custody_conflict','current':'unproven'}
    if held['state']=='restored':return {'state':'restored','current':'original'}
    if held['state'] not in {'captured_expected','captured_conflict'}:
        return {'state':'conflict','current':'unproven'}
    with bridge._view(workspace,path,original,plan['identity'],plan['parents'],tuple(plan.get('approved_paths',()))) as (source,name):
        if not os.path.lexists(Path(source)/path):return {'state':'held','current':'absent'}
        for candidate in _attempts(directory,path):
            if _matches(source,path,candidate):return {'state':'held','current':'before_copy','record':_record(candidate)}
    return {'state':'held','current':'other'}


def preflight_restore(workspace,directory,path):
    directory=Path(directory);plan,entry=_plan(directory,path)
    for name,key in (('original-','support'),('displaced-','displaced_support')):
        actual=bridge.preflight_git_entry(workspace,path,directory/(name+_key(path)),
            identity=plan['identity'],parents=plan['parents'],approved_paths=tuple(plan.get('approved_paths',())))
        if actual!=entry[key]:raise PermissionError('Original metadata custody support changed')
