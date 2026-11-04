"""Preflight and exact-inode retirement of trusted native import guards."""
import hashlib
import os
import stat

from agentporter.sandbox import workspace_custody as custody
from agentporter.sandbox import git_metadata_custody as bridge
from agentporter.sandbox.workspace_git_recovery import _digest


def _write(directory,name,data):
    descriptor=os.open(directory,custody._FLAGS)
    try:custody._write_record(descriptor,name,data)
    finally:os.close(descriptor)


def _read(directory,name):
    descriptor=os.open(directory,custody._FLAGS)
    try:
        custody._private(descriptor)
        return custody._read_record(descriptor,name)
    finally:os.close(descriptor)


def preflight(workspace,directory,baseline,plan):
    directory.mkdir(mode=0o700,exist_ok=True)
    identity={key:baseline[key] for key in ('workspace','git')}
    parents={key:value['identity'] for key,value in baseline['directories'].items()}
    paths=['index.lock','HEAD.lock']
    if plan['before']['stash_log']!=plan['after']['stash_log']:paths.append('refs/stash.lock')
    entries=[]
    for path in paths:
        slot=hashlib.sha256(path.encode()).hexdigest()
        support=bridge.preflight_git_entry(workspace,path,directory/slot,identity=identity,parents=parents)
        entries.append({'path':path,'slot':slot,'support':support})
    record={'schema':1,'plan_sha256':_digest(plan),'identity':identity,'parents':parents,'entries':entries}
    _write(directory,'preflight.json',record)
    return record


def retire(workspace,directory,plan,native):
    """Retry only retained guards; never rerun the native ref transaction."""
    record=_read(directory,'preflight.json')
    if record['plan_sha256']!=_digest(plan) or native['last_stage']!='cleanup_finished':
        raise PermissionError('Native guard cleanup lacks a matching completed import phase')
    bindings=native['events'][-1]['bindings']
    entries=[]
    for entry in record['entries']:
        binding=bindings.get(entry['path'])
        if binding is None or binding['source']!=entry['path']:
            raise PermissionError('Native guard has no exact original descriptor binding')
        expected=binding['record']
        expected={**expected,'mode':stat.S_IMODE(expected['signature'][2]),'mtime_ns':expected['signature'][5]}
        entries.append({**entry,'expected':expected})
    cleanup={'schema':1,'plan_sha256':_digest(plan),'native_sha256':native['sha256'],'entries':entries}
    _write(directory,'cleanup-plan.json',cleanup)
    for entry in entries:
        bridge.capture_git_entry(workspace,entry['path'],directory/entry['slot'],
            identity=record['identity'],parents=record['parents'],expected_record=entry['expected'],
            expected_support=entry['support'])
    _write(directory,'done.json',{'schema':1,'cleanup_sha256':_digest(cleanup)})
    return _digest(cleanup)
