#!/usr/bin/python3
"""Owner-run, Wei-only v12 route repair. Default: proposal, no changes.

--apply runs fixed code as agentporter-dev, never Python as root. No service
restart, paid request, credential refresh, production or other-worker change.
"""
import argparse
import hashlib
import os
from pathlib import Path
import pwd
import subprocess

RELEASE = Path('/opt/agentporter-development/versions/20261021T132836.936455Z')
RUNTIME_SHA = 'a7df3487448198ae05d4e2c6e881ad8f8f27798b675a6c2d1bf5dceccf1d0100'
SERVICE_CODE = r'''
import copy,hashlib,json,os,pwd,secrets,stat
from pathlib import Path
import yaml

MODEL='opencode/glm-5.3-flash-free'
CONFIG=Path('/var/lib/agentporter-dev/config')
CREDENTIALS=Path('/var/lib/agentporter-dev/credentials/wei/.config/opencode')
PUBLIC=b'public\n'

def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)

def private_dir(path,uid,gid):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        info=os.fstat(fd)
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(uid,gid,0o700):
            raise PermissionError('Expected private service-owned directory')
        return fd
    except BaseException:
        os.close(fd);raise

def read_private(fd,name,uid,gid):
    file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    try:
        info=os.fstat(file)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(uid,gid,0o600)
                or not 0<info.st_size<=1024**2):
            raise PermissionError('Expected bounded private regular service file')
        data=os.read(file,1024**2+1)
        if len(data)!=info.st_size or identity(os.fstat(file))!=identity(info):
            raise PermissionError('Private file changed while reading')
        return data,info
    finally:os.close(file)

def publish_new(fd,name,data):
    temporary='.wei-free-'+secrets.token_hex(12)
    file=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    try:
        with os.fdopen(file,'wb',closefd=False) as handle:
            handle.write(data);handle.flush();os.fsync(file)
        os.link(temporary,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
        os.fsync(fd)
    finally:
        os.close(file);os.unlink(temporary,dir_fd=fd)

def transform(before,credentials):
    if (before.get('profile'),before.get('enabled'),before.get('gateway_user'),before.get('production_uid'))!=('development',True,'agentporter-dev',1000):
        raise PermissionError('Unexpected runtime identity/profile')
    workers=before.get('workers',{})
    wei=workers.get('wei',{})
    old={'provider':'opencode-go','model':'opencode-go/glm-5.3-flash',
         'credentials':{'.config/opencode/wei-key':str(credentials/'wei-key')}}
    new={'provider':'opencode','model':MODEL,
         'credentials':{'.config/opencode/wei-key':str(credentials/'free-access')}}
    current={k:wei.get(k) for k in old}
    if current!=old and current!=new:
        raise PermissionError('Wei route differs from reviewed old/new pair; preserve it')
    after=copy.deepcopy(before)
    after['workers']['wei'].update(new)
    expected=copy.deepcopy(after)
    expected['workers']['wei']=copy.deepcopy(before['workers']['wei'])
    if expected!=before:
        raise PermissionError('Unrelated runtime change detected')
    return after

def repair(config,credentials,uid,gid):
    config_fd=private_dir(config,uid,gid)
    credential_fd=None
    try:
        credential_fd=private_dir(credentials,uid,gid)
        raw,original_info=read_private(config_fd,'development-runtime.yaml',uid,gid)
        before=yaml.safe_load(raw)
        after=transform(before,credentials)
        proposed=yaml.safe_dump(after,sort_keys=False).encode()
        if yaml.safe_load(proposed)!=after:
            raise ValueError('Runtime serialization changed data')
        try: marker,_=read_private(credential_fd,'free-access',uid,gid)
        except FileNotFoundError:
            publish_new(credential_fd,'free-access',PUBLIC)
        else:
            if marker!=PUBLIC:raise PermissionError('Existing free-access file differs; preserve it')
        if before==after:return {'changed':False,'provider':'opencode','model':MODEL}
        backup='development-runtime.before-wei-free-'+hashlib.sha256(raw).hexdigest()+'.yaml'
        try: saved,_=read_private(config_fd,backup,uid,gid)
        except FileNotFoundError:publish_new(config_fd,backup,raw)
        else:
            if saved!=raw:raise PermissionError('Backup differs; preserve it')
        temporary='.wei-runtime-'+secrets.token_hex(12)
        file=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=config_fd)
        try:
            with os.fdopen(file,'wb',closefd=False) as handle:
                handle.write(proposed);handle.flush();os.fsync(file)
            current,current_info=read_private(config_fd,'development-runtime.yaml',uid,gid)
            if current!=raw or identity(current_info)!=identity(original_info):
                raise PermissionError('Runtime changed concurrently; preserve it')
            os.replace(temporary,'development-runtime.yaml',src_dir_fd=config_fd,dst_dir_fd=config_fd)
            temporary=None;os.fsync(config_fd)
        finally:
            os.close(file)
            if temporary:os.unlink(temporary,dir_fd=config_fd)
        return {'changed':True,'provider':'opencode','model':MODEL,'backup':str(config/backup),
            'other_workers_changed':False,'paid_credential_used':False,'service_restarted':False,
            'production_changed':False,'network_requests':0}
    finally:
        if credential_fd is not None:os.close(credential_fd)
        os.close(config_fd)

if __name__=='__main__':
    account=pwd.getpwnam('agentporter-dev')
    if os.getuid()!=account.pw_uid or os.geteuid()!=account.pw_uid or account.pw_uid in (0,1000):
        raise PermissionError('Run only as the separate A7Dev account')
    os.umask(0o077)
    print(json.dumps(repair(CONFIG,CREDENTIALS,account.pw_uid,account.pw_gid)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print('Wei only: opencode-go/glm-5.3-flash -> opencode/glm-5.3-flash-free', flush=True)
    print('Use a separate public placeholder file; preserve paid key and every other worker.', flush=True)
    if not args.apply:
        print('Proposal only. No files changed or commands executed. No restart required.')
        return
    if os.getuid() != pwd.getpwnam('operator').pw_uid or not os.isatty(0):
        raise PermissionError('Apply as operator in an independently authorized local terminal')
    if Path('/opt/agentporter-development/current').resolve() != RELEASE:
        raise PermissionError('Installed release changed; review proposal again')
    runtime = RELEASE / 'src/agentporter/agents/development.py'
    if hashlib.sha256(runtime.read_bytes()).hexdigest() != RUNTIME_SHA:
        raise PermissionError('Installed runtime changed; review proposal again')
    subprocess.run(['/usr/bin/sudo', '-u', 'agentporter-dev', '--',
                    str(RELEASE / 'venv/bin/python'), '-I', '-c', SERVICE_CODE], check=True)


if __name__ == '__main__':
    main()
