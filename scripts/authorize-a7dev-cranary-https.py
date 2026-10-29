#!/usr/bin/python3
"""Human-run, pinned A7Dev policy installation; never restarts a service.

Default is a read-only proposal. --apply-policy requires yeli's local terminal
and sudo approval. Root executes only the fixed stdlib bootstrap below, never
this mutable repository file or package code as root. Existing differing policy
is preserved and rejected. A separate, explicitly approved restart is required.
"""
import argparse
import hashlib
import os
import pwd
import subprocess

POLICY = '''version: 1
workspaces:
  cranary:
    hosts:
      - api.github.com
      - cran.r-project.org
      - cran-archive.r-project.org
      - bioconductor.org
    methods: [GET, HEAD]
    max_response_bytes: 262144
    timeout_seconds: 15
'''

BOOTSTRAP = r'''
import hashlib,json,os,pwd,secrets,stat,subprocess
from pathlib import Path
ACCOUNT='agentporter-dev'
CONFIG='/var/lib/agentporter-dev/config'
RELEASE='/opt/agentporter-development/versions/20261021T132836.936455Z'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
POLICY=__POLICY_BYTES__
SOURCE_PINS={
 'src/agentporter/scoped_https.py':'2c51714f5e12deb92cc8536df1cc7aa36a0baef08b4529505a3ca27253e8ee56',
 'src/agentporter/scoped_https_worker.py':'d02745df9e18f0e412c12a4b6b85290aefa98e33f62fadcb70d01decca7886bb',
 'src/agentporter/tools/execution.py':'10f7d529c9901e195430f3f37803bf7210389404bd297cdf08eff5dedfc49b9c',
}
VALIDATE=r"""
import json,os
from agentporter.scoped_https import ScopedPublicHTTPSPolicy
assert os.getuid()==os.geteuid()!=0
p=ScopedPublicHTTPSPolicy('/var/lib/agentporter-dev/config',workspace_roots=['/home/yeli/repos/cranary','/home/yeli/agent-work/agentporter-dev'])
assert set(p.scopes)=={'cranary'}
s=p.scopes['cranary']
assert s['hosts']==frozenset({'api.github.com','cran.r-project.org','cran-archive.r-project.org','bioconductor.org'})
assert s['methods']==frozenset({'GET','HEAD'})
assert s['max_response_bytes']==262144 and s['timeout_seconds']==15
print(json.dumps({'policy_validated_as_service_uid':os.getuid(),'network_requests':0}))
"""

def root_directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:]:
            info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode&0o022:
                raise PermissionError('Untrusted root-owned ancestor')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        info=os.fstat(fd)
        if info.st_uid!=0 or info.st_mode&0o022:
            raise PermissionError('Untrusted root-owned directory')
        return fd
    except BaseException:
        os.close(fd);raise

def existing_policy(config_fd,uid,gid):
    try:
        fd=os.open('public-https.yaml',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=config_fd)
    except FileNotFoundError:
        return None
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=len(POLICY)):
            raise PermissionError('Existing policy metadata differs; preserve it for operator review')
        if os.read(fd,len(POLICY)+1)!=POLICY:
            raise PermissionError('Existing policy content differs; no overwrite authorized')
        return (info.st_dev,info.st_ino)
    finally:
        os.close(fd)

def install_policy(config_fd,uid,gid):
    previous=existing_policy(config_fd,uid,gid)
    if previous is not None:
        return False,previous
    name='.public-https-'+secrets.token_hex(16)
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=config_fd)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(POLICY);stream.flush();os.fsync(fd)
        os.fchown(fd,uid,gid);os.fchmod(fd,0o600)
        os.fsync(fd)
        info=os.fstat(fd)
        # Link into a new name only: a racing policy is never overwritten.
        os.link(name,'public-https.yaml',src_dir_fd=config_fd,dst_dir_fd=config_fd,follow_symlinks=False)
        os.fsync(config_fd)
        return True,(info.st_dev,info.st_ino)
    finally:
        os.close(fd)
        os.unlink(name,dir_fd=config_fd)

def main():
    if os.geteuid()!=0:
        raise PermissionError('Operator sudo authorization required')
    os.umask(0o077)
    account=pwd.getpwnam(ACCOUNT)
    if account.pw_uid in (0,pwd.getpwnam('yeli').pw_uid):
        raise PermissionError('Separate development service UID required')
    install=root_directory('/opt/agentporter-development')
    try:
        if os.readlink('current',dir_fd=install)!=RELEASE:
            raise PermissionError('A7Dev release changed; review the proposal again')
    finally:os.close(install)
    for relative,expected in SOURCE_PINS.items():
        path=Path(RELEASE)/relative
        parent=root_directory(str(path.parent))
        try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        finally:os.close(parent)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o222 or info.st_size>1024**2:
                raise PermissionError('Installed HTTPS implementation must be immutable root-owned code')
            if hashlib.sha256(os.read(fd,1024**2+1)).hexdigest()!=expected:
                raise PermissionError('Installed HTTPS implementation changed')
        finally:os.close(fd)
    state=subprocess.check_output(['/usr/bin/systemctl','show','agentporter-development.service',
        '--property=ActiveState,MainPID,User,Group'],env=ENV,text=True,timeout=10)
    values=dict(line.split('=',1) for line in state.splitlines())
    if values.get('ActiveState')!='active' or values.get('User')!=ACCOUNT or values.get('Group')!=ACCOUNT:
        raise PermissionError('Unexpected development service state or identity')
    pid=int(values['MainPID'])
    if pid<=0:raise PermissionError('Development service PID missing')
    command=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
    index=command.index(b'--config-dir')
    if command[index+1]!=CONFIG.encode():
        raise PermissionError('Development service uses a different configuration')
    data=root_directory('/var/lib/agentporter-dev')
    try:
        info=os.fstat(data)
        if info.st_gid!=account.pw_gid or stat.S_IMODE(info.st_mode)!=0o750:
            raise PermissionError('Unexpected development data directory metadata')
        config=os.open('config',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=data)
    finally:os.close(data)
    try:
        info=os.fstat(config)
        if info.st_uid!=account.pw_uid or info.st_gid!=account.pw_gid or stat.S_IMODE(info.st_mode)!=0o700:
            raise PermissionError('Unexpected private development config metadata')
        created,identity=install_policy(config,account.pw_uid,account.pw_gid)
        try:
            checked=subprocess.run(['/usr/sbin/runuser','-u',ACCOUNT,'--',RELEASE+'/venv/bin/python',
                '-I','-c',VALIDATE],check=True,env=ENV,stdin=subprocess.DEVNULL,
                capture_output=True,text=True,timeout=20)
            print(checked.stdout.strip())
        except BaseException:
            if created and existing_policy(config,account.pw_uid,account.pw_gid)==identity:
                os.unlink('public-https.yaml',dir_fd=config);os.fsync(config)
            raise
    finally:os.close(config)
    print(json.dumps({'policy_path':CONFIG+'/public-https.yaml','owner':ACCOUNT,'mode':'0600',
        'sha256':hashlib.sha256(POLICY).hexdigest(),'created':created,
        'service_restarted':False,'restart_required_to_load':True,'production_changed':False}))

if __name__=='__main__':main()
'''.replace('__POLICY_BYTES__', repr(POLICY.encode('utf-8')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-policy', action='store_true')
    args = parser.parse_args()
    print('A7Dev proposal: /var/lib/agentporter-dev/config/public-https.yaml; owner agentporter-dev; mode 0600', flush=True)
    print('Policy SHA256: ' + hashlib.sha256(POLICY.encode()).hexdigest(), flush=True)
    if not args.apply_policy:
        print(POLICY, end='')
        print('Proposal only. No policy installed; no service restarted.')
        return
    if os.getuid() != pwd.getpwnam('yeli').pw_uid or not os.isatty(0):
        raise PermissionError('Apply only as yeli in an independently authorized local terminal')
    subprocess.run(['/usr/bin/sudo', '--', '/usr/bin/python3', '-I', '-c', BOOTSTRAP], check=True)


if __name__ == '__main__':
    main()
