#!/usr/bin/python3
"""Pinned v9-only activation with service-UID acceptance and exact-pair rollback.

Run as operator. Root executes only fixed stdlib code and the unchanged immutable
installed helper; the mutable candidate preparation script is never privileged.
"""
import os
import subprocess

BOOTSTRAP = r'''

import errno,fcntl,grp,hashlib,json,os,pwd,re,sqlite3,stat,subprocess,sys,time,urllib.request
from pathlib import Path
DATA='/var/lib/agentporter-dev'
INSTALL='/opt/agentporter-development'
ACCOUNT='agentporter-dev'
UNIT='agentporter-development.service'
BASE_RELEASE='/opt/agentporter-development/versions/20261020T223443.649130Z'
VERSION='20261021T011116.967219Z'
RELEASE=INSTALL+'/versions/'+VERSION
ARTIFACT='/tmp/agentporter-development-candidate-v9.tgz'
ARCHIVE_SHA256='537a7645c38626b65a10b820570d7b984ba98ec6cef28045fd724d0e2abdef2f'
TRUSTED='/usr/local/libexec/agentporter/install-development-artifact.py'
HELPER_SHA256='84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
JOBS_PROBE=r"""
import json,os,sqlite3
assert os.getuid()==994 and os.geteuid()==994
connection=sqlite3.connect('file:/var/lib/agentporter-dev/state/jobs.db?mode=ro',uri=True,timeout=2)
connection.execute('PRAGMA query_only=ON')
try:
    columns=('job_id','agent','workspace_id','status','created_at')
    rows=connection.execute('SELECT job_id,agent,workspace_id,status,created_at FROM jobs WHERE agent=? AND created_at>=? ORDER BY created_at,job_id LIMIT 1001',('jax',1792544190)).fetchall()
    assert len(rows)<=1000,'Too many pending-acceptance metadata rows'
    print(json.dumps([dict(zip(columns,row)) for row in rows]))
finally:
    connection.close()
"""
STARTUP_PROBE=r"""
import json,os
from pathlib import Path
assert os.getuid()==994 and os.geteuid()==994
from agentporter.config import Config
from agentporter.server import create_asgi_app
p=Path('/var/lib/agentporter-dev/config/secrets.env')
assert p.is_file() and not p.is_symlink(),'Existing private gateway key required'
app=create_asgi_app(Config(config_dir=Path('/var/lib/agentporter-dev/config'),state_dir=Path('/var/lib/agentporter-dev/state'),cache_dir=Path('/var/lib/agentporter-dev/cache')))
rows=app.state.tools['list_agents']()
expected={'jax','liz','prof','phil','wei','ming','argie'}
summary=[{'agent':row.get('agent'),'available':bool(row.get('available')),'delegatable':bool(row.get('delegatable')),'confinement_status':row.get('confinement_status')} for row in rows]
print(json.dumps({'inventory':summary}),flush=True)
assert len(rows)==7 and {row.get('agent') for row in rows}==expected
assert all(row.get('available') and row.get('delegatable') and row.get('confinement_status')=='verified_development_bwrap' for row in rows),'Seven confined workers must pass before restart'
"""
def trusted_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted root directory')
        for component in Path(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Untrusted root-owned ancestor')
        return fd
    except BaseException:
        os.close(fd)
        raise

def private_account():
    account = pwd.getpwnam(ACCOUNT)
    group = grp.getgrnam(ACCOUNT)
    if (account.pw_uid in (0, pwd.getpwnam('operator').pw_uid) or group.gr_gid == 0
            or account.pw_gid != group.gr_gid
            or set(group.gr_mem) - {ACCOUNT}
            or {row.pw_name for row in pwd.getpwall() if row.pw_gid == group.gr_gid} != {ACCOUNT}
            or set(os.getgrouplist(ACCOUNT, account.pw_gid)) != {account.pw_gid}):
        raise PermissionError('A7Dev service group is not exclusive and private')
    return account

def existing_private_key(data_fd, account):
    config = os.open('config', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=data_fd)
    try:
        info = os.fstat(config)
        if info.st_uid != account.pw_uid or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Unexpected private A7Dev config directory')
        key = os.open('secrets.env', os.O_PATH | os.O_NOFOLLOW, dir_fd=config)
        try:
            info = os.fstat(key)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != account.pw_uid
                    or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o600):
                raise PermissionError('Existing private A7Dev gateway key metadata required')
        finally:
            os.close(key)
    finally:
        os.close(config)

def healthy():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 30
    consecutive = 0
    previous = None
    while time.monotonic() < deadline:
        try:
            with opener.open('http://127.0.0.1:8876/health', timeout=2) as response:
                body = response.read(1025)
                valid = response.status == 200 and len(body) <= 1024 and json.loads(body) == {'status':'healthy'}
            result = subprocess.run(['/usr/bin/systemctl','show',UNIT,
                                     '--property=ActiveState,MainPID,NRestarts'],
                                    check=True, env=ENV, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, timeout=5)
            state = dict(line.split('=', 1) for line in result.stdout.splitlines())
            snapshot = (int(state['MainPID']), int(state['NRestarts']))
            active = state['ActiveState'] == 'active' and snapshot[0] > 0 and snapshot[1] >= 0
            consecutive = (consecutive + 1 if snapshot == previous else 1) if valid and active else 0
            previous = snapshot if valid and active else None
            if consecutive >= 3:
                return
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            consecutive = 0
            previous = None
        time.sleep(1)
    raise RuntimeError('A7Dev did not remain active and healthy within the bounded check')

def read_owned_file(parent,name,uid,mode,limit):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or stat.S_IMODE(before.st_mode)!=mode or before.st_size>limit:
            raise PermissionError('Untrusted bounded private metadata file')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(limit+1)
        after=os.fstat(fd)
        if len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise PermissionError('Private metadata changed while reading')
        return data
    finally:os.close(fd)

def trusted_helper():
    parent=trusted_directory('/usr/local/libexec/agentporter')
    try:data=read_owned_file(parent,'install-development-artifact.py',0,0o555,1024**2)
    finally:os.close(parent)
    if hashlib.sha256(data).hexdigest()!=HELPER_SHA256:raise PermissionError('Installed helper digest mismatch')

def archive_digest():
    fd=os.open(ARTIFACT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=pwd.getpwnam('operator').pw_uid or info.st_mode&0o022 or info.st_size>8*1024**3:raise PermissionError('Unsafe v9 archive')
        with os.fdopen(fd,'rb',closefd=False) as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=ARCHIVE_SHA256:raise PermissionError('V9 archive digest mismatch')
    finally:os.close(fd)

def interpreter_for(release):
    interpreter=Path(release)/'venv/bin/python'
    resolved=interpreter.resolve(strict=True)
    if not resolved.is_relative_to(Path(release)):raise PermissionError('Installed interpreter escapes release')
    for path in (Path(release),interpreter.parent,resolved.parent,Path(release)/'src'):
        fd=trusted_directory(path)
        try:
            if os.fstat(fd).st_mode&0o222:raise PermissionError('Release code directory is mutable')
        finally:os.close(fd)
    info=resolved.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o222 or not info.st_mode&0o111:raise PermissionError('Untrusted immutable interpreter')
    return str(interpreter)

def service_probe(interpreter,code,timeout):
    result=subprocess.run(['/usr/sbin/runuser','-u',ACCOUNT,'--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','HOME=/var/lib/agentporter-dev/home','PYTHONDONTWRITEBYTECODE=1',interpreter,'-I','-B','-c',code],check=True,env=ENV,cwd=DATA+'/home',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=timeout)
    if len(result.stdout)>1024**2:raise RuntimeError('Service preflight output exceeded bound')
    return json.loads(result.stdout)

def job_snapshot(phase):
    rows=service_probe('/usr/bin/python3',JOBS_PROBE,15)
    columns={'job_id','agent','workspace_id','status','created_at'}
    if not isinstance(rows,list) or len(rows)>1000:raise ValueError('Invalid jobs metadata snapshot')
    for row in rows:
        if not isinstance(row,dict) or set(row)!=columns or row['agent']!='jax' or not re.fullmatch(r'job_[0-9a-f]{24}',row['job_id']) or not isinstance(row['workspace_id'],str) or len(row['workspace_id'])>128 or not isinstance(row['status'],str) or len(row['status'])>64 or not isinstance(row['created_at'],(int,float)) or row['created_at']<1792544190:
            raise ValueError('Invalid jobs metadata fields')
    print(json.dumps({'pending_jax_phase':phase,'jobs':rows}),flush=True)

def runtime_digest(data_fd,account):
    fd=os.open('config',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=data_fd)
    try:return hashlib.sha256(read_owned_file(fd,'development-runtime.yaml',account.pw_uid,0o600,1024**2)).hexdigest()
    finally:os.close(fd)

def run_helper(arguments):
    trusted_helper()
    result=subprocess.run(['/usr/bin/python3','-I','-B',TRUSTED,*arguments],check=True,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=300)
    if len(result.stdout)>16384:raise RuntimeError('Unexpected helper output size')
    return json.loads(result.stdout)

def find_evidence(base_fd,before,old_runtime_digest):
    matches=[]
    for name in sorted(set(os.listdir(base_fd))-before):
        if not re.fullmatch(r'\.candidate-[0-9a-f]{32}',name):continue
        fd=trusted_directory(INSTALL+'/'+name)
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700:raise PermissionError('Rollback directory must be private')
            try:record=json.loads(read_owned_file(fd,'rollback.json',0,0o600,16384))
            except FileNotFoundError:continue
            if record!={'release':BASE_RELEASE,'candidate':VERSION}:continue
            previous=read_owned_file(fd,'previous-runtime.yaml',0,0o600,1024**2)
            if hashlib.sha256(previous).hexdigest()!=old_runtime_digest:raise PermissionError('Rollback runtime does not match exact previous pair')
            matches.append(name)
        finally:os.close(fd)
    if len(matches)>1:raise PermissionError('Ambiguous newly-created rollback evidence')
    return matches[0] if matches else None

def control(operation):
    subprocess.run(['/usr/bin/systemctl',operation,UNIT],check=True,env=ENV,stdin=subprocess.DEVNULL,timeout=30)

def stop_after_failure():
    try:control('stop')
    except (OSError,subprocess.SubprocessError):print('Development service stop could not be confirmed.',flush=True)

def main():
    if os.geteuid()!=0 or not sys.flags.isolated:raise PermissionError('Use the pinned isolated root bootstrap')
    if not re.fullmatch('[0-9a-f]{64}',ARCHIVE_SHA256) or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z',VERSION):raise ValueError('Candidate pins not finalized')
    os.umask(0o077)
    account=private_account()
    if (account.pw_uid,account.pw_gid)!=(994,981):raise PermissionError('Unexpected service identity')
    trusted_helper(); archive_digest(); interpreter_for(BASE_RELEASE)
    data_fd=trusted_directory(DATA); base_fd=trusted_directory(INSTALL)
    stopped=False; before=set(); old_digest=None
    try:
        # Serialize reviewed activations without creating any lockfile.
        fcntl.flock(base_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        data_info=os.fstat(data_fd)
        if data_info.st_uid!=0 or data_info.st_gid!=981 or stat.S_IMODE(data_info.st_mode)!=0o750:raise PermissionError('Private A7Dev data must already be root:service mode0750')
        try:os.getxattr(data_fd,'system.posix_acl_access')
        except OSError as error:
            if error.errno not in (errno.ENODATA,errno.ENOTSUP,errno.EOPNOTSUPP):raise
        else:raise PermissionError('Unexpected A7Dev access ACL')
        existing_private_key(data_fd,account)
        if os.readlink('current',dir_fd=base_fd)!=BASE_RELEASE:raise PermissionError('Current release is not admitted v8')
        before=set(os.listdir(base_fd)); old_digest=runtime_digest(data_fd,account)
        job_snapshot('before_stop')
        control('stop'); stopped=True
        job_snapshot('after_stop')
        if runtime_digest(data_fd,account)!=old_digest:raise PermissionError('Runtime changed during development stop')
        result=run_helper(['--artifact',ARTIFACT,'--sha256',ARCHIVE_SHA256])
        evidence=find_evidence(base_fd,before,old_digest)
        if result.get('installed')!=RELEASE or result.get('service_restarted') is not False or evidence is None or result.get('rollback_evidence')!=INSTALL+'/'+evidence:raise PermissionError('Installer result differs from exact rollback pair')
        if os.readlink('current',dir_fd=base_fd)!=RELEASE:raise PermissionError('Installed current release changed')
        inventory=service_probe(interpreter_for(RELEASE),STARTUP_PROBE,300)
        rows=inventory.get('inventory') if isinstance(inventory,dict) else None
        if not isinstance(rows,list) or len(rows)!=7 or {row.get('agent') for row in rows}!={'jax','liz','prof','phil','wei','ming','argie'} or not all(row.get('available') is True and row.get('delegatable') is True and row.get('confinement_status')=='verified_development_bwrap' for row in rows):raise PermissionError('Seven real confined inventory checks did not pass')
        print(json.dumps({'v9_confined_inventory':rows,'rollback_evidence':evidence}),flush=True)
        control('restart'); healthy()
    except BaseException:
        if stopped:
            stop_after_failure()
            try:
                evidence=find_evidence(base_fd,before,old_digest)
                current=os.readlink('current',dir_fd=base_fd)
                if current==RELEASE and evidence:
                    result=run_helper(['--rollback',evidence,'--activate'])
                    if result.get('rolled_back')!=BASE_RELEASE or runtime_digest(data_fd,account)!=old_digest or os.readlink('current',dir_fd=base_fd)!=BASE_RELEASE:raise PermissionError('Rollback did not restore exact previous pair')
                    healthy()
                    print(json.dumps({'v9_acceptance':'failed','rollback':'exact prior pair restored; health verified','evidence':evidence}),flush=True)
                elif current==BASE_RELEASE and runtime_digest(data_fd,account)==old_digest:
                    control('restart'); healthy()
                    print('V9 install did not switch the previous pair; prior development service restored and healthy.',flush=True)
                else:
                    raise PermissionError('Current/runtime pair cannot be safely rolled back with the trusted helper')
            except BaseException:
                stop_after_failure()
                print('V9 acceptance failed; automatic restoration could not be verified. Development stop requested; inspect newly-created rollback evidence before any restart.',flush=True)
                raise
        raise
    finally:
        os.close(data_fd); os.close(base_fd)
    print('Reviewed A7Dev v9 activated; seven confined workers verified; stable development health. Production unchanged.',flush=True)

if __name__=='__main__':main()
'''


def main():
    if os.geteuid()==0:
        raise SystemExit('Run this pinned launcher as operator')
    subprocess.run(['/usr/bin/sudo','/usr/bin/python3','-I','-B','-c',BOOTSTRAP],check=True)

if __name__=='__main__':main()
