#!/usr/bin/python3
"""Pinned candidate-only diagnosis. Never installs, stops, switches or dispatches.

The fixed root bootstrap reads admitted metadata and runs immutable v9 code as
service UID in disposable private config/state. No real gateway key is copied.
"""
import os
import subprocess

BOOTSTRAP = r'''


import errno,fcntl,grp,hashlib,json,os,pwd,re,stat,subprocess,sys
from pathlib import Path
ACCOUNT='agentporter-dev'
INSTALL='/opt/agentporter-development'
BASE_RELEASE=INSTALL+'/versions/20261020T223443.649130Z'
RELEASE=INSTALL+'/versions/20261021T011116.967219Z'
RUNTIME_SHA256='8ed4c5b2616577fc67c4e6af97dc47f352badbe4294b8af11dd061ecd0ddea6e'
SOURCE_PINS={'development.py':'6b09a3a870f6b7c7ab5859397353a59389864ea266d35f7555dafc4a76958be3','broker.py':'7e7619504a38b895974f88a3a15e2f134ede85872162b94ddc9744bc976be32f'}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
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

DIAGNOSTIC = r"""

import contextlib,ctypes,hashlib,io,json,os,sys,tempfile,time,traceback
from pathlib import Path
REPORT={'diagnostic':'candidate_v9_only','live_config_changed':False,'passes':[]}
PREFIXES=('separate development worker authentication unavailable','separate development worker credentials unavailable','development worker credentials are shared','worker executable and credentials must be outside registered development workspaces','Codex code-mode helper must be a bundled native executable','Codex code-mode helper must be installed beside the matching Codex executable','bundled Codex code-mode helper is not configured','worker file must be an absolute, non-symlink path','worker file is not regular','runtime_mounts must be a list of installed code mounts','unsupported development credential destination','Development workspace allowlist requires unique canonical directories','Explicit development workspace allowlist is required','Malformed development workspace allowlist','development runtime configuration unavailable','development gateway must run as configured account','worker file requires trusted ownership/mode','worker credential requires private ownership/mode','Shared tool digest mismatch','Shared package digest mismatch','Shared package symlink escapes or changed','Mutable shared package resource','Shared tools must be root-owned and immutable','Unlisted shared toolkit resource','Unlisted shared package','Tool manifest must be trusted and bounded','Tool manifest changed during validation','Shared tool release changed during validation','unsupported confined OpenCode permission schema version','confined worker probe timed out','confined worker probe exceeded output limit','live OS confinement probe failed','confined bundled Codex code-mode helper probe failed','provider environment credentials require a separately provisioned file profile','Codex code-mode helper requires trusted executable ownership/mode','development executable is not configured','development worker executable unavailable','Failed to load config file','Failed to parse','HTTPS operator policy has untrusted ancestor directory','HTTPS operator config directory must be owner-owned, not group/world-writable')
MARKERS={'permission denied':'permission_denied','operation not permitted':'operation_not_permitted','read-only file system':'read_only_filesystem','no such file or directory':'missing_path','timed out':'timeout','unshare':'namespace_unshare','bwrap:':'bubblewrap_error','executable probe failed':'worker_cli_probe_failed','code-mode helper':'codex_helper','credential':'credential_guard','allowlist':'workspace_allowlist_guard','model':'model_route_guard'}
def reason(text):
    return {'classification':next((prefix for prefix in PREFIXES if text.startswith(prefix)),'unclassified_failure'),'markers':[label for marker,label in MARKERS.items() if marker in text.lower()]}
def error_summary(error):
    frames=[{'file':Path(frame.filename).name[:80],'function':frame.name[:80],'line':frame.lineno} for frame in traceback.extract_tb(error.__traceback__)[-8:]]
    return {'exception':type(error).__name__,'error':reason(str(error)),'frames':frames}
def nnp():
    return next(int(line.split(':',1)[1].strip()) for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('NoNewPrivs:'))
def copy_metadata(source,target):
    import stat
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,994) or info.st_mode&0o022 or info.st_size>1024**2:raise PermissionError('Untrusted diagnostic metadata')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(1024**2+1)
        if len(data)!=info.st_size:raise ValueError('Metadata read changed')
        target.write_bytes(data);target.chmod(0o600)
    finally:os.close(fd)
def run_pass(runtime_bytes,context):
    result={'context':context,'no_new_privs':nnp(),'phases':[]}
    with tempfile.TemporaryDirectory(prefix='v9-diagnostic-',dir='/var/lib/agentporter-dev/state') as temporary:
        root=Path(temporary);config=root/'config';config.mkdir(mode=0o700)
        for name in ('config.yaml','workspaces.yaml','agents.yaml','action-policy.yaml','public-https.yaml'):
            try:copy_metadata(Path('/var/lib/agentporter-dev/config')/name,config/name)
            except FileNotFoundError:continue
        (config/'development-runtime.yaml').write_bytes(runtime_bytes)
        (config/'development-runtime.yaml').chmod(0o600)
        runtime=json.loads(runtime_bytes)
        roots=[]
        for row in runtime['allowed_workspace_roots']:
            path=Path(row['path'])
            try:roots.append({'path':str(path),'is_directory':path.is_dir(),'canonical':path.resolve(strict=True)==path,'read_search':os.access(path,os.R_OK|os.X_OK)})
            except Exception as error:roots.append({'path':str(path),'failure':error_summary(error)})
        result['roots']=roots
        try:
            from agentporter.config import Config
            from agentporter.server import create_asgi_app
            start=time.monotonic()
            app=create_asgi_app(Config(config_dir=config,state_dir=root/'state',cache_dir=root/'cache'))
            result['phases'].append({'phase':'app_initialization','ok':True,'seconds':round(time.monotonic()-start,3)})
        except Exception as error:
            result['phases'].append({'phase':'app_initialization','ok':False,'failure':error_summary(error)})
            return result
        try:
            start=time.monotonic();rows=app.app.state.tools['list_agents']()
            summary=[]
            for row in rows:
                summary.append({'agent':row.get('agent'),'available':bool(row.get('available')),'delegatable':bool(row.get('delegatable')),'confinement_status':row.get('confinement_status'),'reason':reason(str(row.get('availability_reason','')))})
            result['phases'].append({'phase':'seven_worker_inventory','ok':len(rows)==7 and all(row.get('available') and row.get('delegatable') for row in rows),'seconds':round(time.monotonic()-start,3),'agents':summary})
        except Exception as error:result['phases'].append({'phase':'seven_worker_inventory','ok':False,'failure':error_summary(error)})
    return result
try:
    assert os.getuid()==994 and os.geteuid()==994
    os.umask(0o077)
    runtime_bytes=sys.stdin.buffer.read(1024**2+1)
    assert len(runtime_bytes)<=1024**2 and hashlib.sha256(runtime_bytes).hexdigest()=='8ed4c5b2616577fc67c4e6af97dc47f352badbe4294b8af11dd061ecd0ddea6e'
    with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
        initial=nnp();REPORT['passes'].append(run_pass(runtime_bytes,'initial_runuser'))
        if initial==0:
            libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NoNewPrivileges setting failed')
            REPORT['passes'].append(run_pass(runtime_bytes,'matching_systemd_nnp'))
except Exception as error:REPORT['failure']=error_summary(error)
print(json.dumps(REPORT,sort_keys=True),flush=True)
"""

def candidate_runtime(base_fd):
    matches=[]
    for name in os.listdir(base_fd):
        if not re.fullmatch(r'\.candidate-[0-9a-f]{32}',name):continue
        fd=trusted_directory(INSTALL+'/'+name)
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700:raise PermissionError('Untrusted evidence directory')
            try:record=json.loads(read_owned_file(fd,'rollback.json',0,0o600,16384))
            except FileNotFoundError:continue
            if record!={'release':BASE_RELEASE,'candidate':Path(RELEASE).name}:continue
            data=read_owned_file(fd,'runtime.json',0,0o444,1024**2)
            if hashlib.sha256(data).hexdigest()!=RUNTIME_SHA256:raise PermissionError('Candidate runtime pin mismatch')
            matches.append(data)
        finally:os.close(fd)
    if len(matches)!=1:raise PermissionError('Expected exactly one matching candidate runtime evidence')
    return matches[0]

def main():
    phase='identity'
    base=None
    try:
        if os.geteuid()!=0 or not sys.flags.isolated:raise PermissionError('Pinned isolated root bootstrap required')
        account=private_account()
        if (account.pw_uid,account.pw_gid)!=(994,981):raise PermissionError('Unexpected service identity')
        phase='installed_candidate'
        interpreter=interpreter_for(RELEASE)
        code=trusted_directory(Path(RELEASE)/'src/agentporter/agents')
        try:
            for name,expected in SOURCE_PINS.items():
                if hashlib.sha256(read_owned_file(code,name,0,0o444,1024**2)).hexdigest()!=expected:raise PermissionError('Installed source pin mismatch')
        finally:os.close(code)
        base=trusted_directory(INSTALL)
        fcntl.flock(base,fcntl.LOCK_SH|fcntl.LOCK_NB)
        if os.readlink('current',dir_fd=base)!=BASE_RELEASE:raise PermissionError('Expected unchanged live v8 release')
        phase='candidate_runtime'
        runtime=candidate_runtime(base)
        phase='service_uid_diagnostic'
        command=['/usr/sbin/runuser','-u',ACCOUNT,'--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','HOME=/var/lib/agentporter-dev/home','PYTHONDONTWRITEBYTECODE=1','AGENTPORTER_API_KEY=DIAGNOSTIC_PLACEHOLDER_NO_SERVER',interpreter,'-I','-B','-c',DIAGNOSTIC]
        result=subprocess.run(command,check=False,input=runtime.decode(),env=ENV,cwd='/var/lib/agentporter-dev/home',stdin=None,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=420)
        if len(result.stdout)>128*1024:raise ValueError('Diagnostic output exceeded safe bound')
        report=json.loads(result.stdout)
        if not isinstance(report,dict) or set(report)-{'diagnostic','live_config_changed','passes','failure'} or report.get('diagnostic')!='candidate_v9_only' or report.get('live_config_changed') is not False:raise ValueError('Unexpected diagnostic report schema')
        if os.readlink('current',dir_fd=base)!=BASE_RELEASE:raise PermissionError('Live release changed during diagnostic')
        print(json.dumps({'diagnostic_child_exit':result.returncode,'report':report}),flush=True)
        return 0 if result.returncode==0 else 2
    except Exception as error:
        print(json.dumps({'diagnostic':'failed','phase':phase,'exception':type(error).__name__}),flush=True)
        return 2
    finally:
        if base is not None:os.close(base)

if __name__=='__main__':sys.exit(main())
'''


def main():
    if os.geteuid()==0:
        raise SystemExit('Run this pinned diagnostic launcher as operator')
    result=subprocess.run(['/usr/bin/sudo','/usr/bin/python3','-I','-B','-c',BOOTSTRAP],check=False)
    if result.returncode:
        print('Candidate diagnosis did not complete; live release was not changed.')
    return result.returncode

if __name__=='__main__':raise SystemExit(main())
