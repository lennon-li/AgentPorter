#!/usr/bin/python3
"""Pinned BCC production cutover; explicit apply, durable backup, owner rollback."""
import argparse,fcntl,hashlib,json,os,secrets,stat,subprocess,sys,tempfile,time,types,urllib.request,urllib.error
from pathlib import Path
import yaml

ROOT=Path('/usr/local/libexec/agentporter-bcc-production')
STATE=Path('/var/lib/agentporter-bcc-production-operator/20261029-release19')
RELEASE=Path('/opt/agentporter-bcc/releases/bcc-stage-20261029-19')
PYTHON=RELEASE/'venv/bin/python'
FINGERPRINT='96812fbaf766cfb4a121f47efd61091fdc86b47895fc9416abcde5f00ff6852c'
GW=Path('/home/yeli/.config/agentporter')
WD=Path('/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03')
WC=WD/'config'
OWNER=2056259175; GROUP=2056259276; WORKER=997
GW_UNIT=Path('/etc/systemd/system/agentporter-bcc-gateway.service')
WORKER_UNIT=Path('/etc/systemd/system/agentporter-bcc-worker.service')
VIEWS_UNIT=Path('/etc/systemd/system/agentporter-bcc-project-views.service')
VIEWS_SCRIPT=ROOT/'project-views.py'
TUNNEL_DROP=Path('/home/yeli/.config/systemd/user/agentporter-openai-tunnel.service.d/production-gateway.conf')
ENV={'PATH':'/usr/bin:/bin','HOME':'/root','LANG':'C.UTF-8'}
USER_ENV={**ENV,'HOME':'/home/yeli','XDG_RUNTIME_DIR':f'/run/user/{OWNER}',
          'DBUS_SESSION_BUS_ADDRESS':f'unix:path=/run/user/{OWNER}/bus'}
DOCS=('config.yaml','workspaces.yaml','action-policy.yaml','public-client-policy.yaml',
      'gateway-job-resources.yaml','delegation-upstream.yaml','delegation-relay-scope.yaml',
      'delegation-relay-write-scope.yaml','development-runtime.yaml')


def require(value,message):
    if not value: raise PermissionError(message)


def command(argv,*,user=None,check=True,input=None):
    kwargs={} if user is None else {'user':user,'group':GROUP if user==OWNER else WORKER,'extra_groups':()}
    result=subprocess.run(argv,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=USER_ENV if user==OWNER else ENV,cwd='/',timeout=180,**kwargs)
    if check: require(result.returncode==0,'Command failed: '+str(argv[0])+' '+str(argv[1:3]))
    return result


def system(*args): return command(['/usr/bin/systemctl',*args])
def user_system(*args): return command(['/usr/bin/systemctl','--user',*args],user=OWNER)
def sha(data): return hashlib.sha256(data).hexdigest()


def trusted_parents(path,owners):
    for item in (path,*path.parents):
        info=item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in owners and not info.st_mode&0o022,
                'Untrusted directory: '+str(item))


def read(path,owners=(0,OWNER,WORKER),limit=131072):
    trusted_parents(path.parent,owners)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid in owners
                and not info.st_mode&0o022 and info.st_size<=limit,'Untrusted input: '+str(path))
        data=os.read(fd,limit+1);require(len(data)<=limit,'Input exceeds budget')
        return data,{'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
    finally: os.close(fd)


def atomic(path,data,uid,gid,mode=0o600):
    trusted_parents(path.parent,(0,OWNER,WORKER))
    fd,temporary=tempfile.mkstemp(prefix='.bcc-cutover-',dir=path.parent)
    try:
        os.fchmod(fd,mode);os.fchown(fd,uid,gid)
        with os.fdopen(fd,'wb') as output:
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def save(journal): atomic(STATE/'state.json',json.dumps(journal,sort_keys=True,indent=2).encode(),0,0)


def snapshot(path,journal):
    key=str(path)
    if key in journal['files']: return
    if path.exists() or path.is_symlink():
        data,meta=read(path)
        name=str(len(journal['files']))+'.backup'
        atomic(STATE/name,data,0,0)
        journal['files'][key]={'backup':name,'before_sha256':sha(data),**meta}
    else: journal['files'][key]={'backup':None}
    save(journal)


def replace(path,data,uid,gid,journal,mode=0o600):
    snapshot(path,journal)
    previous=journal['files'][str(path)]
    expected=previous.get('after_sha256',previous.get('before_sha256'))
    current=sha(read(path)[0]) if path.exists() else None
    require(current==expected,'Configuration changed concurrently: '+str(path))
    # Persist intended content before replacement so interrupted writes can be
    # distinguished from concurrent owner edits during rollback.
    previous['after_sha256']=sha(data);save(journal)
    atomic(path,data,uid,gid,mode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise PermissionError('Local verification redirect refused')


def api(port,path,data=None):
    config=GW if port==8765 else WC
    body,_=read(config/'secrets.env')
    keys=[line.split('=',1)[1].strip().strip('"\'') for line in body.decode().splitlines()
          if line.startswith('AGENTPORTER_API_KEY=')]
    require(len(keys)==1 and keys[0],'API key unavailable')
    request=urllib.request.Request(f'http://127.0.0.1:{port}'+path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'X-AgentPorter-Key':keys[0],'Content-Type':'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request,timeout=180) as response:
        return json.loads(response.read(2*1024**2))


def parity(port,unit):
    for attempt in range(90):
        try:
            value=api(port,'/api/v1/server/deploy-info')
            require(value['loaded_fingerprint']==value['disk_fingerprint']==FINGERPRINT
                    and not value['stale'] and str(RELEASE) in value['package_path'], 'Immutable parity mismatch')
            pid=int(system('show',unit,'-p','MainPID','--value').stdout)
            require(value['pid']==pid,'Service PID mismatch')
            return pid
        except (OSError,ValueError,urllib.error.URLError):
            if attempt==89:raise
            time.sleep(.5)


def module(name):
    data,_=read(ROOT/name,(0,),1024**2)
    manifest=json.loads(read(ROOT/'MANIFEST.json',(0,))[0])
    require(sha(data)==manifest[name],'Installed operator component hash mismatch')
    result=types.ModuleType(name);result.__file__=str(ROOT/name)
    exec(compile(data,str(ROOT/name),'exec'),result.__dict__)
    return result


MAIN_GUARD=r'''
import re,sqlite3,sys
database,action,nonce=sys.argv[1:]
assert re.fullmatch('[0-9a-f]{32}',nonce)
names={'bcc_production_maintenance':'jobs','bcc_production_admissions':'job_admissions'}
sql={name:"CREATE TRIGGER "+name+" BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'BCC production maintenance "+nonce+"'); END"
     for name,table in names.items()}
with sqlite3.connect('file:'+database+'?mode=rw',uri=True,timeout=5) as db:
    db.execute('BEGIN IMMEDIATE')
    terminal={'completed','failed','cancelled','timed_out','output_limit_exceeded','interrupted','recovered'}
    assert all(r[0] in terminal for r in db.execute('SELECT status FROM jobs')),'Active jobs'
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_admissions'").fetchone():
        assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0,'Held admissions'
    db.execute('CREATE TABLE IF NOT EXISTS job_admissions (token TEXT PRIMARY KEY, job_id TEXT, owner_pid INTEGER, created_at REAL)')
    rows=dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN (?,?)",tuple(names)))
    if action=='install':
        assert not rows,'Unknown maintenance guard'
        for statement in sql.values():db.execute(statement)
    else:
        assert rows==sql,'Maintenance guard ownership differs'
        for name in names:db.execute('DROP TRIGGER '+name)
'''


def main_guard(action,nonce):
    command(['/usr/bin/python3','-I','-c',MAIN_GUARD,
             '/home/yeli/.local/state/agentporter/jobs.db',action,nonce],user=OWNER)


def guard_count(database,user,names):
    code="import json,sqlite3,sys; d=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); names=json.loads(sys.argv[2]); print(sum(d.execute(\"SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name=?\",(n,)).fetchone()[0] for n in names))"
    return int(command(['/usr/bin/python3','-I','-c',code,str(database),json.dumps(names)],user=user).stdout)


def documents(path):
    out={}
    for name in DOCS:
        file=path/name
        if file.exists():out[name]=yaml.safe_load(read(file)[0])
    return out


def projection_program(paths):
    return ('''import os,stat,subprocess
from pathlib import Path
paths = '''+repr(paths)+'''
for source in paths:
    p=Path(source);info=p.lstat()
    assert p.resolve(strict=True)==p and stat.S_ISDIR(info.st_mode) and info.st_uid==2056259175
    for publication in (False,True):
        root=Path('/var/lib/agentporter-bcc/publication-views' if publication else '/var/lib/agentporter-bcc/projections')
        target=root/f'{info.st_dev:x}-{info.st_ino:x}'
        if target.exists():
            current=target.lstat()
            if current.st_uid==0 and stat.S_ISDIR(current.st_mode) and not target.is_mount() and not list(target.iterdir()):
                target.rmdir()  # Empty operator-owned mountpoint left after reboot.
        args=['/usr/bin/python3','-I','-S','''+repr(str(ROOT/'projection.py'))+''','--source',source,'--apply']
        if publication:args.append('--publication')
        subprocess.run(args,check=True,timeout=30,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
''').encode()


def rollback(journal,updater):
    require(journal.get('phase')!='rolled_back','Already rolled back')
    # Never overwrite edits made after this operator run.
    for name,record in journal['files'].items():
        path=Path(name)
        current=sha(read(path)[0]) if path.exists() else None
        require(current in {record.get('before_sha256'),record.get('after_sha256')},
                'Rollback conflicts with owner edits: '+name)
    # Do not terminate unrelated work to perform a rollback. Freeze both
    # admissions first; these barriers refuse active jobs or held slots.
    if journal.get('worker_changed') and not journal.get('worker_guard'):
        journal['worker_guard']=True;save(journal);updater.guard('install',journal['nonce'])
    if journal.get('gateway_started') and not journal.get('main_guard'):
        journal['main_guard']=True;save(journal);main_guard('install',journal['nonce'])
    if journal.get('gateway_started'):
        system('stop','agentporter-bcc-gateway.service')
        transactions=Path('/home/yeli/.local/state/agentporter/workspace-transactions')
        require(not list(transactions.glob('*.pending.json')) and not list(transactions.glob('*.git-pending.json')),
                'Gateway has pending workspace recovery; retain maintenance state for owner inspection')
    if journal.get('worker_changed'):
        system('stop','agentporter-bcc-worker.service')
        system('stop','agentporter-bcc-project-views.service')
    if journal.get('gateway_enabled'):
        system('disable','agentporter-bcc-gateway.service')
    for name,record in reversed(list(journal['files'].items())):
        path=Path(name)
        if record['backup'] is None:
            if path.exists():path.unlink()
        else:
            atomic(path,read(STATE/record['backup'],(0,),1024**2)[0],record['uid'],record['gid'],record['mode'])
    system('daemon-reload');user_system('daemon-reload')
    if journal.get('worker_guard'):
        if guard_count(WD/'state/jobs.db',WORKER,['bcc_stage_update_insert','bcc_stage_update_update']):
            updater.guard('remove',journal['nonce'])
        journal['worker_guard']=False
    if journal.get('worker_changed'):system('start','agentporter-bcc-worker.service')
    if journal.get('main_guard'):
        if guard_count(Path('/home/yeli/.local/state/agentporter/jobs.db'),OWNER,['bcc_production_maintenance','bcc_production_admissions']):
            main_guard('remove',journal['nonce'])
        journal['main_guard']=False
    if journal.get('legacy_stopped'):
        user_system('enable','agentporter.service');user_system('start','agentporter.service')
    journal['phase']='rolled_back';save(journal)
    print('PRODUCTION_ROLLED_BACK: saved configuration and legacy gateway restored; tunnel unchanged.',flush=True)


def canary(journal):
    base='/api/v1/workspaces/bcc-production-canary'
    filename='api-'+secrets.token_hex(6)+'.txt'
    api(8765,base+'/files/write',{'path':filename,'content':'Production receipt-free commit canary\n'})
    api(8765,base+'/git/add',{'paths':[filename]})
    commit=api(8765,base+'/git/commit',{'message':'Production receipt-free API commit'})
    require(isinstance(commit,str) and len(commit) in (40,64),'Production commit result invalid')
    try:api(8765,base+'/git/push',{'approval_receipt':'obsolete-receipt'})
    except urllib.error.HTTPError as error:require(error.code==403,'Unexpected push response')
    else:raise PermissionError('Production push unexpectedly allowed')
    for name in journal['projects']:
        result=api(8765,f'/api/v1/workspaces/{name}/exec/run',
            {'argv':['/usr/bin/python3','-c','print("PRODUCTION_WORKSPACE_OK")'],'timeout_seconds':120})
        require(result['exit_code']==0 and 'PRODUCTION_WORKSPACE_OK' in result['stdout'],
                'Workspace execution probe failed: '+name)
        print(json.dumps({'check':'production-workspace','workspace':name,'exit_code':0}),flush=True)
        agents=api(8765,f'/api/v1/workspaces/{name}/agents/list')
        require({row['agent'] for row in agents}=={'jax','liz','prof','phil','wei','ming','argie'},
                'Seven-worker inventory mismatch')
        require(all(row.get('delegatable') and name in row.get('public_writable_dispatch_workspaces',[])
                    for row in agents),'Writable worker scope unavailable: '+name)
    return commit


def apply(updater):
    require(not (STATE/'state.json').exists(),'Existing operator journal: inspect or use --rollback')
    require(system('show','agentporter-bcc-gateway.service','-p','LoadState','--value').stdout.strip()==b'not-found',
            'Unexpected system gateway already installed')
    require(user_system('is-active','agentporter.service').stdout.strip()==b'active','Legacy gateway not active')
    gateway,worker=documents(GW),documents(WC)
    require('public-client-policy.yaml' not in gateway and 'gateway-job-resources.yaml' not in gateway,
            'Gateway already has hardened policies; reconcile explicitly')
    gateway['workspaces.yaml']['workspaces'].setdefault('qman',{'path':'/home/yeli/repos/Qman','writable':True})
    gateway,worker=module('policy.py').prepare(gateway,worker)
    projects=list(gateway['delegation-upstream.yaml']['workspaces'])
    paths=[gateway['workspaces.yaml']['workspaces'][name]['path'] for name in projects]
    for path in paths:
        p=Path(path);require(p.resolve(strict=True)==p and p.stat().st_uid==OWNER,'Project ownership/path mismatch')
    parity(8876,'agentporter-bcc-worker.service')
    journal={'phase':'preparing','nonce':secrets.token_hex(16),'files':{},'projects':projects,
             'worker_guard':False,'main_guard':False,'legacy_stopped':False,'worker_changed':False,
             'gateway_started':False,'gateway_enabled':False,
             'tunnel_pid':int(user_system('show','agentporter-openai-tunnel.service','-p','MainPID','--value').stdout)}
    require(journal['tunnel_pid']>0,'Tunnel not active')
    save(journal)
    try:
        # Provision canary only inside this authorized AgentPorter workspace.
        fixture=Path('/home/yeli/repos/AgentPorter/artifacts/bcc-production-canary-20261029')
        require(not fixture.exists(),'Production canary already exists; inspect before retry')
        # All writes inside the mutable project run as its owner, never root.
        code="from pathlib import Path; import sys; p=Path(sys.argv[1]); p.mkdir(mode=0o755); (p/'initial.txt').write_text('Production canary baseline\\n')"
        command(['/usr/bin/python3','-I','-c',code,str(fixture)],user=OWNER)
        require(fixture.resolve(strict=True)==fixture and fixture.stat().st_uid==OWNER,
                'Canary root identity is invalid')
        git_env={**USER_ENV,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
        for args in (['init','-q','-b','acceptance',str(fixture)],
                     ['-C',str(fixture),'config','user.name','AgentPorter'],
                     ['-C',str(fixture),'config','user.email','agents@agentporter.invalid'],
                     ['-C',str(fixture),'add','initial.txt'],
                     ['-C',str(fixture),'-c','core.hooksPath=/dev/null','commit','-qm','Production canary baseline']):
            r=subprocess.run(['/usr/bin/git',*args],user=OWNER,group=GROUP,extra_groups=(),
                env=git_env,cwd='/',capture_output=True,timeout=20)
            require(r.returncode==0,'Canary initialization failed')
        gateway['workspaces.yaml']['workspaces']['bcc-production-canary']={
            'path':str(fixture),'writable':True,'allow_execute':True,'allow_git':True}
        gateway['public-client-policy.yaml']['workspaces']['bcc-production-canary']={
            'path':str(fixture),'operations':['read','write','exec','git_read','git_write']}
        journal['worker_guard']=True;save(journal);updater.guard('install',journal['nonce'])
        journal['worker_changed']=True;save(journal);system('stop','agentporter-bcc-worker.service')
        replace(VIEWS_SCRIPT,projection_program(paths),0,0,journal,0o500)
        views=b'[Unit]\nDescription=BCC owner-mapped project views\nAfter=network-online.target nss-user-lookup.target\nWants=network-online.target\nBefore=agentporter-bcc-worker.service\n[Service]\nType=oneshot\nExecStart='+str(PYTHON).encode()+b' -B -I '+str(VIEWS_SCRIPT).encode()+b'\nRemainAfterExit=yes\n'
        replace(VIEWS_UNIT,views,0,0,journal,0o644)
        worker_unit=read(WORKER_UNIT,(0,))[0].decode()
        require(str(RELEASE) in worker_unit,'Worker unit is not release 17')
        worker_unit=worker_unit.replace('After=network.target','After=network.target agentporter-bcc-project-views.service\nRequires=agentporter-bcc-project-views.service')
        worker_unit=worker_unit.replace('ProtectHome=yes','ProtectHome=tmpfs\nBindReadOnlyPaths=/home/yeli/repos')
        worker_unit=worker_unit.replace('Restart=no','Restart=on-failure\nRestartSec=5')
        replace(WORKER_UNIT,worker_unit.encode(),0,0,journal,0o644)
        relay=secrets.token_urlsafe(48).encode()+b'\n'
        for config,docs,uid,gid in ((GW,gateway,OWNER,GROUP),(WC,worker,WORKER,WORKER)):
            for name,document in docs.items():
                require(name in DOCS,'Unexpected configuration output')
                replace(config/name,yaml.safe_dump(document,sort_keys=False).encode(),uid,gid,journal)
            replace(config/'delegation-relay.key',relay,uid,gid,journal)
        system('daemon-reload');system('start','agentporter-bcc-project-views.service')
        system('start','agentporter-bcc-worker.service');parity(8876,'agentporter-bcc-worker.service')
        updater.guard('remove',journal['nonce']);journal['worker_guard']=False;save(journal)
        # Exercise real foreign-owner projections before taking down the legacy
        # production gateway. These probes do not call external model providers.
        for name in projects:
            result=api(8876,f'/api/v1/workspaces/{name}/exec/run',{
                'argv':['/usr/bin/python3','-c','print("WORKER_PROJECT_OK")'],'timeout_seconds':120})
            require(result['exit_code']==0 and 'WORKER_PROJECT_OK' in result['stdout'],
                    'Isolated worker project probe failed: '+name)
            print(json.dumps({'check':'isolated-worker-project','workspace':name,'exit_code':0}),flush=True)
        require('agentporter' in projects,'AgentPorter canary parent is not admitted')
        native_code=('import pathlib,subprocess; p=pathlib.Path("/workspace/artifacts/bcc-production-canary-20261029"); '
            '(p/"native.txt").write_text("Isolated native production commit\\n"); '
            'subprocess.run(["git","-C",str(p),"add","native.txt"],check=True); '
            'subprocess.run(["git","-C",str(p),"commit","-qm","Isolated-worker-production-canary"],check=True); '
            'print("NATIVE_PRODUCTION_COMMIT_OK")')
        result=api(8876,'/api/v1/workspaces/agentporter/exec/run',{
            'argv':['/usr/bin/python3','-c',native_code],'timeout_seconds':120})
        require(result['exit_code']==0 and 'NATIVE_PRODUCTION_COMMIT_OK' in result['stdout'],
                'Owner-mapped worker native commit failed')
        print(json.dumps({'check':'isolated-worker-native-commit','exit_code':0}),flush=True)
        journal['main_guard']=True;save(journal);main_guard('install',journal['nonce'])
        journal['legacy_stopped']=True;save(journal);user_system('stop','agentporter.service')
        user_system('disable','agentporter.service')
        if not TUNNEL_DROP.parent.exists():
            command(['/usr/bin/python3','-I','-c',
                     'from pathlib import Path; import sys; Path(sys.argv[1]).mkdir(mode=0o755)',
                     str(TUNNEL_DROP.parent)],user=OWNER)
        trusted_parents(TUNNEL_DROP.parent,(0,OWNER))
        replace(TUNNEL_DROP,b'[Unit]\nAfter=\nAfter=network-online.target\nWants=\nWants=network-online.target\n',OWNER,GROUP,journal)
        user_system('daemon-reload')
        gateway_unit=read(ROOT/'gateway.service',(0,))[0]
        replace(GW_UNIT,gateway_unit,0,0,journal,0o644)
        journal['gateway_started']=True;save(journal)
        system('daemon-reload');system('start','agentporter-bcc-gateway.service')
        pid=parity(8765,'agentporter-bcc-gateway.service')
        main_guard('remove',journal['nonce']);journal['main_guard']=False;save(journal)
        commit=canary(journal)
        require(int(user_system('show','agentporter-openai-tunnel.service','-p','MainPID','--value').stdout)==journal['tunnel_pid'],
                'Tunnel PID changed unexpectedly')
        journal['gateway_enabled']=True;save(journal)
        system('enable','agentporter-bcc-gateway.service')
        require(system('is-enabled','agentporter-bcc-gateway.service').stdout.strip()==b'enabled',
                'System gateway boot enablement failed')
        legacy=command(['/usr/bin/systemctl','--user','is-enabled','agentporter.service'],user=OWNER,check=False)
        require(legacy.stdout.strip()==b'disabled','Legacy gateway is still enabled')
        legacy=command(['/usr/bin/systemctl','--user','is-active','agentporter.service'],user=OWNER,check=False)
        require(legacy.stdout.strip()==b'inactive','Legacy gateway is still running')
        journal.update(phase='complete',gateway_pid=pid,canary_commit=commit,fingerprint=FINGERPRINT);save(journal)
        print(json.dumps({'check':'production-cutover','status':'verified','pid':pid,'fingerprint':FINGERPRINT,
                          'workspace_count':len(projects),'canary_commit':commit,'tunnel_pid':journal['tunnel_pid'],
                          'system_boot_enabled':True,'legacy_gateway':'inactive-disabled'}),flush=True)
        print('PRODUCTION_CUTOVER_VERIFIED: immutable gateway; receipt-free commits; agent pushes denied; tunnel preserved.',flush=True)
    except BaseException:
        print('CUTOVER_FAILED: restoring saved configuration; inspect retained operator evidence.',flush=True)
        rollback(journal,updater)
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true')
    args=parser.parse_args();require(not(args.apply and args.rollback),'Choose apply or rollback')
    require(os.geteuid()==0 and sys.flags.isolated,'Run the installed root-owned helper with isolated Python')
    trusted_parents(ROOT,(0,));require(Path(__file__)==ROOT/'cutover.py','Use installed helper')
    require(__import__('socket').gethostname().split('.')[0]=='pho-rdpdl-23','BCC only')
    require(PYTHON.is_file(),'Immutable release 17 is missing')
    STATE.parent.mkdir(mode=0o700,parents=True,exist_ok=True);trusted_parents(STATE.parent,(0,))
    lock=os.open(STATE.parent/'cutover.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    info=os.fstat(lock)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o077,
            'Untrusted production operator lock')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    STATE.mkdir(mode=0o700,exist_ok=True);trusted_parents(STATE,(0,))
    updater=module('updater.py')
    if args.rollback:rollback(json.loads(read(STATE/'state.json',(0,),1024**2)[0]),updater)
    elif args.apply:apply(updater)
    else:print(json.dumps({'mode':'plan','release':str(RELEASE),'gateway_port':8765,'worker_port':8876,'phone_signing':False,'agent_push':False}))

if __name__=='__main__':main()
