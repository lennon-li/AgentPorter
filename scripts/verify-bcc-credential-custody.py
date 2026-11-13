#!/usr/bin/env python3
"""Disposable distinct-UID test of sealed BCC code; synthetic credentials only."""
import base64
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path('/var/lib/agentporter-bcc/consolidation-20261113-10')
PYTHON = Path('/opt/agentporter-bcc/releases/consolidation-20261113-10-worker/venv/bin/python')
OWNER, GROUP, WORKER = 2056259175, 2056259276, 997


def real_access():
    """After activation only: inspect actual issuance, without a provider turn."""
    assert os.getuid() == 0 and sys.flags.isolated
    assert json.loads((ROOT/'status.json').read_text())['phase'] in {'active_pending_live_acceptance','accepted'}
    policy_path = Path('/etc/agentporter-bcc/credential-broker.json')
    policy = json.loads(policy_path.read_text())
    assert policy['mode'] == 'access_only'
    assert {'jax','liz','prof'} <= set(policy['accounts'])
    target = ROOT/('real-access-'+str(time.time_ns()))
    target.mkdir(mode=0o700)
    os.chown(target, WORKER, WORKER)
    code = '''import concurrent.futures,json,os,subprocess,sys
from pathlib import Path
from agentporter.agents.credential_broker import BrokerCredentialLease
policy=json.loads(Path('/etc/agentporter-bcc/credential-broker.json').read_text())
root=Path(sys.argv[1])
def one(pair):
 i,account=pair;p=root/str(i)/'auth.json'
 config={key:policy[key] for key in ('owner_uid','socket_path')};config['account']=account
 lease=BrokerCredentialLease(config,p)
 try:
  data=json.loads(p.read_bytes());assert data['tokens']['refresh_token']==''
  assert data['tokens']['account_id']==policy['accounts'][account]['account_id']
  env={'PATH':'/usr/bin:/bin','HOME':str(p.parent),'CODEX_HOME':str(p.parent)}
  run=subprocess.run(['/opt/agent-clis/current/bin/codex',
      '--no-daemon','login','status'],env=env,cwd='/',capture_output=True,timeout=15)
  assert run.returncode==0 and b'ChatGPT' in run.stdout+run.stderr
  p.write_text('{"hostile":"must never write back"}')
  return {'profile':account,'native_login_status':'passed','refresh_authority_delegated':False}
 finally:
  lease.finish();p.unlink()
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 outcomes=list(pool.map(one,enumerate(['jax','liz','prof','jax','liz','prof'])))
print(json.dumps({'worker_uid':os.getuid(),'outcomes':outcomes,'model_calls':0}))
'''
    result = subprocess.run([str(PYTHON), '-I', '-B', '-c', code, str(target)],
        user=WORKER, group=WORKER, extra_groups=(), cwd='/',
        env={'PATH':'/usr/bin:/bin','HOME':str(target)}, capture_output=True, timeout=45)
    assert result.returncode == 0, 'Live access issuance or native login status failed; no automatic retry'
    for name, spec in policy['accounts'].items():
        if name not in {'jax','liz','prof'}:
            continue
        current = json.loads(Path(spec['auth_file']).read_text())
        assert current['tokens']['account_id'] == spec['account_id'], 'Native account binding changed'
    print(result.stdout.decode().strip())
    print(json.dumps({'passed':True,'native_accounts_distinct':True,'model_calls':0}))


def real_providers():
    assert os.getuid()==0 and sys.flags.isolated
    policy=json.loads(Path('/etc/agentporter-bcc/credential-broker.json').read_text())
    assert policy['mode']=='access_only' and {'ming','phil'}<=set(policy['accounts'])
    target=ROOT/('provider-access-'+str(time.time_ns()));target.mkdir(mode=0o700);os.chown(target,WORKER,WORKER)
    code='''import json,os,subprocess,sys
from pathlib import Path
from agentporter.agents.credential_broker import BrokerCredentialLease
policy=json.loads(Path('/etc/agentporter-bcc/credential-broker.json').read_text());root=Path(sys.argv[1])
for name,provider,destination in [('ming','claude','.claude/.credentials.json'),('phil','copilot','.copilot-phil/config.json')]:
 home=root/name;target=home/destination
 config={k:policy[k] for k in ('owner_uid','socket_path')};config.update(account=name,provider=provider)
 lease=BrokerCredentialLease(config,target)
 try:
  data=json.loads(target.read_text())
  if provider=='claude':
   assert 'refreshToken' not in data['claudeAiOauth']
   env={'PATH':'/usr/bin:/bin','HOME':str(home),'CLAUDE_CONFIG_DIR':str(target.parent),'DISABLE_AUTOUPDATER':'1'}
   run=subprocess.run(['/opt/agent-clis/current/bin/claude','auth','status','--json'],env=env,cwd='/',capture_output=True,timeout=15)
   assert run.returncode==0 and json.loads(run.stdout)['loggedIn'] is True
  else:
   assert data['lastLoggedInUser']['login']==policy['accounts'][name]['account_id']
   assert 'trustedFolders' not in data and 'mcpServers' not in data
  target.write_text('{"hostile":"must never write back"}')
 finally:lease.finish();target.unlink()
 print(json.dumps({'profile':name,'native_credential_issuance':'passed','worker_uid':os.getuid(),'model_calls':0}))
'''
    result=subprocess.run([str(PYTHON),'-I','-B','-c',code,str(target)],user=WORKER,group=WORKER,
        extra_groups=(),cwd='/',env={'PATH':'/usr/bin:/bin','HOME':str(target)},capture_output=True,timeout=45)
    assert result.returncode==0,'Provider access issuance failed; no credential-bearing output emitted'
    print(result.stdout.decode().strip())
    print(json.dumps({'passed':True,'model_calls':0}))


def main():
    assert os.getuid() == 0 and sys.flags.isolated
    assert json.loads((ROOT/'status.json').read_text())['phase'] == 'staged'
    target = ROOT/'synthetic-custody'
    target.mkdir(mode=0o755)
    def directory(name, uid, gid, mode):
        path = target/name
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        return path
    source = directory('native', OWNER, GROUP, 0o700)/'auth.json'
    payload = base64.urlsafe_b64encode(json.dumps({'exp': time.time()+3600}).encode()).decode().rstrip('=')
    identity = base64.urlsafe_b64encode(json.dumps({'email':'synthetic@example.invalid',
        'https://api.openai.com/auth': {'chatgpt_account_id':'synthetic-account',
            'chatgpt_plan_type':'plus','chatgpt_user_id':'synthetic-user'}}).encode()).decode().rstrip('=')
    raw = json.dumps({'auth_mode': 'chatgpt', 'tokens': {'account_id': 'synthetic-account',
        'id_token': 'head.'+identity+'.signature', 'access_token': 'head.'+payload+'.signature', 'refresh_token': 'synthetic-refresh'}}).encode()
    source.write_bytes(raw)
    source.chmod(0o600)
    os.chown(source, OWNER, GROUP)
    state = directory('state', OWNER, GROUP, 0o700)
    transport = directory('transport', OWNER, WORKER, 0o710)
    worker = directory('worker', WORKER, WORKER, 0o700)
    path = transport/'auth.sock'
    assert len(str(path).encode()) < 108
    policy = {'version': 1, 'mode': 'access_only', 'owner_uid': OWNER, 'worker_uid': WORKER,
        'socket_path': str(path), 'state_dir': str(state), 'forbidden_roots': ['/home/yeli/repos'],
        'accounts': {'prof': {'auth_file': str(source), 'account_id': 'synthetic-account',
            'native_socket': '/nonexistent-synthetic-native.sock'}}}
    policy_path = target/'policy.json'
    policy_path.write_text(json.dumps(policy)); policy_path.chmod(0o644)
    log = (target/'broker.log').open('wb')
    broker = subprocess.Popen([str(PYTHON), '-I', '-B', '-m', 'agentporter.agents.credential_broker',
        '--policy', str(policy_path), 'serve'], user=OWNER, group=WORKER, extra_groups=(),
        cwd='/', env={'PATH': '/usr/bin:/bin', 'HOME': '/home/yeli'}, stdout=log, stderr=log)
    try:
        deadline = time.monotonic()+10
        while not path.exists() and broker.poll() is None and time.monotonic()<deadline:
            time.sleep(.05)
        assert path.is_socket() and broker.poll() is None, 'Synthetic broker failed to start; inspect its private log'
        config = {'owner_uid': OWNER, 'socket_path': str(path), 'account': 'prof'}
        code = '''import concurrent.futures,json,os,subprocess,sys
from pathlib import Path
from agentporter.agents.credential_broker import BrokerCredentialLease
config=json.loads(sys.argv[1]);root=Path(sys.argv[2])
def one(i):
 p=root/str(i)/'auth.json';lease=BrokerCredentialLease(config,p)
 data=json.loads(p.read_bytes());assert data['tokens']['refresh_token']==''
 assert data['tokens']['account_id']=='synthetic-account'
 assert 'synthetic-refresh' not in p.read_text()
 run=subprocess.run(['/opt/agent-clis/current/bin/codex',
     '--no-daemon','login','status'],capture_output=True,timeout=15,cwd='/',
     env={'PATH':'/usr/bin:/bin','HOME':str(p.parent),'CODEX_HOME':str(p.parent)})
 assert run.returncode==0 and b'ChatGPT' in run.stdout+run.stderr
 p.write_text('{"hostile":"worker cannot write this back"}')
 lease.finish()
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(one,range(6)))
print(json.dumps({'worker_uid':os.getuid(),'concurrent_issuances':6,'refresh_token_delegated':False,'native_cli_login_checks':6,'model_calls':0}))
'''
        result = subprocess.run([str(PYTHON), '-I', '-B', '-c', code, json.dumps(config), str(worker)],
            user=WORKER, group=WORKER, extra_groups=(), cwd='/',
            env={'PATH': '/usr/bin:/bin', 'HOME': str(worker)}, capture_output=True, timeout=30)
        assert result.returncode == 0, 'Distinct-UID client test failed'
        assert source.read_bytes() == raw and not list(source.parent.glob('*pending*'))
        print(result.stdout.decode().strip())
        print(json.dumps({'passed': True, 'canonical_auth_unchanged': True, 'native_accounts_used': False}))
    finally:
        broker.terminate()
        broker.wait(10)
        log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--real-access', action='store_true')
    parser.add_argument('--real-providers',action='store_true')
    args=parser.parse_args()
    if args.real_access:
        real_access()
    elif args.real_providers:
        real_providers()
    else:
        main()
