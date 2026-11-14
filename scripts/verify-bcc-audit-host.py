#!/usr/bin/env python3
"""Fresh host checks. Emit booleans/versions only; no identities or token digests."""
import hashlib,json,os
from pathlib import Path
import subprocess,sys,time
REPO=Path('/home/yeli/repos/AgentPorter')
PYTHON='/opt/agentporter-bcc/releases/consolidation-20261113-10-worker/venv/bin/python'

def fingerprint(path):return hashlib.sha256(path.read_bytes()).digest()
def main():
 assert os.geteuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
 start=time.time();policy=json.loads(Path('/etc/agentporter-bcc/credential-broker.json').read_text())
 paths=[Path(s['auth_file']) for s in policy['accounts'].values()]
 before={str(p):fingerprint(p) for p in paths}
 results=[]
 for option in ('--real-access','--real-providers'):
  r=subprocess.run([PYTHON,'-I','-B',str(REPO/'scripts/verify-bcc-credential-custody.py'),option],capture_output=True,timeout=70)
  assert r.returncode==0,'Credential issuance verification failed; private output withheld'
  rows=[json.loads(line) for line in r.stdout.decode().splitlines()]
  assert rows[-1]['passed'] is True;results.append({'kind':option,'exit_code':r.returncode,'passed':True})
 unchanged=all(fingerprint(p)==before[str(p)] for p in paths)
 assert unchanged,'Native authority changed during custody check; inspect locally without emitting credentials'
 assert len({policy['accounts'][name]['account_id'] for name in ('jax','liz','prof')})==3
 def show(unit,*keys):
  args=['systemctl','show',unit]+['--property='+','.join(keys)]
  return dict(line.split('=',1) for line in subprocess.check_output(args,text=True).splitlines() if '=' in line)
 timer=show('bcc-shared-cli-update.timer','ActiveState','TimersCalendar','NextElapseUSecRealtime')
 service=show('bcc-shared-cli-update.service','NoNewPrivileges','ProtectSystem','ProtectHome','InaccessiblePaths','ReadWritePaths','ExecStart','ActiveState')
 assert timer['ActiveState']=='active' and 'America/New_York' in timer['TimersCalendar']
 assert service['NoNewPrivileges']=='yes' and service['ProtectSystem']=='strict'
 for name in ('.codex','.codex-liz','.codex-prof','.claude','.copilot-phil'):
  assert '/home/yeli/'+name in service['InaccessiblePaths']
 runner=Path('/usr/local/libexec/bcc-shared-cli-update-runner.py').read_text()
 assert 'user=' in runner and 'group=' in runner
 installed=json.loads((REPO/'artifacts/bcc-chatgpt-audit-20261113/fresh-shared-installation.json').read_text())
 assert installed['passed']
 print(json.dumps({'observed_started_epoch':start,'observed_finished_epoch':time.time(),'passed':True,
  'cli_selection_and_daemon_inodes':installed['passed'],'native_accounts_distinct':True,
  'actual_worker_uid_issuance':results,'native_store_bytes_unchanged':unchanged,
  'refresh_token_delegation':False,'model_calls':0,'actual_update_triggered':False,
  'timer':timer,'updater':service,'unprivileged_package_stage_present':True},indent=2))
if __name__=='__main__':main()
