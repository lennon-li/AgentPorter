#!/usr/bin/python3
"""Mirror the reviewed asgard workspace snapshot to development; dry run by default."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import urllib.request
import yaml

REPO=Path('/home/yeli/agent-work/agentporter-dev')
ARTIFACTS=REPO/'runtime/development'

def plan():
    old=json.loads((ARTIFACTS/'workspace-comparison.json').read_text())['asgard']
    rows=yaml.safe_load((ARTIFACTS/'mirrored-workspaces.yaml').read_text())['workspaces']
    assert set(rows)=={w['workspace_id'] for w in old}|{'agentporter-dev'}
    for entry in old:
        row=rows[entry['workspace_id']]
        assert row['path']==entry['path'] and row['writable']==entry['writable']
        for local,remote in [('allow_execute','execute'),('allow_git','git'),('allow_artifacts','artifacts'),('allow_agent_dispatch','agent_dispatch')]:
            assert row[local]==entry['permissions'][remote]
    for key,row in rows.items():
        assert '/' not in key and key not in ('.','..')
        path=Path(row['path']).resolve(strict=True)
        assert path.is_dir()
        assert path==Path('/home/yeli/repos') or path.is_relative_to('/home/yeli/repos') or path in (REPO,Path('/home/yeli/m3-agent-poc'))
        assert not row.get('auto_discover')
        assert not any(row.get(k) for k in ('allow_venkata_ssh','allow_venkata_transfer','allow_scinet_diagnostic','allow_scinet_training'))
    return {'workspaces':rows}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    workspaces=plan()
    print(f'Validated {len(workspaces["workspaces"])} explicit workspaces; all 45 asgard entries plus agentporter-dev.')
    print('Production configuration and services unchanged; development remote SSH/SciNet authorities remain disabled.')
    if not args.apply:return
    if os.geteuid()!=0 or not sys.flags.isolated or Path(sys.executable).resolve()!=Path('/usr/bin/python3').resolve():
        raise SystemExit('Apply with sudo /usr/bin/python3 -I '+str(Path(__file__).resolve())+' --apply')
    spec=importlib.util.spec_from_file_location('development_provisioner',REPO/'scripts/provision-development-runtime.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    account=pwd.getpwnam('agentporter-dev')
    assert account.pw_uid not in (0,pwd.getpwnam('yeli').pw_uid)
    target=Path('/var/lib/agentporter-dev/config/workspaces.yaml')
    helper.no_symlink(target)
    backup=Path('/var/lib/agentporter-dev/provisioning')/('workspace-mirror-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(mode=0o700)
    shutil.copy2(target,backup/'previous-workspaces.yaml')
    rows=workspaces['workspaces']
    # Cover umbrella roots once; then restore explicitly restrictive children.
    roots={key:row for key,row in rows.items() if not any(Path(row['path']).resolve().is_relative_to(Path(other['path']).resolve()) and Path(row['path']).resolve()!=Path(other['path']).resolve() for other in rows.values())}
    restrictive={key:row for key,row in rows.items() if not row['writable']}
    helper.grant_workspaces({'workspaces':roots},account,backup)
    helper.grant_workspaces({'workspaces':restrictive},account,backup)
    helper.atomic_text(target,yaml.safe_dump(workspaces,sort_keys=False),uid=account.pw_uid,gid=account.pw_gid)
    helper.run(['systemctl','restart','agentporter-development.service'])
    # Verify the actual live registry from the dedicated account, keeping the key private.
    check='''import json, pathlib, urllib.request
p=pathlib.Path('/var/lib/agentporter-dev/config/secrets.env')
k=next(s.partition('=')[2].strip() for s in p.read_text().splitlines() if s.startswith('AGENTPORTER_API_KEY='))
r=urllib.request.Request('http://127.0.0.1:8876/api/v1/workspaces/',headers={'Authorization':'Bearer '+k})
with urllib.request.urlopen(r,timeout=15) as response: print(json.dumps(json.load(response)))
'''
    for attempt in range(30):
        result=helper.run(['runuser','-u','agentporter-dev','--','/usr/bin/python3','-I','-c',check],check=False)
        if result.returncode==0:break
        time.sleep(1)
    if result.returncode:raise SystemExit('Development restart verification failed; inspect development service. Backup: '+str(backup))
    live=json.loads(result.stdout)
    assert {row['workspace_id'] for row in live}==set(rows)
    assert all(row['exists'] for row in live)
    helper.atomic_text(backup/'verified-live-workspaces.json',json.dumps(live,indent=2))
    print('Verified live: 46 workspaces. Backup/evidence: '+str(backup))

if __name__=='__main__':main()
