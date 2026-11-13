#!/usr/bin/env python3
"""Read-only machine acceptance; emit code paths/versions and booleans only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import yaml

CLI=Path('/opt/agent-clis/current')
OWNER=2056259175
LIBRARY=Path('/var/lib/agentporter-bcc/consolidation-20261113-04/rollout-v2.py')
LIBRARY_SHA='305a774df04a74ff2dc0e40dee1064964dce4ec49726d9816b2978ea10e0e41b'
CONTROL=Path('/var/lib/agentporter-bcc/consolidation-20261113-10')
RELEASES={r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-10-'+r) for r in ('gateway','worker')}


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def main():
    assert os.getuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    manifest=json.loads((CLI/'MANIFEST.json').read_text());release=CLI.resolve(strict=True)
    assert release.parent==Path('/opt/agent-clis/releases')
    for relative,row in manifest['files'].items():
        path=release/relative;assert not Path(relative).is_absolute() and '..' not in Path(relative).parts
        info=path.lstat();assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o222
        assert info.st_size==row['size'] and sha(path)==row['sha256']
    runtime_path=Path('/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03/config/development-runtime.yaml')
    runtime=yaml.safe_load(runtime_path.read_text());mapping={}
    for agent,provider in {'jax':'codex','liz':'codex','prof':'codex','ming':'claude','phil':'copilot','wei':'opencode','argie':'agy'}.items():
        row=manifest['providers'][provider];worker=runtime['workers'][agent];binary=CLI/row['binary']
        assert worker['executable']==str(CLI/'bin'/provider) and os.path.samefile(binary,worker['executable'])
        for directory in (Path('/home/yeli/.local/bin'),Path('/usr/local/bin'),Path('/home/yeli/.nvm/versions/node/v22.23.0/bin')):
            assert os.path.samefile(directory/provider,Path('/opt/agent-clis/launch')/provider)
        launch=Path('/opt/agent-clis/launch')/provider;info=launch.stat()
        assert info.st_uid==0 and not info.st_mode&0o222
        assert launch.read_text().endswith('exec /opt/agent-clis/current/bin/'+provider+' "$@"\n')
        mapping[agent]={'provider':provider,'version':row['version'],'same_selected_file':True,'binary':str(binary.resolve())}
    assert os.path.samefile('/usr/bin/copilot','/opt/agent-clis/launch/copilot')
    assert os.path.samefile('/home/yeli/.opencode/bin/opencode','/opt/agent-clis/launch/opencode')
    assert os.path.samefile('/home/yeli/.local/bin/qman','/opt/agent-clis/launch/qman')
    assert os.path.samefile('/usr/local/bin/qman','/opt/agent-clis/launch/qman')
    native=Path('/opt/agentporter-bcc/releases/bcc-qman-shared-cli-20261113-01')
    assert not (native/'cli').exists()
    assert b'from qman.shared_cli import selected_codex' in (native/'venv/lib/python3.13/site-packages/qman/codex_collector.py').read_bytes()
    for account in ('.codex','.codex-liz','.codex-prof'):
        home=Path('/home/yeli')/account
        assert os.path.samefile(home/'packages/app-server-daemon/current/bin/codex',CLI/'bin/codex')
        pid=json.loads((home/'app-server-daemon/daemon.pid').read_text())['pid']
        assert os.path.samefile(Path('/proc')/str(pid)/'exe',CLI/'bin/codex')
        assert json.loads((home/'app-server-daemon/settings.json').read_text())['updater']['autoUpdateEnabled'] is False
    policy=json.loads(Path('/etc/agentporter-bcc/credential-broker.json').read_text())
    assert policy['mode']=='access_only' and set(policy['accounts'])=={'jax','liz','prof','ming','phil'}
    assert len({policy['accounts'][n]['account_id'] for n in ('jax','liz','prof')})==3
    for name in ('jax','liz','prof','ming','phil'):
        spec=runtime['workers'][name];assert spec['credential_broker']['account']==name
        assert not any(p.endswith(('auth.json','.credentials.json','config.json')) for p in spec['credentials'])
    raw=LIBRARY.read_bytes();assert hashlib.sha256(raw).hexdigest()==LIBRARY_SHA
    spec=importlib.util.spec_from_file_location('sealed_read_controls',LIBRARY);lib=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(LIBRARY),'exec'),lib.__dict__);helper=lib.controls()
    services={}
    for role,root in RELEASES.items():
        sealed=json.loads(lib.read(root/'RELEASE.json'));assert sealed['files']==helper.files_manifest(root)
        fp=helper.fingerprint(root/lib.SITE);pid=lib.live(helper,role,root,fp)
        modes=yaml.safe_load((lib.CONFIG[role]/'action-policy.yaml').read_text())['action_modes']
        assert modes['git_commit']==modes['git_push']=='LOCKED'
        services[role]={'pid':pid,'release':str(root),'loaded_and_disk_fingerprint':fp,'seal_verified':True,'commit_and_push_locked':True}
    assert json.loads((native/'RELEASE.json').read_text())['files']==helper.files_manifest(native)
    for unit in ('agentporter-bcc-credential-broker.service','agentporter-qman.service',
                 'agentporter-bcc-production-discovery.timer','bcc-shared-cli-update.timer'):
        assert lib.system('is-active',unit)=='active'
    result=lib.system('show','bcc-shared-cli-update.service','-p','Result','-p','ExecMainStatus')
    assert 'Result=success' in result and 'ExecMainStatus=0' in result
    cron=subprocess.run(['/usr/bin/crontab','-u','yeli','-l'],capture_output=True,check=True).stdout
    assert not any(b'updateCLI' in line and not line.lstrip().startswith(b'#') for line in cron.splitlines())
    workspaces=yaml.safe_load(Path('/home/yeli/.config/agentporter/workspaces.yaml').read_text())['workspaces']
    assert 'bcc-production-canary' not in workspaces
    assert all(Path(row['path']).exists() for row in workspaces.values())
    state=json.loads((CONTROL/'status.json').read_text());assert state['phase'] in {'accepted','active_pending_live_acceptance'} and state['guarded']==[] and state['timer_restored'] is True
    print(json.dumps({'passed':True,'selected_cli_release':str(release),'manifest_sha256':sha(CLI/'MANIFEST.json'),
        'worker_mappings':mapping,'native_codex_daemons_same_inode':True,'native_accounts_distinct':True,
        'services':services,'scheduled_shared_updater_passed':True,'old_updater_cron_removed':True,'native_qman_shared_cli':True,
        'workspace_count':len(workspaces),'all_configured_workspaces_exist':True,'root_control':str(CONTROL),
        'credentials_or_account_ids_emitted':False},indent=2))


if __name__=='__main__':main()
