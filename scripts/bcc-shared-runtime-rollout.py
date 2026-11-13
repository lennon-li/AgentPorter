#!/usr/bin/env python3
"""Guarded BCC shared-CLI cutover, with exact configuration rollback."""
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import yaml

LIBRARY=Path('/var/lib/agentporter-bcc/consolidation-20261113-04/rollout-v2.py')
LIBRARY_SHA='305a774df04a74ff2dc0e40dee1064964dce4ec49726d9816b2978ea10e0e41b'
CONTROL=Path('/var/lib/agentporter-bcc/consolidation-20261113-06')
CANDIDATE=Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112/shared-runtime-v06')
MANIFEST_SHA='54b08598d265ac42ef8e03972c74c4ee88866498366312417d73356e5a8ab3f4'
OLD={r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-05-'+r) for r in ('gateway','worker')}
NEW={r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-06-'+r) for r in OLD}
SITE=Path('venv/lib/python3.13/site-packages')
CLI=Path('/opt/agent-clis/current')
QMAN=Path('/etc/systemd/system/agentporter-qman.service')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    assert os.getuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    for p in (LIBRARY,*LIBRARY.parents):
        i=p.lstat();assert i.st_uid==0 and not i.st_mode&0o022 and not p.is_symlink()
    raw=LIBRARY.read_bytes();assert sha(raw)==LIBRARY_SHA
    spec=importlib.util.spec_from_file_location('sealed_bcc_controls',LIBRARY)
    lib=importlib.util.module_from_spec(spec);exec(compile(raw,str(LIBRARY),'exec'),lib.__dict__)
    lib.OLD,lib.NEW,lib.CONTROL,lib.STATE=OLD,NEW,CONTROL,CONTROL/'status.json'
    helper=lib.controls()
    with helper.operation_locks():
        if sys.argv[1:]==['--rollback']:
            assert Path(__file__)==CONTROL/'rollout.py'
            state=json.loads(lib.read(lib.STATE));assert state['phase'] in {'active_pending_live_acceptance','accepted'}
            state['nonce']=secrets.token_hex(16);helper.begin_timer_cycle(state)
            for role in OLD:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
            helper.pause_timer(state);lib.system('stop',QMAN.name);lib.restore(helper,state);lib.system('start',QMAN.name);return
        own=Path(__file__).read_bytes();assert sha(own)==globals().get('BOOTSTRAP_SHA')
        assert not CONTROL.exists() and all(not p.exists() for p in NEW.values())
        body=lib.read(CANDIDATE/'MANIFEST.json');assert sha(body)==MANIFEST_SHA
        manifest=json.loads(body)
        state={'phase':'preflight','files':{},'guarded':[],'nonce':secrets.token_hex(16),
               'baseline':{'databases':{},'releases':{}},'new':{}}
        for role in OLD:
            value=json.loads(lib.read(OLD[role]/'RELEASE.json'))
            assert value['files']==helper.files_manifest(OLD[role])
            assert sha(lib.read(OLD[role]/'RELEASE.json'))==manifest['roles'][role]['base_manifest_sha256']
            fp=helper.fingerprint(OLD[role]/lib.SITE);lib.live(helper,role,OLD[role],fp)
            state['baseline']['releases'][role]={'fingerprint':fp}
            state['baseline']['databases'][role]=json.loads(helper.guard(role,'probe','0'*32))['database_identity']
        CONTROL.mkdir(mode=0o755);(CONTROL/'events').mkdir(mode=0o700)
        lib.atomic(CONTROL/'rollout.py',own,mode=0o500)
        lib.atomic(CONTROL/'candidate-manifest.json',body,mode=0o444)
        lib.save(state,'preflight_passed')
        for role in OLD:
            changes=manifest['roles'][role]['files']
            allowed={'agentporter/agents/development.py','agentporter/shared_cli.py'}
            if role=='gateway':allowed|={'qman/codex_collector.py','qman/copilot_collector.py'}
            assert set(changes)==allowed
            shutil.copytree(OLD[role],NEW[role],symlinks=True)
            for directory,_,_ in os.walk(NEW[role]):Path(directory).chmod(0o755)
            replacements={}
            for relative,entry in changes.items():
                old=OLD[role]/SITE/relative;after=lib.read(CANDIDATE/role/relative)
                assert (sha(lib.read(old)) if old.exists() else None)==entry['before_sha256']
                assert sha(after)==entry['after_sha256']
                compile(after,str(relative),'exec')
                lib.atomic(NEW[role]/SITE/relative,after,mode=0o444);replacements[relative]=after
            for record in (NEW[role]/SITE).glob('*.dist-info/RECORD'):
                rows=list(csv.reader(io.StringIO(lib.read(record).decode())))
                changed=False
                for row in rows:
                    if row[0] in replacements:
                        after=replacements[row[0]];row[1]='sha256='+base64.urlsafe_b64encode(hashlib.sha256(after).digest()).decode().rstrip('=');row[2]=str(len(after));changed=True
                if record.parent.name.startswith('agentporter-'):
                    rel='agentporter/shared_cli.py';after=replacements[rel]
                    assert not any(r[0]==rel for r in rows)
                    rows.append([rel,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(after).digest()).decode().rstrip('='),str(len(after))]);changed=True
                if changed:
                    out=io.StringIO();csv.writer(out,lineterminator='\n').writerows(rows)
                    lib.atomic(record,out.getvalue().encode(),mode=0o444)
            value=json.loads(lib.read(NEW[role]/'RELEASE.json'))
            value.update(version=NEW[role].name,previous_version=OLD[role].name,application_delta_sha256=MANIFEST_SHA,
                         build_method='sealed_consolidation_plus_shared_cli_selection')
            for directory,_,names in os.walk(NEW[role],topdown=False):
                for name in names:
                    p=Path(directory)/name
                    if not p.is_symlink():p.chmod(0o555 if p.stat().st_mode&0o111 else 0o444)
                Path(directory).chmod(0o555)
            value['files']=helper.files_manifest(NEW[role]);NEW[role].chmod(0o755)
            lib.atomic(NEW[role]/'RELEASE.json',json.dumps(value,sort_keys=True,indent=2).encode()+b'\n',mode=0o444);NEW[role].chmod(0o555)
            assert value['files']==helper.files_manifest(NEW[role])
            state['new'][role]={'fingerprint':helper.fingerprint(NEW[role]/lib.SITE),'manifest_sha256':sha(lib.read(NEW[role]/'RELEASE.json'))}
        helper.begin_timer_cycle(state)
        try:
            for role in OLD:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
                lib.save(state,'admissions_held_'+role)
            helper.pause_timer(state);lib.stop_pair(helper,state);lib.system('stop',lib.AUTH_UNIT.name,QMAN.name)
            path=lib.CONFIG['worker']/'development-runtime.yaml'
            runtime=yaml.safe_load(lib.read(path));selection=json.loads(lib.read(CLI/'MANIFEST.json'))
            assert selection['schema']==1 and selection['account_data_included'] is False
            for agent,provider in {'jax':'codex','liz':'codex','prof':'codex','ming':'claude','phil':'copilot','wei':'opencode','argie':'agy'}.items():
                row=selection['providers'][provider];worker=runtime['workers'][agent]
                worker['executable']=str(CLI/row['binary'])
                if provider!='agy':worker['runtime_mounts']=[{'source':str(CLI/row['package_root']),'target':'/opt/agentporter/runtime/'+provider}]
                if provider=='codex':worker['code_mode_host']=str(CLI/row['helper'])
            lib.snapshot_replace(state,path,yaml.safe_dump(runtime,sort_keys=False).encode(),997,997)
            for name in ('workspaces.yaml','public-client-policy.yaml'):
                path=lib.CONFIG['gateway']/name;value=yaml.safe_load(lib.read(path));old=value['workspaces']['bcc-production-canary']
                assert old['path']=='/home/yeli/repos/AgentPorter/artifacts/bcc-production-canary-20261029' and not Path(old['path']).exists()
                del value['workspaces']['bcc-production-canary']
                lib.snapshot_replace(state,path,yaml.safe_dump(value,sort_keys=False).encode(),lib.OWNER,lib.GROUP)
            for role in OLD:
                path=helper.unit_path(role);before=lib.read(path);after=before.replace(str(OLD[role]).encode(),str(NEW[role]).encode())
                assert after!=before;lib.snapshot_replace(state,path,after,mode=0o644)
            for path,old,new in [(lib.AUTH_UNIT,OLD['worker'],NEW['worker']),
                (QMAN,Path('/opt/agentporter-bcc/releases/bcc-parity-gateway-20261105-01'),NEW['gateway'])]:
                before=lib.read(path);after=before.replace(str(old).encode(),str(new).encode());assert after!=before
                lib.snapshot_replace(state,path,after,mode=0o644)
            lib.system('daemon-reload');lib.system('start',lib.AUTH_UNIT.name,QMAN.name)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in OLD))
            state['new_pids']={r:lib.live(helper,r,NEW[r],state['new'][r]['fingerprint']) for r in OLD}
            assert lib.system('is-active',QMAN.name)=='active'
            helper.profile_snapshot();lib.save(state,'new_services_verified')
            # Rehearse configuration and application rollback with admissions held.
            after={n:lib.read(Path(n)) for n in state['files']}
            lib.system('stop',QMAN.name);lib.restore(helper,state,release=False);lib.system('start',QMAN.name)
            lib.stop_pair(helper,state);lib.system('stop',lib.AUTH_UNIT.name,QMAN.name)
            for name,raw in after.items():
                row=state['files'][name];lib.atomic(Path(name),raw,row.get('uid',0),row.get('gid',0),row.get('mode',0o644))
            lib.system('daemon-reload');lib.system('start',lib.AUTH_UNIT.name,QMAN.name)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in OLD))
            state['new_pids']={r:lib.live(helper,r,NEW[r],state['new'][r]['fingerprint']) for r in OLD}
            helper.profile_snapshot();lib.save(state,'rollback_rehearsal_passed')
            lib.release_guards(helper,state);lib.save(state,'active_pending_live_acceptance')
        except BaseException:
            lib.save(state,'cutover_failed')
            if state['files']:
                lib.system('stop',QMAN.name);lib.restore(helper,state);lib.system('start',QMAN.name)
            else:lib.release_guards(helper,state)
            raise


if __name__=='__main__':main()
