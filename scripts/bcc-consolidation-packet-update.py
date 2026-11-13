#!/usr/bin/env python3
"""Sealed BCC packet wording correction; reuse accepted cutover/rollback controls."""
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

LIBRARY = Path('/var/lib/agentporter-bcc/consolidation-20261113-04/rollout-v2.py')
LIBRARY_SHA = '305a774df04a74ff2dc0e40dee1064964dce4ec49726d9816b2978ea10e0e41b'
CONTROL = Path('/var/lib/agentporter-bcc/consolidation-20261113-05')
CANDIDATE = Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112/candidate-v17')
MANIFEST_SHA = '5afbbf255fbde6928d2cb1216111ffb2e04a594a85ebbc9664ef1fdb9c6af7b2'
OLD = {r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-04-'+r) for r in ('gateway','worker')}
NEW = {r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-05-'+r) for r in OLD}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    assert os.getuid() == 0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    for p in (LIBRARY,*LIBRARY.parents):
        i=p.lstat();assert i.st_uid==0 and not i.st_mode&0o022 and not p.is_symlink()
    raw=LIBRARY.read_bytes();assert digest(raw)==LIBRARY_SHA
    spec=importlib.util.spec_from_file_location('sealed_bcc_controls',LIBRARY)
    lib=importlib.util.module_from_spec(spec);exec(compile(raw,str(LIBRARY),'exec'),lib.__dict__)
    lib.OLD,lib.NEW,lib.CONTROL,lib.STATE=OLD,NEW,CONTROL,CONTROL/'status.json'
    helper=lib.controls()
    with helper.operation_locks():
        if sys.argv[1:] == ['--rollback']:
            assert Path(__file__)==CONTROL/'update.py'
            state=json.loads(lib.read(lib.STATE));assert state['phase']=='active_pending_live_acceptance'
            state['nonce']=secrets.token_hex(16);helper.begin_timer_cycle(state)
            for role in OLD:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
            helper.pause_timer(state);lib.restore(helper,state);return
        own=Path(__file__).read_bytes();assert digest(own)==globals().get('BOOTSTRAP_SHA')
        assert not CONTROL.exists() and all(not p.exists() for p in NEW.values())
        body=lib.read(CANDIDATE/'MANIFEST.json');assert digest(body)==MANIFEST_SHA
        manifest=json.loads(body)
        profile=helper.profile_snapshot()
        state={'phase':'preflight','files':{},'guarded':[],'nonce':secrets.token_hex(16),
            'baseline':{'databases':{},'releases':{}},'new':{}}
        for role in OLD:
            m=json.loads(lib.read(OLD[role]/'RELEASE.json'))
            assert m['files']==helper.files_manifest(OLD[role])
            fp=helper.fingerprint(OLD[role]/lib.SITE)
            lib.live(helper,role,OLD[role],fp)
            state['baseline']['releases'][role]={'fingerprint':fp}
            state['baseline']['databases'][role]=json.loads(helper.guard(role,'probe','0'*32))['database_identity']
        CONTROL.mkdir(mode=0o755);(CONTROL/'events').mkdir(mode=0o700)
        lib.atomic(CONTROL/'update.py',own,mode=0o500)
        lib.atomic(CONTROL/'candidate-manifest.json',body,mode=0o444)
        lib.save(state,'preflight_passed')
        for role in OLD:
            before=lib.read(OLD[role]/lib.SITE/'agents/broker.py')
            after=lib.read(CANDIDATE/role/'agentporter/agents/broker.py')
            expected=before.replace(b'After success continue scoped edits/tests/commits; canonical publication occurs at successful ',
                b'After success continue scoped edits and tests. Workspace file changes persist after successful ').replace(
                b'job cleanup. If refused, report the exact refusal without changing scope. ',
                b'job cleanup. Commits require owner-run Git separately. If refused, report the exact refusal without changing scope. ')
            assert after==expected and after!=before
            assert digest(after)==manifest['roles'][role]['changed_files']['agents/broker.py']['after_sha256']
            shutil.copytree(OLD[role],NEW[role],symlinks=True)
            for directory,_,_ in os.walk(NEW[role]):Path(directory).chmod(0o755)
            lib.atomic(NEW[role]/lib.SITE/'agents/broker.py',after,mode=0o444)
            record=NEW[role]/lib.SITE.parent/'agentporter-0.1.0.dev0.dist-info/RECORD'
            rows=list(csv.reader(io.StringIO(lib.read(record).decode())))
            for row in rows:
                if row[0]=='agentporter/agents/broker.py':
                    row[1]='sha256='+base64.urlsafe_b64encode(hashlib.sha256(after).digest()).decode().rstrip('=');row[2]=str(len(after))
            output=io.StringIO();csv.writer(output,lineterminator='\n').writerows(rows)
            lib.atomic(record,output.getvalue().encode(),mode=0o444)
            value=json.loads(lib.read(NEW[role]/'RELEASE.json'))
            value.update(version=NEW[role].name,previous_version=OLD[role].name,
                application_delta_sha256=MANIFEST_SHA,build_method='sealed_consolidation_plus_packet_wording_correction')
            for directory,_,files in os.walk(NEW[role],topdown=False):
                for name in files:
                    p=Path(directory)/name
                    if not p.is_symlink():p.chmod(0o555 if p.stat().st_mode&0o111 else 0o444)
                Path(directory).chmod(0o555)
            value['files']=helper.files_manifest(NEW[role]);NEW[role].chmod(0o755)
            lib.atomic(NEW[role]/'RELEASE.json',json.dumps(value,sort_keys=True,indent=2).encode()+b'\n',mode=0o444)
            NEW[role].chmod(0o555)
            assert value['files']==helper.files_manifest(NEW[role])
            state['new'][role]={'fingerprint':helper.fingerprint(NEW[role]/lib.SITE),
                'manifest_sha256':digest(lib.read(NEW[role]/'RELEASE.json'))}
        helper.profile_snapshot(profile)
        helper.begin_timer_cycle(state)
        try:
            for role in OLD:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
                lib.save(state,'admissions_held_'+role)
            helper.pause_timer(state);lib.stop_pair(helper,state)
            lib.system('stop',lib.AUTH_UNIT.name)
            for role in OLD:
                path=helper.unit_path(role);old=lib.read(path)
                updated=old.replace(str(OLD[role]).encode(),str(NEW[role]).encode())
                assert updated!=old and updated.count(str(NEW[role]).encode())==1
                lib.snapshot_replace(state,path,updated,mode=0o644)
            unit=lib.read(lib.AUTH_UNIT);updated=unit.replace(str(OLD['worker']).encode(),str(NEW['worker']).encode())
            assert updated!=unit
            lib.snapshot_replace(state,lib.AUTH_UNIT,updated,mode=0o644)
            lib.system('daemon-reload');lib.system('start',lib.AUTH_UNIT.name)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in OLD))
            state['new_pids']={r:lib.live(helper,r,NEW[r],state['new'][r]['fingerprint']) for r in OLD}
            helper.profile_snapshot(profile)
            after={n:lib.read(Path(n)) for n in state['files']}
            lib.restore(helper,state,release=False)
            lib.stop_pair(helper,state);lib.system('stop',lib.AUTH_UNIT.name)
            for name,raw in after.items():lib.atomic(Path(name),raw,mode=0o644)
            lib.system('daemon-reload');lib.system('start',lib.AUTH_UNIT.name)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in OLD))
            state['new_pids']={r:lib.live(helper,r,NEW[r],state['new'][r]['fingerprint']) for r in OLD}
            helper.profile_snapshot(profile);lib.save(state,'rollback_rehearsal_passed')
            lib.release_guards(helper,state);lib.save(state,'active_pending_live_acceptance')
        except BaseException:
            lib.save(state,'update_failed')
            if state['files']:lib.restore(helper,state)
            else:lib.release_guards(helper,state)
            raise


if __name__=='__main__':main()
