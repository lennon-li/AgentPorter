#!/usr/bin/env python3
"""Select stable shared CLI links in BCC worker policy; guarded exact rollback."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import yaml

LIBRARY=Path('/var/lib/agentporter-bcc/consolidation-20261113-04/rollout-v2.py')
LIBRARY_SHA='305a774df04a74ff2dc0e40dee1064964dce4ec49726d9816b2978ea10e0e41b'
CONTROL=Path('/var/lib/agentporter-bcc/consolidation-20261113-08')
RELEASES={r:Path('/opt/agentporter-bcc/releases/consolidation-20261113-07-'+r) for r in ('gateway','worker')}


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    assert os.getuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    for path in (LIBRARY,*LIBRARY.parents):
        i=path.lstat();assert i.st_uid==0 and not i.st_mode&0o022 and not path.is_symlink()
    raw=LIBRARY.read_bytes();assert sha(raw)==LIBRARY_SHA
    spec=importlib.util.spec_from_file_location('sealed_bcc_controls',LIBRARY)
    lib=importlib.util.module_from_spec(spec);exec(compile(raw,str(LIBRARY),'exec'),lib.__dict__)
    lib.OLD=lib.NEW=RELEASES;lib.CONTROL=CONTROL;lib.STATE=CONTROL/'status.json';helper=lib.controls()
    with helper.operation_locks():
        if sys.argv[1:]==['--rollback']:
            assert Path(__file__)==CONTROL/'rollout.py'
            state=json.loads(lib.read(lib.STATE));assert state['phase'] in {'accepted','active_pending_live_acceptance'}
            state['nonce']=secrets.token_hex(16);helper.begin_timer_cycle(state)
            for role in RELEASES:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
            helper.pause_timer(state);lib.restore(helper,state);return
        own=Path(__file__).read_bytes();assert sha(own)==globals().get('BOOTSTRAP_SHA') and not CONTROL.exists()
        state={'phase':'preflight','files':{},'guarded':[],'nonce':secrets.token_hex(16),
            'baseline':{'databases':{},'releases':{}},'new':{}}
        for role,release in RELEASES.items():
            manifest=json.loads(lib.read(release/'RELEASE.json'));assert manifest['files']==helper.files_manifest(release)
            fp=helper.fingerprint(release/lib.SITE);lib.live(helper,role,release,fp)
            state['baseline']['databases'][role]=json.loads(helper.guard(role,'probe','0'*32))['database_identity']
            state['baseline']['releases'][role]={'fingerprint':fp};state['new'][role]={'fingerprint':fp}
        CONTROL.mkdir(mode=0o755);(CONTROL/'events').mkdir(mode=0o700);lib.atomic(CONTROL/'rollout.py',own,mode=0o500)
        lib.save(state,'preflight_passed');helper.begin_timer_cycle(state)
        try:
            for role in RELEASES:
                helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role]);state['guarded'].append(role)
            helper.pause_timer(state);lib.stop_pair(helper,state)
            path=lib.CONFIG['worker']/'development-runtime.yaml';runtime=yaml.safe_load(lib.read(path));cli=Path('/opt/agent-clis/current')
            manifest=json.loads(lib.read(cli/'MANIFEST.json'))
            for agent,provider in {'jax':'codex','liz':'codex','prof':'codex','ming':'claude','phil':'copilot','wei':'opencode','argie':'agy'}.items():
                worker=runtime['workers'][agent];assert Path(worker['executable']).is_relative_to(cli)
                binary=cli/'bin'/provider;assert binary.is_file() and os.access(binary,os.X_OK)
                assert os.path.samefile(binary,cli/manifest['providers'][provider]['binary'])
                worker['executable']=str(binary)
            lib.snapshot_replace(state,path,yaml.safe_dump(runtime,sort_keys=False).encode(),997,997)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in RELEASES))
            state['new_pids']={r:lib.live(helper,r,RELEASES[r],state['new'][r]['fingerprint']) for r in RELEASES}
            after=lib.read(path);lib.restore(helper,state,release=False);lib.stop_pair(helper,state)
            lib.atomic(path,after,997,997,0o600)
            lib.system('start',*(helper.ROLES[r]['unit'] for r in RELEASES))
            state['new_pids']={r:lib.live(helper,r,RELEASES[r],state['new'][r]['fingerprint']) for r in RELEASES}
            helper.profile_snapshot();lib.save(state,'rollback_rehearsal_passed')
            lib.release_guards(helper,state);lib.save(state,'active_pending_live_acceptance')
        except BaseException:
            lib.save(state,'cutover_failed')
            if state['files']:lib.restore(helper,state)
            else:lib.release_guards(helper,state)
            raise


if __name__=='__main__':main()
