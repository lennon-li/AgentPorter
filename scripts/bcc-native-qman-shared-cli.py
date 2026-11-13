#!/usr/bin/env python3
"""Rebind native Qman collectors; preserve its CLI/store code and database."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

LIBRARY=Path('/var/lib/agentporter-bcc/consolidation-20261113-04/rollout-v2.py')
LIBRARY_SHA='305a774df04a74ff2dc0e40dee1064964dce4ec49726d9816b2978ea10e0e41b'
CONTROL=Path('/var/lib/agent-clis/native-qman-consolidation-20261113')
OLD=Path('/opt/agentporter-bcc/releases/bcc-qman-20261105-01')
NEW=Path('/opt/agentporter-bcc/releases/bcc-qman-shared-cli-20261113-01')
CANDIDATE=Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112/native-qman-shared-cli')
MANIFEST_SHA='07a83d9357858cde3d0df0b2d4497098e4610771fa3b1bbd62be300a61c7cd27'
SITE=Path('venv/lib/python3.13/site-packages')
OWNER,GROUP=2056259175,2056259276


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    assert os.getuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    raw=LIBRARY.read_bytes();assert sha(raw)==LIBRARY_SHA
    spec=importlib.util.spec_from_file_location('sealed_native_qman_controls',LIBRARY);lib=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(LIBRARY),'exec'),lib.__dict__);helper=lib.controls()
    own=Path(__file__).read_bytes();assert sha(own)==globals().get('BOOTSTRAP_SHA')
    assert not NEW.exists() and not CONTROL.exists()
    baseline=json.loads(lib.read(OLD/'RELEASE.json'))
    expected={k:v for k,v in baseline['files'].items() if k.startswith('venv/')}
    actual={k:v for k,v in helper.files_manifest(OLD,sealed=False).items() if k.startswith('venv/')}
    assert actual==expected, 'Native Qman Python package changed'
    raw=lib.read(CANDIDATE/'MANIFEST.json');assert sha(raw)==MANIFEST_SHA
    candidate=json.loads(raw);assert set(candidate['files'])=={'qman/codex_collector.py','qman/copilot_collector.py','qman/shared_cli.py'}
    CONTROL.mkdir(mode=0o700);NEW.mkdir(mode=0o755)
    lib.atomic(CONTROL/'install.py',own,mode=0o500);lib.atomic(CONTROL/'candidate-manifest.json',raw,mode=0o444)
    shutil.copytree(OLD/'venv',NEW/'venv',symlinks=True)
    for directory,_,_ in os.walk(NEW/'venv'):Path(directory).chmod(0o755)
    for relative,row in candidate['files'].items():
        old=OLD/SITE/relative;after=lib.read(CANDIDATE/relative)
        assert (sha(lib.read(old)) if old.exists() else None)==row['before_sha256'] and sha(after)==row['after_sha256']
        lib.atomic(NEW/SITE/relative,after,mode=0o444)
    for directory,_,files in os.walk(NEW,topdown=False):
        for name in files:
            p=Path(directory)/name
            if not p.is_symlink():p.chmod(0o555 if p.stat().st_mode&0o111 else 0o444)
        Path(directory).chmod(0o555)
    for key in ('binary_inputs','native_bridge'):
        if key in baseline:baseline['historical_'+key]=baseline.pop(key)
    baseline['shared_cli_manifest']='/opt/agent-clis/current/MANIFEST.json'
    baseline.update(version=NEW.name,previous_version=OLD.name,
        build_method='native_qman_collectors_only_shared_cli_no_embedded_cli',application_delta_sha256=MANIFEST_SHA)
    baseline['files']=helper.files_manifest(NEW);NEW.chmod(0o755)
    lib.atomic(NEW/'RELEASE.json',json.dumps(baseline,sort_keys=True,indent=2).encode()+b'\n',mode=0o444);NEW.chmod(0o555)
    assert baseline['files']==helper.files_manifest(NEW)
    # --help is a provider/DB-free operation. Interface equality proves that
    # native CLI/store behavior is retained; only collectors and their helper differ.
    help_output=[]
    for release in (OLD,NEW):
        result=subprocess.run([str(release/'venv/bin/python'),'-I','-B','-m','qman.cli','--help'],
            user=OWNER,group=GROUP,extra_groups=(),env={'PATH':'/usr/bin:/bin','HOME':'/home/yeli'},
            cwd='/',capture_output=True,timeout=20)
        assert result.returncode==0;help_output.append(result.stdout)
    assert help_output[0]==help_output[1]
    path=Path('/home/yeli/.local/bin/qman')
    before=lib.read(path)
    assert before==(b'#!/bin/sh\nexec '+str(OLD/'venv/bin/python').encode()+b' -I -B -m qman.cli --db /home/yeli/.local/state/qman/qman.db "$@"\n')
    lib.atomic(CONTROL/'native-launcher-before',before,mode=0o600)
    launcher=Path('/opt/agent-clis/launch/qman');assert not launcher.exists()
    after=before.replace(str(OLD).encode(),str(NEW).encode());lib.atomic(launcher,after,mode=0o555)
    pending=path.with_name('.qman-shared-cli');assert not pending.exists();pending.symlink_to(launcher);os.replace(pending,path)
    system=Path('/usr/local/bin/qman');assert not os.path.lexists(system);system.symlink_to(launcher)
    receipt={'passed':True,'release':str(NEW),'native_cli_help_unchanged':True,'database_opened_or_changed':False,
        'services_changed':False,'embedded_agent_cli_copies':False,'updated_modules':sorted(candidate['files'])}
    lib.atomic(CONTROL/'receipt.json',json.dumps(receipt,indent=2).encode(),mode=0o444)
    print(json.dumps(receipt))


if __name__=='__main__':main()
