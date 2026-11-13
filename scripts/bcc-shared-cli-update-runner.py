#!/usr/bin/env python3
"""Fixed scheduled update: download as yeli, import sealed code as root.

No sudo permission is granted to the owner or any worker. HOME is an empty
staging home, so unattended updates never load native account credentials.
"""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

OWNER,GROUP=2056259175,2056259276
CONTROLLER=Path('/usr/local/libexec/bcc-shared-cli.py')


def main():
    assert os.getuid()==0
    parent=Path('/home/yeli/.cache/bcc-shared-cli-staging')
    assert parent.is_dir() and parent.stat().st_uid==OWNER and not parent.stat().st_mode&0o077
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    home=parent/('scheduled-home-'+stamp);home.mkdir(mode=0o700);os.chown(home,OWNER,GROUP)
    stage=parent/('scheduled-'+stamp)
    env={'PATH':'/home/yeli/.nvm/versions/node/v22.23.0/bin:/usr/local/bin:/usr/bin:/bin',
         'HOME':str(home),'USER':'yeli','LOGNAME':'yeli','LANG':'C.UTF-8'}
    result=subprocess.run(['/usr/bin/python3','-I','-B',str(CONTROLLER),'--prepare',str(stage),'--latest'],
        user=OWNER,group=GROUP,extra_groups=(),env=env,cwd='/',capture_output=True,timeout=1800)
    if result.returncode:
        raise RuntimeError('Shared CLI staging failed; current selection retained')
    # The installed controller bounds paths, verifies every byte, strips special
    # modes, and never executes supplied code with machine privileges.
    manifest=stage/'release/MANIFEST.json'
    digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
    subprocess.run(['/usr/bin/python3','-I','-B',str(CONTROLLER),'--install',str(stage/'release'),
        '--manifest-sha256',digest],check=True,timeout=600,env={'PATH':'/usr/bin:/bin'},cwd='/')
    assert hashlib.sha256(Path('/opt/agent-clis/current/MANIFEST.json').read_bytes()).hexdigest()==digest
    # Only these create-only, credential-free staging directories are retired.
    for directory in (stage,home):
        assert directory.parent==parent and directory.stat().st_uid==OWNER and not directory.is_symlink()
        shutil.rmtree(directory)
    print(json.dumps({'scheduled_shared_cli_update':'passed','staging_cleaned':True,'credentials_loaded':False}),flush=True)


if __name__=='__main__':main()
