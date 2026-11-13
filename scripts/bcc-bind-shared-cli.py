#!/usr/bin/env python3
"""Bind system/native entrypoints to the common code, retaining rollback data.

Only CLI code and selection links are changed. No native auth, sessions,
instructions, account configuration or daemon launch settings are moved.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

ROOT=Path('/opt/agent-clis')
CONTROL=Path('/var/lib/agent-clis/consolidation-20261113')
OWNER=2056259175
NVM=Path('/home/yeli/.nvm/versions/node/v22.23.0')


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def main():
    assert os.getuid()==0 and sys.flags.isolated and sys.flags.dont_write_bytecode
    own=Path(__file__).read_bytes();assert hashlib.sha256(own).hexdigest()==globals().get('BOOTSTRAP_SHA')
    journal=CONTROL/'native-aliases.json';assert not journal.exists()
    archive=CONTROL/'previous-entrypoints';archive.mkdir(mode=0o700)
    selection=json.loads((ROOT/'current/MANIFEST.json').read_text())
    current=(ROOT/'current').resolve(strict=True)
    state={'schema':1,'selected_release':str(current),'files':{},'native_profiles':{},'auth_changed':False}
    def save():
        temp=journal.with_suffix('.pending');temp.write_text(json.dumps(state,sort_keys=True,indent=2)+'\n');temp.chmod(0o600);os.replace(temp,journal)
    save()
    # Preserve the running Prof daemon's exact executable/helper/resource inodes.
    # All bytes must already equal the sealed common bundle before adoption.
    native=Path('/home/yeli/.codex-prof/packages/app-server-daemon/current').resolve(strict=True)
    bundle=current/selection['providers']['codex']['bundle']
    assert native.name=='0.169.0-x86_64-unknown-linux-musl'
    for source in native.rglob('*'):
        if source.is_symlink() or not source.is_file():continue
        dest=bundle/source.relative_to(native);entry=selection['files'][str(dest.relative_to(current))]
        assert sha(source)==sha(dest)==entry['sha256']
        assert source.stat().st_uid in {0,OWNER} and not source.stat().st_mode&0o022
    for source in native.rglob('*'):
        if source.is_symlink() or not source.is_file():continue
        dest=bundle/source.relative_to(native)
        os.chown(source,0,0);source.chmod(0o555 if source.stat().st_mode&0o111 else 0o444)
        if not os.path.samefile(source,dest):
            dest.parent.chmod(0o755)
            pending=dest.with_name('.adopt-'+secrets.token_hex(6));os.link(source,pending);os.replace(pending,dest)
            dest.parent.chmod(0o555)
    state['running_prof_code_inodes_preserved']=True;save()
    launch=ROOT/'launch';launch.mkdir(mode=0o755,exist_ok=True)
    for provider in selection['providers']:
        target=launch/provider
        assert not target.exists()
        text='''#!/bin/sh
set -eu
export DISABLE_AUTOUPDATER=1 COPILOT_AUTO_UPDATE=false OPENCODE_DISABLE_AUTOUPDATE=true AGY_CLI_DISABLE_AUTO_UPDATE=true
if [ "${1:-}" = update ] || [ "${1:-}" = upgrade ]; then
    exec /usr/local/bin/updateCLI-bcc
fi
'''
        if provider=='codex':
            text+='''if [ "${1:-}" = app-server ] && [ "${2:-}" = daemon ] && [ "${3:-}" = update ]; then
    exec /usr/local/bin/updateCLI-bcc
fi
'''
        text+='exec /opt/agent-clis/current/bin/'+provider+' "$@"\n'
        target.write_text(text);target.chmod(0o555)
    def alias(path,target):
        assert path.parent.is_dir() and path.parent.stat().st_uid in {0,OWNER}
        key=str(path);entry={'target':str(target),'before':None}
        if os.path.lexists(path):
            info=path.lstat();assert info.st_uid in {0,OWNER}
            if path.is_symlink():entry['before']={'kind':'symlink','target':os.readlink(path)}
            else:
                assert stat.S_ISREG(info.st_mode)
                entry['before']={'kind':'file','sha256':sha(path),'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
            entry['archive']=str(archive/str(len(state['files'])))
        state['files'][key]=entry;save()
        if 'archive' in entry:os.rename(path,entry['archive'])
        pending=path.with_name('.shared-cli-'+secrets.token_hex(6));pending.symlink_to(target);os.replace(pending,path)
        entry['bound']=True;save()
    for provider in selection['providers']:
        for directory in (Path('/home/yeli/.local/bin'),Path('/usr/local/bin'),NVM/'bin'):
            alias(directory/provider,launch/provider)
    if Path('/home/yeli/.opencode/bin').is_dir():alias(Path('/home/yeli/.opencode/bin/opencode'),launch/'opencode')
    alias(Path('/home/yeli/.local/bin/updateCLI'),Path('/usr/local/bin/updateCLI-bcc'))
    for profile in ('.codex','.codex-liz','.codex-prof'):
        root=Path('/home/yeli')/profile/'packages'
        for name in ('app-server-daemon','standalone'):
            path=root/name/'current'
            if path.exists():
                assert path.is_symlink()
                alias(path,ROOT/'current'/selection['providers']['codex']['bundle'])
        state['native_profiles'][profile]={'shared_code':True,'credentials_moved':False};save()
    state['complete']=True;save()
    print(json.dumps({'native_and_system_bound':True,'providers':list(selection['providers']),
                      'running_prof_code_inodes_preserved':True,'auth_changed':False,'journal':str(journal)}))


if __name__=='__main__':main()
