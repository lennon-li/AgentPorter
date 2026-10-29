#!/usr/bin/env python3
"""Create an unprivileged artifact-test harness with explicit local relocations.

Does not install a release or alter source payloads. Existing harnesses refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extracted',type=Path,required=True)
    parser.add_argument('--harness',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()==0:raise PermissionError('Unprivileged harness only')
    if any(p.exists() or p.is_symlink() for p in (args.harness,args.report)):
        raise FileExistsError('Harness/report must be new')
    repo=Path(__file__).resolve().parents[1];release=args.extracted/'release'
    version=json.loads((args.extracted/'release-metadata.json').read_text())['version']
    manifest=json.loads((args.extracted/'release-files.json').read_text())
    old=('/opt/agentporter-development/versions/'+version).encode();new=str(release).encode()
    changes={}
    for name in ['venv/pyvenv.cfg','venv/lib/python3.13/site-packages/agentporter_development.pth']:
        path=release/name;data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=manifest[name]['sha256'] or old not in data:
            raise ValueError('Expected unmodified artifact relocation file')
        parent_mode=path.parent.stat().st_mode&0o777;path.parent.chmod(parent_mode|0o200)
        try:
            path.chmod(0o644);path.write_bytes(data.replace(old,new));path.chmod(0o444)
        finally:path.parent.chmod(parent_mode)
        changes[name]={'before':hashlib.sha256(data).hexdigest(),'after':hashlib.sha256(path.read_bytes()).hexdigest()}
    args.harness.mkdir(mode=0o700)
    for name in ['tests','scripts']:
        shutil.copytree(repo/name,args.harness/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name in ['pyproject.toml','README.md']:shutil.copy2(repo/name,args.harness/name)
    (args.harness/'docs').mkdir()
    for name in ['agent7-asgard-actions.openapi.json','agent-roster-action-policy.md','deployment.md']:
        shutil.copy2(repo/'docs'/name,args.harness/'docs'/name)
    if (repo/'docs/examples/a7dev-cranary-acquisition-https.yaml').exists():
        (args.harness/'docs/examples').mkdir()
        shutil.copy2(repo/'docs/examples/a7dev-cranary-acquisition-https.yaml',args.harness/'docs/examples')
    if (repo/'examples').exists():shutil.copytree(repo/'examples',args.harness/'examples')
    (args.harness/'src').symlink_to(release/'src',target_is_directory=True)
    (args.harness/'.venv').symlink_to(release/'venv',target_is_directory=True)
    report={'harness':str(args.harness),'package_source':str(release/'src'),
        'allowed_local_relocations':changes,'installed':False,
        'pytest_addopts':'-o pythonpath='+str(release/'src')}
    with args.report.open('x') as file:json.dump(report,file,indent=2);file.write('\n')
    print(json.dumps(report))


if __name__=='__main__':main()
