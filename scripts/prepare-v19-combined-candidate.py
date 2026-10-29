#!/usr/bin/env python3
"""Unprivileged, pinned v17-r3 + Cranary v18 acquisition overlay. No activation."""
import argparse, hashlib, json, os, re, stat, tempfile, types
from pathlib import Path

REPO=Path(__file__).resolve().parents[1]
BASE_SHA='a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac'
SOURCES={
'src/agentporter/scoped_https.py':'027e2664519a208b6e3b605b93998019a08b32c7a6a37c07c54c7f588d44727b',
'src/agentporter/https_download.py':'4809e716c4747b573a843c052b356e62195335a315848ebd1e948ce4c6b1fc64',
'src/agentporter/action_policy.py':'77d48bf4d11a435f5d2a1603d7ee0881aa31aaf3fa4b7d004c582290100ce103',
'src/agentporter/rest/schemas.py':'4f22dbf82852b955965022804e3efba32c29406668beea6eb61e4176844c9119',
'src/agentporter/rest/routers/exec.py':'b53fbb13cc0188f824be0b83d669f514581a994621f4673e4dfe9109e9c58a14',
'src/agentporter/server.py':'8f8511abd711df6823bfafc1303161d747e7d168a5b713abf103fb213a31826c',
}
POLICY_SHA='e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf'
def helper(name,expected):
    path=REPO/'scripts'/(name+'.py')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Helper pin mismatch: '+name)
    mod=types.ModuleType(name.replace('-','_'));mod.__file__=str(path)
    exec(compile(raw,str(path),'exec'),mod.__dict__);return mod

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('base','output','extract_to','report'):parser.add_argument('--'+key.replace('_','-'),type=Path,required=True)
    parser.add_argument('--version',required=True)
    args=parser.parse_args()
    if os.geteuid()==0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z',args.version):raise PermissionError('Nonroot immutable build only')
    os.umask(0o077)
    for p in (args.output,args.extract_to,args.report):
        if p.exists() or p.is_symlink():raise FileExistsError(p)
    overlay=helper('prepare-development-overlay','bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc')
    canonical=helper('prepare-closeout-candidate','1ce0f50ca4179901123975334c175b7d1cd3ca84c2c7d44ddfe2fd2f195d70fc')
    builder=overlay.helper('build-development-candidate')
    installer=overlay.helper('install-development-artifact')
    with tempfile.TemporaryDirectory(prefix='agentporter-v19-merge-') as td:
        tmp=Path(td);frozen=tmp/'base.tgz'
        fd=os.open(args.base,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o022 or st.st_size>installer.LIMIT:raise ValueError('Unsafe frozen base')
            digest=hashlib.sha256()
            with frozen.open('xb') as dest:
                while chunk:=os.read(fd,1024**2):digest.update(chunk);dest.write(chunk)
            if digest.hexdigest()!=BASE_SHA:raise ValueError('Frozen r3 SHA256 differs')
        finally:os.close(fd)
        src=tmp/'source';overlay.extract(installer,frozen,src)
        release=src/'release';previous=installer.bounded_json(src/'release-files.json')
        installer.verify_release(release,previous)
        meta=installer.bounded_json(src/'release-metadata.json')
        runtime=installer.bounded_json(src/'runtime.json')
        old='/opt/agentporter-development/versions/'+meta['version']
        new='/opt/agentporter-development/versions/'+args.version
        for rel,expect in SOURCES.items():
            data=(REPO/rel).read_bytes()
            if hashlib.sha256(data).hexdigest()!=expect:raise ValueError('Pinned source changed: '+rel)
            target=release/rel
            if target.exists():overlay.replace_file(target,data)
            else:
                parent=target.parent;mode=parent.stat().st_mode&0o777;parent.chmod(mode|0o200)
                try:target.write_bytes(data);target.chmod(0o444)
                finally:parent.chmod(mode)
        plan=release/'operator-plan'
        policy=(REPO/'docs/examples/a7dev-cranary-acquisition-https.yaml').read_bytes()
        if hashlib.sha256(policy).hexdigest()!=POLICY_SHA:raise ValueError('Approved policy proposal changed')
        mode=plan.stat().st_mode&0o777;plan.chmod(mode|0o200)
        try:
            with (plan/'public-https.yaml.proposed').open('xb') as output:output.write(policy)
            (plan/'public-https.yaml.proposed').chmod(0o444)
        finally:plan.chmod(mode)
        for rel in ('venv/pyvenv.cfg','venv/lib/python3.13/site-packages/agentporter_development.pth'):
            target=release/rel;old_bytes=target.read_bytes()
            if old.encode() not in old_bytes:raise ValueError('Version source not found: '+rel)
            overlay.replace_file(target,old_bytes.replace(old.encode(),new.encode()))
        runtime_txt=json.dumps(runtime,sort_keys=True).replace(old,new)
        revised=json.loads(runtime_txt)
        if revised['egress_policy']!='provider_origin' or not revised['public_client_policy_required']:raise ValueError('Strict v17 runtime missing')
        if revised['workers']['wei']['model']!='opencode/glm-5.3-flash-free':raise ValueError('Wei route regressed')
        overlay.replace_file(src/'runtime.json',json.dumps(revised,sort_keys=True).encode()+b'\n')
        meta['version']=args.version
        overlay.replace_file(src/'release-metadata.json',json.dumps(meta,sort_keys=True).encode()+b'\n')
        builder.freeze(release);manifest=builder.entries(release)
        changed={n for n in set(manifest)|set(previous) if manifest.get(n)!=previous.get(n)}
        expected=set(SOURCES)|{'operator-plan/public-https.yaml.proposed','venv/pyvenv.cfg','venv/lib/python3.13/site-packages/agentporter_development.pth'}
        if changed!=expected:raise ValueError('Unreviewed release delta: '+repr(sorted(changed^expected)))
        overlay.replace_file(src/'release-files.json',json.dumps(manifest,sort_keys=True).encode()+b'\n')
        archive=tmp/'candidate.tgz';canonical.pack_canonical(builder,release,src,archive,manifest)
        overlay.extract(installer,archive,args.extract_to)
        installer.verify_release(args.extract_to/'release',manifest)
        for name in ('release-files.json','release-metadata.json','runtime.json'):
            if (src/name).read_bytes()!=(args.extract_to/name).read_bytes():raise ValueError('Round-trip metadata changed')
        archive.chmod(0o400);os.link(archive,args.output)
        pins={name:hashlib.sha256((release/name).read_bytes()).hexdigest() for name in manifest if name.startswith('src/agentporter/') and (release/name).is_file()}
        report=dict(version=args.version,archive=str(args.output),archive_sha256=builder.digest(archive,installer.LIMIT),base_sha256=BASE_SHA,manifest_entries=len(manifest),changed_payload_files=sorted(changed),source_sha256=pins,policy_sha256=POLICY_SHA,runtime=revised,installed=False,independently_reviewed=False,production_activated=False)
        with args.report.open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
        print(json.dumps({k:report[k] for k in ('version','archive','archive_sha256','manifest_entries','changed_payload_files','installed')},sort_keys=True))
if __name__=='__main__':main()
