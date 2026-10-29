#!/usr/bin/env python3
"""Freeze a source-pinned derivative of reviewed v12, unprivileged and inactive.

Preserves existing archives/releases. No payload execution, credential reads,
installation, service changes, root commands or activation clearance.
"""
import argparse
import hashlib
import gzip
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import tarfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/tmp/agentporter-development-candidate-v12.tgz')
BASE_SHA = 'e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5'


def pack_canonical(builder,release,metadata,output,manifest):
    """Stable tree order, owners, times and gzip header for pinned inputs."""
    if builder.entries(release)!=manifest:raise ValueError('Payload changed before packing')
    builder.validate_packable_links(release,manifest)
    included=set()
    def normalize(item):
        item.uid=item.gid=0;item.uname=item.gname='';item.mtime=0;item.pax_headers={}
        return item
    def reviewed(item):
        relative=PurePosixPath(item.name).relative_to('release')
        if '__pycache__' in relative.parts:return None
        if relative.parts and not item.isdir():
            if str(relative) not in manifest:raise ValueError('Unlisted payload member')
            included.add(str(relative))
        return normalize(item)
    with output.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0,compresslevel=1) as zipped:
            with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT,dereference=False) as archive:
                archive.add(release,arcname='release',filter=reviewed)
                if included!=set(manifest):raise ValueError('Packed manifest mismatch')
                for name in ('runtime.json','release-metadata.json','release-files.json'):
                    archive.add(metadata/name,arcname=name,filter=normalize)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--extract-to', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z',args.version):
        raise PermissionError('Unprivileged build and explicit version required')
    os.umask(0o077)
    for path in (args.output,args.report,args.extract_to):
        if path.exists() or path.is_symlink(): raise FileExistsError(path)
    sources = json.loads(args.source_manifest.read_text())
    actual = {str(p.relative_to(REPO)) for p in (REPO/'src/agentporter').rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    if set(sources) != actual: raise ValueError('Exact package source manifest required')
    helper_path=REPO/'scripts/prepare-development-overlay.py'
    helper_bytes=helper_path.read_bytes()
    if hashlib.sha256(helper_bytes).hexdigest()!='69bf234a1b8d1732daf2179823ab93a92a6a3a9f29e00ec1c4edd01b87c02ec0':
        raise ValueError('Overlay helper changed')
    overlay=types.ModuleType('closeout_overlay');overlay.__file__=str(helper_path)
    exec(compile(helper_bytes,str(helper_path),'exec'),overlay.__dict__)
    payload={name:overlay.pinned_bytes(REPO/name,digest) for name,digest in sources.items()}
    builder=overlay.helper('build-development-candidate')
    installer=overlay.helper('install-development-artifact')
    print('Freeze reviewed base and verify exact manifest',flush=True)
    with tempfile.TemporaryDirectory(prefix='agentporter-closeout-build-') as temporary:
        root=Path(temporary);frozen=root/'base.tgz'
        fd=os.open(BASE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022 or info.st_size>installer.LIMIT:
                raise ValueError('Unsafe base archive')
            with os.fdopen(fd,'rb',closefd=False) as incoming,frozen.open('xb') as outgoing:
                shutil.copyfileobj(incoming,outgoing,1024**2)
        finally:os.close(fd)
        if builder.digest(frozen,installer.LIMIT)!=BASE_SHA:raise ValueError('Reviewed base hash differs')
        original=root/'original';overlay.extract(installer,frozen,original)
        release=original/'release';old=installer.bounded_json(original/'release-files.json')
        installer.verify_release(release,old)
        metadata=installer.bounded_json(original/'release-metadata.json')
        previous=metadata['version'];old_prefix='/opt/agentporter-development/versions/'+previous
        new_prefix='/opt/agentporter-development/versions/'+args.version
        runtime=json.loads(json.dumps(installer.bounded_json(original/'runtime.json')).replace(old_prefix,new_prefix))
        runtime.update(egress_policy='provider_origin', production_relay_agents=['liz','prof'],
            public_client_policy_required=True,
            job_resources={'memory_bytes':4*1024**3,'pids':128,'cpu_quota_us':200000,'cpu_period_us':100000})
        runtime['workers']['wei'].update(provider='opencode',model='opencode/glm-5.3-flash-free',
            credentials={'.config/opencode/wei-key':'/var/lib/agentporter-dev/credentials/wei/.config/opencode/free-access'})
        for name,content in payload.items():
            path=release/name
            if path.exists(): overlay.replace_file(path,content)
            else:
                parent_mode=stat.S_IMODE(path.parent.stat().st_mode);path.parent.chmod(parent_mode|0o200)
                try:path.write_bytes(content);path.chmod(0o444)
                finally:path.parent.chmod(parent_mode)
        for name in ('venv/pyvenv.cfg','venv/lib/python3.13/site-packages/agentporter_development.pth'):
            path=release/name;data=path.read_bytes()
            if old_prefix.encode() not in data:raise ValueError('Expected relocation missing')
            overlay.replace_file(path,data.replace(old_prefix.encode(),new_prefix.encode()))
        plan=release/'operator-plan';release.chmod(0o755);plan.mkdir()
        plan_files={}
        for name in ('a7dev-public-client-policy.yaml','a7dev-job-resources.conf'):
            data=(REPO/'docs/examples'/name).read_bytes();(plan/name).write_bytes(data)
            plan_files[name]=hashlib.sha256(data).hexdigest()
        metadata['version']=args.version
        overlay.replace_file(original/'runtime.json',json.dumps(runtime,sort_keys=True).encode()+b'\n')
        overlay.replace_file(original/'release-metadata.json',json.dumps(metadata,sort_keys=True).encode()+b'\n')
        builder.freeze(release);manifest=builder.entries(release)
        overlay.replace_file(original/'release-files.json',json.dumps(manifest,sort_keys=True).encode()+b'\n')
        archive=root/'candidate.tgz';print('Pack frozen candidate',flush=True)
        pack_canonical(builder,release,original,archive,manifest)
        print('Round-trip extraction and full payload verification',flush=True)
        overlay.extract(installer,archive,args.extract_to)
        installer.verify_release(args.extract_to/'release',manifest)
        for name in ('release-files.json','release-metadata.json','runtime.json'):
            if (original/name).read_bytes()!=(args.extract_to/name).read_bytes():raise ValueError('Metadata round trip mismatch')
        archive.chmod(0o400)
        report={'artifact':str(args.output),'sha256':builder.digest(archive,installer.LIMIT),
            'version':args.version,'base_sha256':BASE_SHA,'previous_version':previous,
            'source_sha256':sources,'manifest_entries':len(manifest),'operator_plan_sha256':plan_files,
            'changed_release_files':sorted(name for name in set(old)|set(manifest) if old.get(name)!=manifest.get(name)),
            'runtime':runtime,'resource_manifest_sha256':metadata['resource_manifest_sha256'],
            'extracted_payload':str(args.extract_to),'installed':False,'independently_reviewed':False,
            'production_activation_cleared':False,'canonical_encoding':True,
            'known_blockers':['Argie ACL semantics','cgroup/ingress owner setup and installed acceptance','independent review']}
        os.link(archive,args.output,follow_symlinks=False)
        with args.report.open('x') as file:json.dump(report,file,indent=2,sort_keys=True);file.write('\n')
        print(json.dumps({k:report[k] for k in ('artifact','sha256','version','manifest_entries','installed','independently_reviewed')}),flush=True)


if __name__=='__main__':main()
