#!/usr/bin/env python3
"""Separate stdlib-only streaming artifact verifier. Never extracts or executes.

An automated cross-check, not independent human security clearance.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import tarfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--source-manifest',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    with args.artifact.open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==args.sha256,'Archive hash mismatch'
    seen=set(); actual={}; docs={}; package={}; total=0
    with tarfile.open(args.artifact,'r|gz') as archive:
        for item in archive:
            name=item.name; parts=PurePosixPath(name)
            assert not parts.is_absolute() and '..' not in parts.parts and posixpath.normpath(name)==name
            assert name not in seen,'Duplicate archive member';seen.add(name)
            assert parts.parts[0] in {'release','runtime.json','release-metadata.json','release-files.json'}
            assert item.isdir() or item.isreg() or item.issym(),'Special/hardlinked archive member'
            assert not item.issparse(),'Sparse archive member'
            if item.isdir():continue
            if item.issym():
                assert name.startswith('release/') and not item.linkname.startswith('/')
                target=posixpath.normpath(posixpath.join(posixpath.dirname(name),item.linkname))
                assert target.startswith('release/'),'Escaping archive symlink'
                actual[name.removeprefix('release/')]={'link':item.linkname}
                continue
            assert 0<=item.size<=1024**3,'Oversized member'
            total+=item.size;assert total<=8*1024**3,'Expansion limit'
            stream=archive.extractfile(item); digest=hashlib.sha256(); retained=bytearray()
            keep=(name in {'runtime.json','release-metadata.json','release-files.json',
                          'release/release-resource-admissions.json'} or name.startswith('release/src/agentporter/'))
            remaining=item.size
            while remaining:
                block=stream.read(min(1024**2,remaining));assert block,'Truncated member'
                remaining-=len(block);digest.update(block)
                if keep:
                    retained.extend(block);assert len(retained)<=16*1024**2,'Metadata bound'
            if name.startswith('release/'):
                actual[name.removeprefix('release/')]={'sha256':digest.hexdigest(),'executable':bool(item.mode&0o111)}
                assert not item.mode&0o222,'Mutable release payload'
            if keep:
                if name.startswith('release/src/agentporter/'):
                    package[name.removeprefix('release/src/agentporter/')]=bytes(retained)
                else:docs[name]=json.loads(retained)
    assert actual==docs['release-files.json'],'Payload/manifest mismatch'
    for name,entry in actual.items():
        if 'link' not in entry:continue
        current='release/'+name
        for _ in range(40):
            components=current.split('/');changed=False
            for index in range(1,len(components)+1):
                prefix='/'.join(components[:index]);record=actual.get(prefix.removeprefix('release/'),{})
                if 'link' in record:
                    current=posixpath.normpath(posixpath.join(posixpath.dirname(prefix),record['link'],*components[index:]))
                    assert current.startswith('release/'),'Symlink-chain escape';changed=True;break
            if not changed:break
        else:raise AssertionError('Symlink loop/depth')
    sources=json.loads(args.source_manifest.read_text())
    assert set(package)=={name.removeprefix('src/agentporter/') for name in sources}
    for name,digest in sources.items():
        assert hashlib.sha256(package[name.removeprefix('src/agentporter/')]).hexdigest()==digest
    fingerprint=hashlib.sha256()
    for name,data in sorted(package.items()):
        fingerprint.update(name.encode()+b'\0'+data+b'\0')
    runtime=docs['runtime.json'];wei=runtime['workers']['wei']
    assert runtime['egress_policy']=='provider_origin' and runtime['public_client_policy_required'] is True
    assert runtime['production_relay_agents']==['liz','prof']
    assert runtime['job_resources']=={'memory_bytes':4*1024**3,'pids':128,'cpu_quota_us':200000,'cpu_period_us':100000}
    assert wei['provider']=='opencode' and wei['model']=='opencode/glm-5.3-flash-free'
    assert wei['credentials']=={'.config/opencode/wei-key':'/var/lib/agentporter-dev/credentials/wei/.config/opencode/free-access'}
    admissions=docs['release/release-resource-admissions.json']
    assert hashlib.sha256(json.dumps(admissions,sort_keys=True).encode()).hexdigest()==docs['release-metadata.json']['resource_manifest_sha256']
    report={'passed':True,'archive_sha256':args.sha256,'payload_files':len(actual),'expanded_bytes':total,
            'package_fingerprint':fingerprint.hexdigest(),'source_files':len(package),
            'version':docs['release-metadata.json']['version'],'payload_executed':False,'independent_review_clearance':False}
    with args.report.open('x') as file:json.dump(report,file,indent=2);file.write('\n')
    print(json.dumps(report))


if __name__=='__main__':main()
