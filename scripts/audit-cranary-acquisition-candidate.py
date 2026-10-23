#!/usr/bin/env python3
"""Stdlib-only streaming comparison of the acquisition candidate with pinned v12.

Never extracts or executes payloads. An implementer-written cross-check,
not independent security clearance.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile

BASE_SHA = 'e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5'


def inspect(path, sha):
    with path.open('rb') as stream: assert hashlib.file_digest(stream, 'sha256').hexdigest() == sha
    seen = set(); files = {}; documents = {}; source = {}; total = 0
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            name = member.name; parts = PurePosixPath(name)
            assert not parts.is_absolute() and '..' not in parts.parts and posixpath.normpath(name) == name
            assert name not in seen; seen.add(name); assert len(seen) <= 100000
            assert parts.parts[0] in {'release', 'runtime.json', 'release-files.json', 'release-metadata.json'}
            assert member.isdir() or member.isreg() or member.issym()
            assert not member.issparse()
            if member.isdir(): continue
            if member.issym():
                assert name.startswith('release/') and not member.linkname.startswith('/')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                assert target.startswith('release/')
                files[name.removeprefix('release/')] = {'link': member.linkname}; continue
            assert 0 <= member.size <= 1024**3; total += member.size; assert total <= 8 * 1024**3
            stream = archive.extractfile(member); digest = hashlib.sha256(); body = bytearray()
            keep = name in {'runtime.json', 'release-files.json', 'release-metadata.json'} or name.startswith('release/src/agentporter/')
            remaining = member.size
            while remaining:
                block = stream.read(min(remaining, 1024**2)); assert block
                digest.update(block); remaining -= len(block)
                if keep: body.extend(block); assert len(body) <= 16 * 1024**2
            if name.startswith('release/'):
                assert not member.mode & 0o222
                files[name.removeprefix('release/')] = {'sha256': digest.hexdigest(), 'executable': bool(member.mode & 0o111)}
            if keep:
                if name.startswith('release/src/agentporter/'): source[name.removeprefix('release/')] = bytes(body)
                else: documents[name] = json.loads(body)
    assert files == documents['release-files.json']
    for name, entry in files.items():
        if 'link' not in entry: continue
        current = 'release/' + name
        for _ in range(40):
            changed = False; components = current.split('/')
            for index in range(1, len(components) + 1):
                prefix = '/'.join(components[:index]); record = files.get(prefix.removeprefix('release/'), {})
                if 'link' in record:
                    current = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), record['link'], *components[index:]))
                    assert current.startswith('release/'); changed = True; break
            if not changed: break
        else: raise ValueError('Symlink loop/depth')
    return files, documents, source, total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('artifact', 'base-artifact', 'source-manifest', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sha256', required=True); args = parser.parse_args()
    old, before, _, _ = inspect(args.base_artifact, BASE_SHA)
    files, docs, source, total = inspect(args.artifact, args.sha256)
    expected = {'src/agentporter/' + name for name in (
        'scoped_https.py', 'https_download.py', 'server.py', 'action_policy.py', 'rest/schemas.py', 'rest/routers/exec.py')}
    expected |= {'operator-plan/public-https.yaml.proposed', 'venv/pyvenv.cfg',
                 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
    changed = {name for name in set(old) | set(files) if old.get(name) != files.get(name)}
    assert changed == expected, 'Unrelated payload delta'
    version = docs['release-metadata.json']['version']; previous = before['release-metadata.json']['version']
    assert re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', version)
    meta = dict(before['release-metadata.json']); meta['version'] = version
    assert docs['release-metadata.json'] == meta
    prefix = '/opt/agentporter-development/versions/'
    runtime = json.loads(json.dumps(before['runtime.json']).replace(prefix + previous, prefix + version))
    runtime['workers']['wei'].update(provider='opencode', model='opencode/glm-5.3-flash-free',
        credentials={'.config/opencode/wei-key': '/var/lib/agentporter-dev/credentials/wei/.config/opencode/free-access'})
    assert docs['runtime.json'] == runtime, 'Runtime differs beyond version relocation and active Wei-free repair'
    pins = json.loads(args.source_manifest.read_text())
    assert pins == {name: hashlib.sha256(data).hexdigest() for name, data in source.items()}
    fingerprint = hashlib.sha256()
    for name, data in sorted(source.items()): fingerprint.update(name.removeprefix('src/agentporter/').encode() + b'\0' + data + b'\0')
    record = {'passed': True, 'archive_sha256': args.sha256, 'base_sha256': BASE_SHA,
        'manifest_entries': len(files), 'source_files': len(source), 'expanded_bytes': total,
        'package_fingerprint': fingerprint.hexdigest(), 'version': version, 'changed_release_files': sorted(changed),
        'other_worker_profiles_changed': False, 'production_changed': False,
        'installed': False, 'payload_executed': False, 'independently_reviewed': False}
    with args.report.open('x') as stream: json.dump(record, stream, indent=2); stream.write('\n')
    print(json.dumps(record))


if __name__ == '__main__': main()
