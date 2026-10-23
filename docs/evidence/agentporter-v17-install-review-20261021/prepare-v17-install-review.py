#!/usr/bin/env python3
"""Unprivileged, exact three-module cancellation revision of frozen v17.

Never mixes later Cranary acquisition source into v17. Never installs, executes
payloads, reads credentials, or changes services. Existing outputs are refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE_SHA = 'acbc64e95e238a3d568035834b75949456064445af89110bc68ddf8d18c6c72f'
MODULES = {'src/agentporter/tools/jobs.py', 'src/agentporter/resources.py',
           'src/agentporter/sandbox/bubblewrap.py'}


def load(name, expected):
    path = REPO / 'scripts' / (name + '.py')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Preparation helper changed: ' + name)
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extract-to', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    import re
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise PermissionError('Unprivileged preparation with explicit immutable version only')
    os.umask(0o077)
    for path in (args.output, args.extract_to, args.report):
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
    pins = json.loads(args.source_manifest.read_text())
    if set(pins) != MODULES:
        raise ValueError('Only the three cancellation modules may change')
    overlay = load('prepare-development-overlay', 'bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc')
    canonical = load('prepare-closeout-candidate', '1ce0f50ca4179901123975334c175b7d1cd3ca84c2c7d44ddfe2fd2f195d70fc')
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    changes = {name: overlay.pinned_bytes(REPO / name, digest) for name, digest in pins.items()}
    with tempfile.TemporaryDirectory(prefix='agentporter-v17-review-build-') as temporary:
        root = Path(temporary)
        frozen = root / 'base.tgz'
        fd = os.open(args.base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > installer.LIMIT:
                raise ValueError('Unsafe base archive')
            remaining = installer.LIMIT + 1
            digest = hashlib.sha256()
            with frozen.open('xb') as outgoing:
                while remaining:
                    block = os.read(fd, min(1024**2, remaining))
                    if not block:
                        break
                    remaining -= len(block)
                    outgoing.write(block)
                    digest.update(block)
            if not remaining or digest.hexdigest() != BASE_SHA:
                raise ValueError('Frozen v17 base differs')
        finally:
            os.close(fd)
        original = root / 'original'
        overlay.extract(installer, frozen, original)
        release = original / 'release'
        before = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, before)
        metadata = installer.bounded_json(original / 'release-metadata.json')
        previous_version = metadata['version']
        if previous_version == args.version:
            raise ValueError('New payload requires a new release identity')
        old = '/opt/agentporter-development/versions/' + previous_version
        new = '/opt/agentporter-development/versions/' + args.version
        runtime = (original / 'runtime.json').read_bytes().replace(old.encode(), new.encode())
        for name, data in changes.items():
            overlay.replace_file(release / name, data)
        relocations = ('venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth')
        for name in relocations:
            data = (release / name).read_bytes()
            if old.encode() not in data:
                raise ValueError('Expected version relocation absent')
            overlay.replace_file(release / name, data.replace(old.encode(), new.encode()))
        metadata['version'] = args.version
        overlay.replace_file(original / 'runtime.json', runtime)
        overlay.replace_file(original / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode()+b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changed = sorted(name for name in set(before) | set(manifest) if before.get(name) != manifest.get(name))
        if set(changed) != MODULES | set(relocations):
            raise ValueError('Unexpected payload delta')
        overlay.replace_file(original / 'release-files.json', json.dumps(manifest, sort_keys=True).encode()+b'\n')
        archive = root / 'candidate.tgz'
        canonical.pack_canonical(builder, release, original, archive, manifest)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        for name in ('release-files.json', 'release-metadata.json', 'runtime.json'):
            if (original / name).read_bytes() != (args.extract_to / name).read_bytes():
                raise ValueError('Round-trip metadata differs')
        package = {str(path.relative_to(release)): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (release / 'src/agentporter').rglob('*')
                   if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
                  'version': args.version, 'base_sha256': BASE_SHA, 'source_sha256': package,
                  'manifest_entries': len(manifest), 'changed_release_files': changed,
                  'runtime_changes': 'version path relocation only; strict v17, Wei-free preserved',
                  'installed': False, 'independently_reviewed': False,
                  'known_blockers': ['Argie strict ACL semantics', 'independent review and owner approval',
                                     'actual installed cgroup/service-UID acceptance and rollback']}
        archive.chmod(0o400)
        os.link(archive, args.output, follow_symlinks=False)
        with args.report.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps({key: report[key] for key in ('artifact', 'sha256', 'version', 'manifest_entries', 'installed')}))


if __name__ == '__main__':
    main()
