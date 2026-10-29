#!/usr/bin/env python3
"""Unprivileged exact-delta access repair on frozen v19; never installs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = '701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80'
MODULES = {'src/agentporter/' + name for name in (
    'client_policy.py', 'server.py', 'rest/routers/agents.py', 'rest/schemas.py',
    'agents/development.py', 'workspaces/bounded.py')}
PLAN = {'scripts/' + name: 'operator-plan/' + name for name in (
    'authorize-a7dev-project-delegation.py', 'verify-a7dev-project-access.py')}


def load(name, expected):
    path = ROOT / 'scripts' / (name + '.py')
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('Build helper changed: ' + name)
    result = types.ModuleType(name.replace('-', '_'))
    result.__file__ = str(path)
    exec(compile(body, str(path), 'exec'), result.__dict__)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'input-pins', 'output', 'extract-to', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise PermissionError('Unprivileged preparation with explicit immutable version required')
    os.umask(0o077)
    for path in (args.output, args.extract_to, args.report):
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
    overlay = load('prepare-development-overlay', '69bf234a1b8d1732daf2179823ab93a92a6a3a9f29e00ec1c4edd01b87c02ec0')
    canonical = load('prepare-closeout-candidate', 'eb36970fe8e734ef46a7b49ba12465ccaa5200634cc4eaa2e1acb98a62a170be')
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    pins = json.loads(args.input_pins.read_text())
    if set(pins) != MODULES | set(PLAN):
        raise ValueError('Only the six access modules and two inert operator scripts may change')
    inputs = {name: overlay.pinned_bytes(ROOT / name, digest) for name, digest in pins.items()}
    if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
        raise ValueError('Frozen v19 archive hash mismatch')
    with tempfile.TemporaryDirectory(prefix='a7dev-project-access-build-') as temporary:
        stage = Path(temporary) / 'stage'
        overlay.extract(installer, args.base, stage)
        release = stage / 'release'
        before = installer.bounded_json(stage / 'release-files.json')
        installer.verify_release(release, before)
        if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
            raise ValueError('Base changed during extraction')
        for source, body in inputs.items():
            target = release / PLAN.get(source, source)
            if target.exists():
                overlay.replace_file(target, body)
            else:
                mode = target.parent.stat().st_mode & 0o777
                target.parent.chmod(mode | 0o200)
                try:
                    target.write_bytes(body)
                    target.chmod(0o444)
                finally:
                    target.parent.chmod(mode)
        metadata = installer.bounded_json(stage / 'release-metadata.json')
        old_version = metadata['version']
        if old_version == args.version:
            raise ValueError('Changed payload requires a new immutable identity')
        prefix = '/opt/agentporter-development/versions/'
        old = (prefix + old_version).encode()
        new = (prefix + args.version).encode()
        relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        for name in relocations:
            body = (release / name).read_bytes()
            if old not in body:
                raise ValueError('Expected version relocation missing')
            overlay.replace_file(release / name, body.replace(old, new))
        runtime = (stage / 'runtime.json').read_bytes().replace(old, new)
        overlay.replace_file(stage / 'runtime.json', runtime)
        metadata['version'] = args.version
        overlay.replace_file(stage / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changes = sorted(name for name in set(before) | set(manifest) if before.get(name) != manifest.get(name))
        if set(changes) != MODULES | set(PLAN.values()) | relocations:
            raise ValueError('Unexpected payload delta: ' + repr(changes))
        overlay.replace_file(stage / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        archive = Path(temporary) / 'candidate.tgz'
        print('Packing exact project-access delta on immutable v19', flush=True)
        canonical.pack_canonical(builder, release, stage, archive, manifest)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        package = {str(path.relative_to(release / 'src/agentporter')): path.read_bytes()
                   for path in (release / 'src/agentporter').rglob('*')
                   if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
        fingerprint = hashlib.sha256()
        for name, body in sorted(package.items()):
            fingerprint.update(name.encode() + b'\0' + body + b'\0')
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
                  'version': args.version, 'base_sha256': BASE_SHA,
                  'fingerprint': fingerprint.hexdigest(), 'changed_release_files': changes,
                  'manifest_entries': len(manifest), 'source_pins': pins,
                  'runtime_delta': 'release path relocation only; owner policy helper applies reviewed project grants separately',
                  'installed': False, 'independently_reviewed': False, 'production_changed': False}
        archive.chmod(0o400)
        os.link(archive, args.output, follow_symlinks=False)
        with args.report.open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
