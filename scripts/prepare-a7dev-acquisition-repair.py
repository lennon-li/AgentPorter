#!/usr/bin/env python3
"""Build only the reviewed acquisition/ownership delta; never install or activate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = 'c2924acec4e2a5bb15b36c41891929179f614c211a79a5a57f5b53e258d28566'
OLD_VERSION = '20261021T232414.837654Z'
RUNTIME_SHA = '1ead69fa8d365fe9e1a062ce1906180a6b8caec1d124cf01282efc8253a96ae7'
MODULES = {'src/agentporter/' + name for name in (
    'tools/system.py', 'server.py', 'sandbox/bubblewrap.py', 'tools/git.py',
    'https_download.py')}
VERIFIER = 'scripts/verify-a7dev-acquisition-repair.py'


def load(name, expected):
    path = ROOT / 'scripts' / (name + '.py')
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != expected:
        raise ValueError('Build helper changed: ' + name)
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'input-pins', 'runtime', 'output', 'extract-to', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise PermissionError('Unprivileged preparation with a fresh version required')
    os.umask(0o077)
    for path in (args.output, args.extract_to, args.report):
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
    overlay = load('prepare-development-overlay', '69bf234a1b8d1732daf2179823ab93a92a6a3a9f29e00ec1c4edd01b87c02ec0')
    canonical = load('prepare-closeout-candidate', 'eb36970fe8e734ef46a7b49ba12465ccaa5200634cc4eaa2e1acb98a62a170be')
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    pins = json.loads(args.input_pins.read_text())
    if set(pins) != MODULES | {VERIFIER}:
        raise ValueError('Exactly five package modules and one inert verifier are admitted')
    inputs = {name: overlay.pinned_bytes(ROOT / name, digest) for name, digest in pins.items()}
    runtime_bytes = overlay.pinned_bytes(args.runtime, RUNTIME_SHA)
    import yaml
    runtime = yaml.safe_load(runtime_bytes)
    if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
        raise ValueError('Base archive differs from active reviewed access release')
    old_prefix = '/opt/agentporter-development/versions/' + OLD_VERSION
    new_prefix = '/opt/agentporter-development/versions/' + args.version
    with tempfile.TemporaryDirectory(prefix='a7dev-acquisition-repair-build-') as temporary:
        stage = Path(temporary) / 'stage'
        print('Extracting and verifying exact existing release', flush=True)
        overlay.extract(installer, args.base, stage)
        release = stage / 'release'
        before = installer.bounded_json(stage / 'release-files.json')
        installer.verify_release(release, before)
        if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
            raise ValueError('Base archive changed during extraction')
        metadata = installer.bounded_json(stage / 'release-metadata.json')
        if metadata['version'] != OLD_VERSION or args.version == OLD_VERSION:
            raise ValueError('Unexpected base or reused release version')
        for source, body in inputs.items():
            destination = 'operator-plan/verify-a7dev-acquisition-repair.py' if source == VERIFIER else source
            target = release / destination
            if target.exists():
                overlay.replace_file(target, body)
            else:
                mode = target.parent.stat().st_mode & 0o777
                target.parent.chmod(mode | 0o200)
                try:
                    with target.open('xb') as stream:
                        stream.write(body)
                    target.chmod(0o444)
                finally:
                    target.parent.chmod(mode)
        relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        for name in relocations:
            body = (release / name).read_bytes()
            if old_prefix.encode() not in body:
                raise ValueError('Missing expected Python release relocation')
            overlay.replace_file(release / name, body.replace(old_prefix.encode(), new_prefix.encode()))
        new_runtime = json.loads(json.dumps(runtime).replace(old_prefix + '/', new_prefix + '/'))
        # Only relocation of existing configured paths; all 41 project grants,
        # workers, credentials paths, models and egress/resource policy survive.
        if json.loads(json.dumps(new_runtime).replace(new_prefix + '/', old_prefix + '/')) != runtime:
            raise ValueError('Unexpected runtime change')
        overlay.replace_file(stage / 'runtime.json', json.dumps(new_runtime).encode() + b'\n')
        metadata['version'] = args.version
        overlay.replace_file(stage / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changed = sorted(name for name in set(before) | set(manifest) if before.get(name) != manifest.get(name))
        if set(changed) != MODULES | relocations | {'operator-plan/verify-a7dev-acquisition-repair.py'}:
            raise ValueError('Unexpected release payload delta: ' + repr(changed))
        overlay.replace_file(stage / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        archive = Path(temporary) / 'candidate.tgz'
        print('Packing exact acquisition/ownership repair', flush=True)
        canonical.pack_canonical(builder, release, stage, archive, manifest)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        fingerprint = hashlib.sha256()
        package = release / 'src/agentporter'
        for path in sorted(p for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'):
            fingerprint.update(str(path.relative_to(package)).encode() + b'\0' + path.read_bytes() + b'\0')
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
                  'version': args.version, 'base_sha256': BASE_SHA, 'fingerprint': fingerprint.hexdigest(),
                  'changed_release_files': changed, 'manifest_entries': len(manifest), 'source_pins': pins,
                  'old_runtime_sha256': RUNTIME_SHA,
                  'installed_runtime_sha256': hashlib.sha256((stage / 'runtime.json').read_bytes()).hexdigest(),
                  'runtime_delta': 'Active reviewed runtime, release paths relocated only',
                  'installed': False, 'independently_reviewed': False, 'production_changed': False}
        archive.chmod(0o400)
        os.link(archive, args.output, follow_symlinks=False)
        with args.report.open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
