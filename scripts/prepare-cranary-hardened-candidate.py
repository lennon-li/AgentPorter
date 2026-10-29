#!/usr/bin/env python3
"""Freeze v18 acquisition on exact v17-r3, with all v17 controls retained.

Unprivileged preparation only. No credential reads, root execution, service
changes, network requests or installation. Existing outputs are refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE_SHA = 'a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac'
CHANGED_MODULES = {'src/agentporter/' + name for name in (
    'action_policy.py', 'client_policy.py', 'https_download.py', 'rest/routers/exec.py',
    'rest/schemas.py', 'scoped_https.py', 'server.py')}
PLAN = {
    'docs/examples/a7dev-cranary-acquisition-https.yaml': 'operator-plan/public-https.yaml.proposed',
    'scripts/verify-a7dev-cranary-acquisition.py': 'operator-plan/verify-a7dev-cranary-acquisition.py',
    'scripts/verify-a7dev-cranary-https.py': 'operator-plan/verify-a7dev-cranary-https.py',
}


def load(name, sha):
    path = REPO / 'scripts' / (name + '.py'); data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha:raise ValueError('Changed build helper: ' + name)
    module = types.ModuleType(name.replace('-', '_'));module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'input-pins', 'output', 'extract-to', 'report'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--version', required=True);args = p.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise PermissionError('Unprivileged explicit-version preparation only')
    os.umask(0o077)
    for path in (args.output, args.extract_to, args.report):
        if path.exists() or path.is_symlink():raise FileExistsError(path)
    overlay = load('prepare-development-overlay', '69bf234a1b8d1732daf2179823ab93a92a6a3a9f29e00ec1c4edd01b87c02ec0')
    canonical = load('prepare-closeout-candidate', 'eb36970fe8e734ef46a7b49ba12465ccaa5200634cc4eaa2e1acb98a62a170be')
    builder = overlay.helper('build-development-candidate');installer = overlay.helper('install-development-artifact')
    pins = json.loads(args.input_pins.read_text())
    package_names = {str(path.relative_to(REPO)) for path in (REPO / 'src/agentporter').rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    if set(pins) != package_names | set(PLAN):raise ValueError('Exact package and operator-plan pins required')
    inputs = {name: overlay.pinned_bytes(REPO / name, sha) for name, sha in pins.items()}
    with tempfile.TemporaryDirectory(prefix='agentporter-cranary-v19-build-') as temporary:
        root = Path(temporary);frozen = root / 'base.tgz'
        fd = os.open(args.base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > installer.LIMIT:
                raise ValueError('Unsafe base archive')
            left = installer.LIMIT + 1; digest = hashlib.sha256()
            with frozen.open('xb') as target:
                while left:
                    data = os.read(fd, min(left, 1024**2))
                    if not data:break
                    left -= len(data);digest.update(data);target.write(data)
            if not left or digest.hexdigest() != BASE_SHA:raise ValueError('v17-r3 base hash differs')
        finally:os.close(fd)
        original = root / 'original';overlay.extract(installer, frozen, original)
        release = original / 'release';before = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, before)
        base_package = {name for name in before if name.startswith('src/agentporter/')}
        if package_names != base_package | {'src/agentporter/https_download.py'}:
            raise ValueError('Unexpected package inventory delta')
        actual_changed = {name for name in package_names if before.get(name, {}).get('sha256') != pins[name]}
        if actual_changed != CHANGED_MODULES:raise ValueError('Unexpected source delta against v17-r3')
        for name in sorted(CHANGED_MODULES | set(PLAN)):
            target = release / PLAN.get(name, name)
            if target.exists():overlay.replace_file(target, inputs[name])
            else:
                mode = target.parent.stat().st_mode & 0o777;target.parent.chmod(mode | 0o200)
                try:target.write_bytes(inputs[name]);target.chmod(0o444)
                finally:target.parent.chmod(mode)
        metadata = installer.bounded_json(original / 'release-metadata.json');previous = metadata['version']
        if previous == args.version:raise ValueError('New version identity required')
        prefix = '/opt/agentporter-development/versions/'
        old, new = (prefix + previous).encode(), (prefix + args.version).encode()
        runtime = (original / 'runtime.json').read_bytes().replace(old, new)
        relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        for name in relocations:
            data = (release / name).read_bytes()
            if old not in data:raise ValueError('Expected venv relocation missing')
            overlay.replace_file(release / name, data.replace(old, new))
        overlay.replace_file(original / 'runtime.json', runtime)
        metadata['version'] = args.version
        overlay.replace_file(original / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode()+b'\n')
        builder.freeze(release);manifest = builder.entries(release)
        changed = sorted(name for name in set(before) | set(manifest) if before.get(name) != manifest.get(name))
        if set(changed) != CHANGED_MODULES | set(PLAN.values()) | relocations:
            raise ValueError('Unexpected payload delta')
        overlay.replace_file(original / 'release-files.json', json.dumps(manifest, sort_keys=True).encode()+b'\n')
        print('Pack pinned v17-r3 plus seven acquisition modules and inert operator plan', flush=True)
        archive = root / 'candidate.tgz';canonical.pack_canonical(builder, release, original, archive, manifest)
        overlay.extract(installer, archive, args.extract_to);installer.verify_release(args.extract_to / 'release', manifest)
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            if (original / name).read_bytes() != (args.extract_to / name).read_bytes():raise ValueError('Metadata round-trip differs')
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
            'version': args.version, 'base_sha256': BASE_SHA, 'manifest_entries': len(manifest),
            'source_sha256': {name: pins[name] for name in package_names},
            'operator_plan_sha256': {PLAN[name]: pins[name] for name in PLAN},
            'changed_release_files': changed, 'runtime_delta': 'v17-r3 version relocation only',
            'v17_security_modules_preserved': True, 'wei_free_default_preserved': True,
            'installed': False, 'independently_reviewed': False, 'production_changed': False,
            'blockers': ['Strict Argie ACL compatibility', 'Independent review and explicit owner approval',
                         'Actual service-UID, resource and public acquisition acceptance']}
        archive.chmod(0o400);os.link(archive, args.output, follow_symlinks=False)
        with args.report.open('x') as stream:json.dump(report, stream, indent=2, sort_keys=True);stream.write('\n')
        print(json.dumps({key: report[key] for key in ('artifact','sha256','version','manifest_entries','installed')}))


if __name__ == '__main__':main()
