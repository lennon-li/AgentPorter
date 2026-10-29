#!/usr/bin/env python3
"""Prepare one inactive, source-pinned v17-r3 + Cranary acquisition candidate.

Unprivileged only. No installation, privileged reads, runtime/policy activation,
network access, model execution, data modification, or production changes.
Starts from the pinned v17-install-r3 archive, overlays exactly seven audited
source files from the current checkout, and includes only an inert v2 HTTPS
operator proposal. Existing destinations are never overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE_SHA = 'a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac'
BASE = REPO / 'review-artifacts/agentporter-v17-install-r3.tgz'
CHANGED = frozenset({
    'src/agentporter/action_policy.py',
    'src/agentporter/client_policy.py',
    'src/agentporter/https_download.py',
    'src/agentporter/rest/routers/exec.py',
    'src/agentporter/rest/schemas.py',
    'src/agentporter/scoped_https.py',
    'src/agentporter/server.py',
})
RELOCATIONS = frozenset({'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'})
POLICY_NAME = 'operator-plan/public-https.yaml.proposed'
POLICY_SHA = 'e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf'


def load(name: str, digest: str):
    path = REPO / 'scripts' / (name + '.py')
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != digest:
        raise ValueError('Pinned build helper differs: ' + name)
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'output', 'extract-to', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise PermissionError('Build must not execute as root')
    if not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise ValueError('Explicit immutable release version required')
    os.umask(0o077)
    for dest in (args.output, args.extract_to, args.report):
        if dest.exists() or dest.is_symlink():
            raise FileExistsError('Refusing existing output: ' + str(dest))

    pins = json.loads(args.manifest.read_text())
    if set(pins) != CHANGED or not all(isinstance(x, str) and re.fullmatch('[0-9a-f]{64}', x) for x in pins.values()):
        raise ValueError('Manifest must pin exactly the seven combined-source changes')
    original_pins = json.loads((REPO / 'docs/evidence/agentporter-v17-install-review-20261021/package-pins.json').read_text())
    actual = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (REPO / 'src/agentporter').rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    if {name for name in (set(actual) | set(original_pins)) if actual.get(name) != original_pins.get(name)} != CHANGED:
        raise ValueError('Additional unexpected source changes detected; stop')
    if any(actual[name] != pins[name] for name in pins):
        raise ValueError('Source changed since manifest generation')
    policy = (REPO / 'docs/examples/a7dev-cranary-acquisition-https.yaml').read_bytes()
    if hashlib.sha256(policy).hexdigest() != POLICY_SHA:
        raise ValueError('Exact proposed Cranary HTTPS policy changed')

    overlay = load('prepare-development-overlay',
                   'bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc')
    packer = load('prepare-closeout-candidate',
                  '1ce0f50ca4179901123975334c175b7d1cd3ca84c2c7d44ddfe2fd2f195d70fc')
    installer = overlay.helper('install-development-artifact')
    builder = overlay.helper('build-development-candidate')
    changes = {name: overlay.pinned_bytes(REPO / name, digest) for name, digest in pins.items()}

    with tempfile.TemporaryDirectory(prefix='agentporter-combined-build-') as scratch:
        tmp = Path(scratch)
        base = tmp / 'base.tgz'
        fd = os.open(BASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > installer.LIMIT:
                raise PermissionError('Frozen base archive has unsafe permissions/size')
            digest = hashlib.sha256()
            with base.open('xb') as out:
                while True:
                    chunk = os.read(fd, 1024**2)
                    if not chunk:
                        break
                    digest.update(chunk)
                    out.write(chunk)
            if digest.hexdigest() != BASE_SHA:
                raise ValueError('v17-r3 baseline SHA256 mismatch')
        finally:
            os.close(fd)
        print('Pinned v17-r3 base verified; extracting', flush=True)
        original = tmp / 'original'
        overlay.extract(installer, base, original)
        release = original / 'release'
        before = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, before)
        meta = installer.bounded_json(original / 'release-metadata.json')
        oldver = meta['version']
        oldpath = '/opt/agentporter-development/versions/' + oldver
        newpath = '/opt/agentporter-development/versions/' + args.version
        runtime_before = installer.bounded_json(original / 'runtime.json')
        if runtime_before.get('egress_policy') != 'provider_origin' or runtime_before.get('public_client_policy_required') is not True:
            raise ValueError('Base is not hardened v17')
        if runtime_before['workers']['wei']['model'] != 'opencode/glm-5.3-flash-free':
            raise ValueError('Wei free canonical model not preserved')
        runtime = json.loads(json.dumps(runtime_before).replace(oldpath, newpath))
        if runtime['production_relay_agents'] != ['liz', 'prof']:
            raise ValueError('Unexpected receiving relay admission')

        for name, body in changes.items():
            path = release / name
            if path.exists():
                overlay.replace_file(path, body)
            else:
                parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
                path.parent.chmod(parent_mode | 0o200)
                try:
                    path.write_bytes(body)
                    path.chmod(0o444)
                finally:
                    path.parent.chmod(parent_mode)
        for name in sorted(RELOCATIONS):
            path = release / name
            original_data = path.read_bytes()
            if oldpath.encode() not in original_data:
                raise ValueError('Expected release path missing in ' + name)
            overlay.replace_file(path, original_data.replace(oldpath.encode(), newpath.encode()))
        release.chmod(0o755)
        plan = release / 'operator-plan'
        old_mode = stat.S_IMODE(plan.stat().st_mode)
        plan.chmod(old_mode | 0o200)
        try:
            target = plan / 'public-https.yaml.proposed'
            if target.exists() or target.is_symlink():
                raise ValueError('Existing policy proposal in base')
            target.write_bytes(policy)
            target.chmod(0o444)
        finally:
            plan.chmod(old_mode)

        meta['version'] = args.version
        overlay.replace_file(original / 'runtime.json', json.dumps(runtime, sort_keys=True).encode() + b'\n')
        overlay.replace_file(original / 'release-metadata.json', json.dumps(meta, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changed = {name for name in set(before) | set(manifest) if before.get(name) != manifest.get(name)}
        expected = CHANGED | RELOCATIONS | {POLICY_NAME}
        if changed != expected:
            raise ValueError('Unexpected release delta: ' + str(sorted(changed.symmetric_difference(expected))))
        overlay.replace_file(original / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        archive = tmp / 'combined.tgz'
        print('Packing canonical combined artifact', flush=True)
        packer.pack_canonical(builder, release, original, archive, manifest)
        print('Extracting and checking every payload member', flush=True)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            if (original / name).read_bytes() != (args.extract_to / name).read_bytes():
                raise ValueError('Round-trip metadata mismatch: ' + name)
        archive.chmod(0o400)
        # Build scratch space may be on a separate filesystem from the review
        # checkout. Publish by exclusive copy instead of a cross-device link.
        with archive.open('rb') as source, args.output.open('xb') as destination:
            shutil.copyfileobj(source, destination, 1024**2)
            destination.flush()
            os.fsync(destination.fileno())
        args.output.chmod(0o400)
        verified_sha = builder.digest(args.output, installer.LIMIT)
        if verified_sha != builder.digest(archive, installer.LIMIT):
            raise ValueError('Copied archive digest differs from frozen build')
        report = {
            'version': args.version, 'archive': str(args.output),
            'sha256': verified_sha,
            'base_sha256': BASE_SHA, 'source_overlays': pins,
            'policy_sha256': POLICY_SHA, 'manifest_entries': len(manifest),
            'changed_release_files': sorted(changed),
            'package_source_sha256': {
                str(p.relative_to(release)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (release / 'src/agentporter').rglob('*')
                if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'
            },
            'runtime': runtime,
            'installed': False, 'independently_reviewed': False,
            'production_activated': False,
            'known_holds': ['Argie strict ACL permission unknown', 'owner installation authorization',
                            'installed cgroup/public-client acceptance and rollback',
                            'no training authorization for Cranary research'],
        }
        with args.report.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps({k: report[k] for k in ('version', 'sha256', 'manifest_entries', 'installed')}),
              flush=True)


if __name__ == '__main__':
    main()
