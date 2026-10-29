#!/usr/bin/env python3
"""Prepare a sealed, uncommitted production permission packet; no live mutations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprint(root):
    digest = hashlib.sha256()
    entries = []
    for path in root.rglob('*'):
        if '__pycache__' in path.parts or path.suffix == '.pyc': continue
        if path.is_symlink(): raise ValueError('Source symlinks are not accepted in a sealed packet')
        if path.is_file(): entries.append((path.relative_to(root).as_posix(), path.read_bytes()))
    for rel, data in sorted(entries):
        digest.update(rel.encode()); digest.update(b'\0'); digest.update(data); digest.update(b'\0')
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fuse-package', type=Path, required=True)
    parser.add_argument('--gateway-home', type=Path, required=True)
    args = parser.parse_args()
    if os.getuid() == 0: raise ValueError('Preparation must not run as root')
    output = args.output.resolve()
    if output.exists(): raise ValueError('Output already exists')
    output.mkdir(mode=0o700)
    shutil.copytree(args.source / 'src/agentporter', output / 'source/agentporter',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    scripts = ['install-production-workspace-policy.py', 'migrate-production-workspace-policy.py',
               'validate-production-workspace-writes.py', 'issue-production-approval.py']
    for category, names in [('scripts', scripts), ('examples', [
            'agentporter-workspace-views.service', 'agentporter-worker-workspace-views.service'])]:
        (output / category).mkdir()
        for name in names: shutil.copyfile(args.source / category / name, output / category / name)
    (output / 'dependencies').mkdir()
    shutil.copyfile(args.fuse_package, output / 'dependencies/fuse-overlayfs.deb')
    gateway = (args.gateway_home / '.local/share/agentporter/current').resolve(strict=True)
    worker = Path('/opt/agentporter-worker/current').resolve(strict=True)
    gateway_sites = list((gateway / 'venv/lib').glob('python*/site-packages/agentporter'))
    if len(gateway_sites) != 1: raise ValueError('Unexpected gateway package layout')
    package_fp = fingerprint(output / 'source/agentporter')
    version = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '.000000Z'
    artifact_id = 'workspace-policy-' + version.replace('.', '-') + '-' + package_fp[:12]
    files = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    manifest = {'version': 1, 'artifact_id': artifact_id, 'worker_version': version,
                'gateway_home': str(args.gateway_home), 'gateway_base': str(gateway),
                'worker_base': str(worker), 'gateway_fingerprint': fingerprint(gateway_sites[0]),
                'package_fingerprint': package_fp, 'files': files,
                'source_provenance': 'uncommitted source snapshot; no branch, commit or push'}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    for path in [output, *output.rglob('*')]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    print(json.dumps({'packet': str(output), 'manifest_sha256': sha(output / 'manifest.json'),
                      'installer_sha256': files['scripts/install-production-workspace-policy.py'],
                      'package_fingerprint': package_fp, 'artifact_id': artifact_id}, sort_keys=True))


if __name__ == '__main__': main()
