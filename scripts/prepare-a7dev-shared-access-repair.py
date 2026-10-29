#!/usr/bin/env python3
"""Prepare a narrowly pinned A7Dev ACL/writable-dispatch derivative, never deploy.

Preserves the exact active-runtime repair baseline except admitted modules,
schema/evidence inputs and release-path relocations. An explicit SHA-pinned
active runtime snapshot is preserved unchanged apart from relocation. Active runtime hash admission is mandatory before install.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import pwd
import stat

import yaml
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = '3f35441c59a392c6ca940915309fe26511eb17adfe09ba8a1b1674f95202c78d'
OLD_VERSION = '20261022T165047.488565Z'
MODULES = {'src/agentporter/' + name for name in (
    'tools/files.py', 'workspaces/paths.py', 'workspaces/shared_access.py',
    'workspaces/patching.py', 'client_policy.py', 'agents/development.py', 'rest/schemas.py')}
INERT = {
    'docs/agent7-asgard-actions.openapi.json': 'operator-plan/agent7-asgard-actions.openapi.json',
    'scripts/authorize-a7dev-project-delegation.py': 'operator-plan/authorize-a7dev-project-delegation.py',
    'scripts/authorize-a7dev-writable-delegation.py': 'operator-plan/authorize-a7dev-writable-delegation.py',
    'scripts/verify-a7dev-runtime-install-gate.py': 'operator-plan/verify-a7dev-runtime-install-gate.py',
    'tests/security/test_shared_workspace_access.py': 'operator-plan/validation/test_shared_workspace_access.py',
    'tests/security/test_writable_public_delegation.py': 'operator-plan/validation/test_writable_public_delegation.py',
    'tests/security/test_development_runtime.py': 'operator-plan/validation/test_development_runtime.py',
    'tests/unit/test_development_delegation.py': 'operator-plan/validation/test_development_delegation.py',
}


def load(name, expected):
    path = ROOT / 'scripts' / (name + '.py')
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != expected:
        raise ValueError('Build helper changed: ' + name)
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def overlay_file(overlay, path, body):
    if path.exists():
        overlay.replace_file(path, body)
        return
    # Create only directories within the already pinned release tree; freeze
    # restores their modes before packing. No installed paths are accessed.
    missing = []
    cursor = path.parent
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    mode = cursor.stat().st_mode & 0o777
    cursor.chmod(mode | 0o200)
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
    finally:
        cursor.chmod(mode)
    mode = path.parent.stat().st_mode & 0o777
    path.parent.chmod(mode | 0o200)
    try:
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(0o444)
    finally:
        path.parent.chmod(mode)



class RuntimeLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('Runtime YAML aliases are forbidden')
        return super().compose_node(parent, index)


def unique_runtime_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError('Runtime YAML has duplicate/nonstring keys')
        result[key] = loader.construct_object(value_node)
    return result


RuntimeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_runtime_mapping)


def parse_active_runtime(body):
    try:
        runtime = yaml.load(body, Loader=RuntimeLoader)
    except (yaml.YAMLError, UnicodeError) as error:
        # Parser diagnostics can contain private values; never surface them.
        raise ValueError('Invalid active runtime YAML') from None
    if (not isinstance(runtime, dict) or runtime.get('enabled') is not True
            or runtime.get('profile') != 'development' or runtime.get('gateway_user') != 'agentporter-dev'
            or type(runtime.get('production_uid')) is not int
            or runtime.get('production_uid') != pwd.getpwnam('yeli').pw_uid
            or not isinstance(runtime.get('workers'), dict)
            or set(runtime['workers']) != {'jax', 'liz', 'prof', 'ming', 'wei', 'phil', 'argie'}
            or not all(isinstance(row, dict) for row in runtime['workers'].values())):
        raise ValueError('Active runtime is not the approved development identity/profile')
    roots = runtime.get('allowed_workspace_roots')
    if (not isinstance(roots, list) or not 1 <= len(roots) <= 64
            or not all(isinstance(row, dict) and set(row) == {'path', 'writable'}
                       and isinstance(row['path'], str) and Path(row['path']).is_absolute()
                       and str(Path(row['path'])) == row['path'] and type(row['writable']) is bool
                       for row in roots)
            or len({row['path'] for row in roots}) != len(roots)):
        raise ValueError('Invalid active runtime workspace allowlist')
    try:
        json.dumps(runtime, allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError('Active runtime must contain finite JSON-compatible values') from None
    return runtime


def relocate_runtime(value, old_prefix, new_prefix):
    """Relocate string VALUES only, preserving every key, list and scalar type."""
    if isinstance(value, str):
        return value.replace(old_prefix + '/', new_prefix + '/')
    if isinstance(value, list):
        return [relocate_runtime(item, old_prefix, new_prefix) for item in value]
    if isinstance(value, dict):
        return {key: relocate_runtime(item, old_prefix, new_prefix) for key, item in value.items()}
    return value


def changed_leaves(before, after):
    if isinstance(before, dict) and isinstance(after, dict):
        return sum(changed_leaves(before[key], after[key]) if key in before and key in after else 1
                   for key in set(before) | set(after))
    if isinstance(before, list) and isinstance(after, list):
        return sum(changed_leaves(a, b) for a, b in zip(before, after)) + abs(len(before) - len(after))
    return int(type(before) is not type(after) or before != after)



def validate_baseline_metadata(metadata):
    if metadata.get('version') != OLD_VERSION or metadata.get('profile') != 'development':
        raise ValueError('Unexpected baseline release')


def validate_release_delta(before, after, relocations):
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    admitted = MODULES | set(relocations) | set(INERT.values())
    required = {'src/agentporter/workspaces/shared_access.py'} | set(relocations)
    if (not set(before) <= set(after) or not set(changed) <= admitted
            or not required <= set(changed)):
        raise ValueError('Unexpected release payload delta: ' + repr(changed))
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'input-pins', 'runtime', 'output', 'extract-to', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--runtime-sha256', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version) or args.version == OLD_VERSION:
        raise PermissionError('Unprivileged preparation with a fresh version required')
    os.umask(0o077)
    for path in (args.output, args.extract_to, args.report):
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
    overlay = load('prepare-development-overlay', 'bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc')
    canonical = load('prepare-closeout-candidate', '1ce0f50ca4179901123975334c175b7d1cd3ca84c2c7d44ddfe2fd2f195d70fc')
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    pins = json.loads(args.input_pins.read_text())
    if set(pins) != MODULES | set(INERT):
        raise ValueError('Exactly seven package modules plus declared inert schema/operator/validation inputs required')
    inputs = {name: overlay.pinned_bytes(ROOT / name, digest) for name, digest in pins.items()}
    if not re.fullmatch('[a-f0-9]{64}', args.runtime_sha256):
        raise ValueError('Explicit active runtime SHA256 pin required')
    if (not args.runtime.is_absolute() or args.runtime.lstat().st_mode & 0o077
            or not stat.S_ISDIR(args.runtime.parent.lstat().st_mode)
            or args.runtime.parent.lstat().st_uid != os.getuid()
            or args.runtime.parent.lstat().st_mode & 0o077):
        raise PermissionError('Active runtime snapshot requires private owner-only file and parent')
    runtime_bytes = overlay.pinned_bytes(args.runtime, args.runtime_sha256)
    runtime = parse_active_runtime(runtime_bytes)
    if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
        raise ValueError('Base archive differs from active reviewed acquisition release')
    old_prefix = '/opt/agentporter-development/versions/' + OLD_VERSION
    new_prefix = '/opt/agentporter-development/versions/' + args.version
    with tempfile.TemporaryDirectory(prefix='a7dev-shared-access-build-') as temporary:
        stage = Path(temporary) / 'stage'
        print('Extracting and strictly verifying exact active baseline', flush=True)
        overlay.extract(installer, args.base, stage)
        release = stage / 'release'
        before = installer.bounded_json(stage / 'release-files.json')
        installer.verify_release(release, before)
        if builder.digest(args.base, installer.LIMIT) != BASE_SHA:
            raise ValueError('Base archive changed during extraction')
        metadata = installer.bounded_json(stage / 'release-metadata.json')
        validate_baseline_metadata(metadata)
        archive_runtime = installer.bounded_json(stage / 'runtime.json')
        baseline_top_keys = sorted(key for key in set(archive_runtime) | set(runtime)
                                   if archive_runtime.get(key) != runtime.get(key))
        baseline_leaf_count = changed_leaves(archive_runtime, runtime)
        runtime_canonical = json.dumps(runtime, sort_keys=True, separators=(',', ':')).encode()
        for source, body in inputs.items():
            overlay_file(overlay, release / INERT.get(source, source), body)
        relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        for name in relocations:
            body = (release / name).read_bytes()
            if old_prefix.encode() not in body:
                raise ValueError('Missing expected Python release relocation')
            overlay.replace_file(release / name, body.replace(old_prefix.encode(), new_prefix.encode()))
        new_runtime = relocate_runtime(runtime, old_prefix, new_prefix)
        if relocate_runtime(new_runtime, new_prefix, old_prefix) != runtime:
            raise ValueError('Unexpected runtime policy change')
        runtime_output = json.dumps(new_runtime).encode() + b'\n'
        overlay.replace_file(stage / 'runtime.json', runtime_output)
        metadata['version'] = args.version
        overlay.replace_file(stage / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changed = validate_release_delta(before, manifest, relocations)
        overlay.replace_file(stage / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        archive = Path(temporary) / 'candidate.tgz'
        print('Packing canonical shared-access default ACL derivative', flush=True)
        canonical.pack_canonical(builder, release, stage, archive, manifest)
        print('Strictly extracting/verifying complete candidate', flush=True)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        for name in ('runtime.json', 'release-files.json', 'release-metadata.json'):
            if (args.extract_to / name).read_bytes() != (stage / name).read_bytes():
                raise ValueError('Candidate metadata roundtrip mismatch')
        fingerprint = hashlib.sha256()
        package = release / 'src/agentporter'
        for path in sorted(p for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'):
            fingerprint.update(str(path.relative_to(package)).encode() + b'\0' + path.read_bytes() + b'\0')
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
                  'version': args.version, 'base_sha256': BASE_SHA, 'base_version': OLD_VERSION,
                  'fingerprint': fingerprint.hexdigest(), 'changed_release_files': changed,
                  'changed_runtime_modules': sorted(MODULES.intersection(changed)), 'manifest_entries': len(manifest),
                  'source_pins': pins, 'inert_source_destinations': INERT,
                  'unchanged_release_entries': 'Exact matching SHA256, executable flags and symlink targets outside changed_release_files',
                  'active_runtime_snapshot_sha256': args.runtime_sha256,
                  'archive_vs_active_changed_top_level_keys': baseline_top_keys,
                  'archive_vs_active_changed_leaf_count': baseline_leaf_count,
                  'required_active_runtime_canonical_sha256': hashlib.sha256(runtime_canonical).hexdigest(),
                  'candidate_runtime_sha256': hashlib.sha256(runtime_output).hexdigest(),
                  'runtime_delta': 'Explicit SHA-pinned active snapshot preserved exactly except existing release paths relocated; active source still requires immediate preinstall hash gate',
                  'mandatory_preinstall_gate': 'Stop and quiesce A7Dev, run verify-a7dev-runtime-install-gate.py as agentporter-dev against base_version and required_active_runtime_canonical_sha256 immediately before install. If it differs, REFUSE install and rebuild against reviewed active runtime. Existing trusted installer does not enforce this gate itself.',
                  'verified': 'Real strict installer extraction/verify_release baseline and candidate, metadata roundtrip, exact changed file membership',
                  'payload_executed': False, 'installed': False, 'independently_reviewed': False,
                  'production_changed': False}
        archive.chmod(0o400)
        os.link(archive, args.output, follow_symlinks=False)
        with args.report.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
