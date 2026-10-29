#!/usr/bin/python3
"""Build an inspectable A7Dev artifact as operator. Never run this under sudo.

--inventory creates a candidate admission manifest, not an authorization.
The independent reviewer must inspect that manifest and the frozen artifact.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[1]
CANONICAL = Path('/home/operator/repos/obsidian')
MOUNT = '/opt/agentporter/tools'
INSTALL = Path('/opt/agentporter-development')
PACKAGES = {
    'codegraph': '/home/operator/.npm-global/lib/node_modules/@colbymchenry/codegraph/node_modules/@colbymchenry/codegraph-linux-x64',
    'repomix': '/home/operator/.npm-global/lib/node_modules/repomix',
    'npm': '/home/operator/.nvm/versions/node/v24.15.0/lib/node_modules/npm',
    'quarto': '/home/operator/.local/quarto-1.5.56',
    'nox': '/home/operator/.local/share/uv/tools/nox/lib/python3.12/site-packages',
    'tox': '/home/operator/.local/share/uv/tools/tox/lib/python3.12/site-packages',
    'tldr': '/tmp/agentporter-tldr-runtime/node_modules',
    'Rscript': '/etc/R',
}


def digest(path, max_bytes=1024**3):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError(f'Not a bounded regular resource: {path}')
        checksum = hashlib.sha256()
        remaining = max_bytes + 1
        while remaining:
            data = os.read(fd, min(1024**2, remaining))
            if not data:
                break
            checksum.update(data)
            remaining -= len(data)
        if not remaining:
            raise ValueError(f'Resource exceeded read bound: {path}')
        result = checksum.hexdigest()
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError(f'Resource changed while hashing: {path}')
        return result
    finally:
        os.close(fd)


def entries(root):
    """Exact package file set; links are recorded, not dereferenced."""
    result = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(dirs + files):
            path = Path(current) / name
            rel = str(path.relative_to(root))
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(Path(root).resolve()):
                    raise ValueError(f'External package symlink: {path}')
                result[rel] = {'link': os.readlink(path)}
            elif stat.S_ISREG(info.st_mode):
                result[rel] = {'sha256': digest(path), 'executable': bool(info.st_mode & 0o111)}
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f'Special package file: {path}')
    return result


def inventory():
    shared = {}
    omitted = []
    for scope in ('AgentSystem/agent-memory/skills', 'AgentSystem/agent-memory/boot',
                  'AgentSystem/agent-memory/policies', 'AgentSystem/agent-memory/loaders',
                  'Toolbox/claude-skills'):
        for path in sorted((CANONICAL / scope).rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(CANONICAL)
            if any(p.startswith('.') or p.startswith('__') for p in rel.parts):
                continue
            # Operational instructions only. Project/export configuration and
            # executable loaders are deliberately not published as skill data.
            if path.suffix != '.md':
                continue
            if (not path.stat().st_mode & 0o004 or
                    any(p.stat().st_mode & 0o005 != 0o005 for p in path.parents if p != CANONICAL and p.is_relative_to(CANONICAL))):
                omitted.append(str(rel))
                continue
            shared[str(rel)] = digest(path)
    for rel in ('tools/agent-tool-policy.json', 'tools/AGENT_TOOL_HANDOFF.md', 'tools/bin/run-quiet'):
        shared[rel] = digest(CANONICAL / rel)
    policy = json.loads((CANONICAL / 'tools/agent-tool-policy.json').read_text())
    tools = {}
    for name in policy['tools']['required']:
        path = shutil.which(name)
        if path:
            path = Path(path).resolve(strict=True)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                signature = os.read(fd, 4) if stat.S_ISREG(os.fstat(fd).st_mode) else b''
            finally:
                os.close(fd)
            if signature == b'\x7fELF' or name == 'run-quiet':
                tools[name] = {'source': str(path), 'sha256': digest(path),
                               'provenance': 'Existing canonical local installation; exact digest admitted for review, upstream provenance not independently attested'}
    tools['run-quiet'] = {'source': str(CANONICAL / 'tools/bin/run-quiet'),
                          'sha256': shared['tools/bin/run-quiet'], 'provenance': 'Canonical first-party Obsidian tool'}
    packages = {name: {'source': source, 'files': entries(Path(source)),
                        'provenance': 'Existing named package installation with bundled dependencies; exact file set for review'}
                for name, source in PACKAGES.items() if Path(source).is_dir()}
    import yaml
    runtime = yaml.safe_load(Path('/tmp/agentporter-development-asgard/config/development-runtime.yaml').read_text())
    workers = {}
    for name, spec in runtime['workers'].items():
        source = Path(spec['executable']).resolve(strict=True)
        if name == 'phil':
            source = Path('/home/operator/.nvm/versions/node/v24.15.0/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot')
        files = {'executable': {'source': str(source), 'sha256': digest(source)}}
        if name in {'jax', 'liz', 'prof'}:
            helper = source.with_name('codex-code-mode-host')
            files['code_mode_host'] = {'source': str(helper), 'sha256': digest(helper)}
        workers[name] = files
    production_config = yaml.safe_load(Path('/home/operator/.config/agentporter/config.yaml').read_text())
    approved_services = {'parallel_search': production_config.get('parallel_search', {}).get('enabled') is True}
    return {'schema': 1, 'shared_files': shared, 'omitted_private_resources': omitted,
            'tools': tools, 'packages': packages,
            'worker_executables': workers,
            'approved_services': approved_services,
            'codify': {'state': 'missing', 'reason': 'No executable in canonical PATH; not assumed installed'},
            'tldr': {'state': 'missing', 'reason': 'Not installed in canonical PATH or named package store'}}


def freeze(root):
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        Path(current).chmod(0o555)


def copy_package(admission, destination):
    source = Path(admission['source'])
    if entries(source) != admission['files']:
        raise ValueError(f'Package changed since admission: {source}')
    shutil.copytree(source, destination, symlinks=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    if entries(destination) != admission['files']:
        raise ValueError(f'Package copy does not match admission: {source}')


def package_tools(release, admissions):
    toolkit = release / 'shared/toolkit'
    manifest_path = toolkit / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    wrappers = {
        'codegraph': f'exec {MOUNT}/packages/codegraph/bin/codegraph "$@"',
        'repomix': f'exec /usr/bin/node {MOUNT}/packages/repomix/bin/repomix.cjs "$@"',
        'npm': f'exec /usr/bin/node {MOUNT}/packages/npm/bin/npm-cli.js "$@"',
        'quarto': f'exec {MOUNT}/packages/quarto/bin/quarto "$@"',
        'tldr': f'export NODE_PATH={MOUNT}/packages/tldr\nexec /usr/bin/node {MOUNT}/packages/tldr/tldr/bin/tldr "$@"',
        'Rscript': 'exec /usr/bin/Rscript "$@"',
    }
    for name in ('nox', 'tox'):
        wrappers[name] = (f'exec /usr/bin/python3 -I -c \'import sys; '
                          f'sys.path.insert(0,"{MOUNT}/packages/{name}"); '
                          f'import runpy; runpy.run_module("{name}",run_name="__main__")\' "$@"')
    for name, admission in admissions.get('packages', {}).items():
        if name not in wrappers:
            raise ValueError('Unknown package admission')
        copy_package(admission, toolkit / 'packages' / name)
        target = toolkit / 'bin' / name
        target.write_text('#!/bin/sh\n' + wrappers[name] + '\n')
        target.chmod(0o555)
        manifest['bundled_scripts'][name] = digest(target)
        if name in manifest['not_bundled']:
            manifest['not_bundled'].remove(name)
    manifest['package_admissions'] = admissions.get('packages', {})
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')


def validate_packable_links(release, expected):
    """Reject links whose resolution needs an omitted cache directory."""
    root = release.resolve(strict=True)
    for name, entry in expected.items():
        if 'link' not in entry:
            continue
        target = (release / name).resolve(strict=True)
        relative = target.relative_to(root)
        parts = Path(entry['link']).parts
        # Check raw components too: normpath/resolve erases cache/../, although
        # the kernel still needs that cache directory to follow the link.
        cache_traversal = any(part == '__pycache__' and index < len(parts) - 1
                              for index, part in enumerate(parts))
        if parts and parts[-1] == '__pycache__' and ((release / name).parent / entry['link']).is_dir():
            # A cache-named directory symlink is itself excluded by entries(),
            # even when its final resolved directory has an ordinary name.
            cache_traversal = True
        target_omitted = ('__pycache__' in relative.parts if target.is_dir()
                          else str(relative) not in expected)
        if cache_traversal or target_omitted:
            raise ValueError(f'Artifact symlink depends on omitted cache contents: {name}')


def write_artifact(release, metadata_directory, output):
    """Pack the exact reviewed file set, excluding unadmitted bytecode caches.

    entries() intentionally excludes __pycache__ directories. Applying that
    same boundary here prevents tar's recursive traversal from adding files
    which the installer must reject. Other unlisted files fail closed.
    """
    expected = json.loads((metadata_directory / 'release-files.json').read_text())
    if entries(release) != expected:
        raise ValueError('Release differs from reviewed manifest before packing')
    validate_packable_links(release, expected)
    included = set()

    def reviewed_member(item):
        relative = PurePosixPath(item.name).relative_to('release')
        if not relative.parts:
            return item
        name = str(relative)
        if item.isdir():
            return None if '__pycache__' in relative.parts else item
        if name not in expected:
            # A symlink to a cache directory is omitted by os.walk's directory
            # filtering too. A regular file named __pycache__ remains admitted.
            if ('__pycache__' in relative.parts[:-1] or
                    relative.name == '__pycache__' and (release / name).is_dir()):
                return None
            raise ValueError(f'Unlisted artifact member: {name}')
        included.add(name)
        return item

    with tarfile.open(output, 'w:gz', dereference=False, compresslevel=1) as archive:
        archive.add(release, arcname='release', filter=reviewed_member)
        if included != set(expected):
            raise ValueError('Artifact file set differs from reviewed manifest')
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            archive.add(metadata_directory / name, arcname=name)


def build(admissions, output):
    spec = importlib.util.spec_from_file_location('development_provision', REPO / 'scripts/provision-development-runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import yaml
    runtime = yaml.safe_load((module.STAGE / 'development-runtime.yaml').read_text())
    workspaces = yaml.safe_load((module.STAGE / 'workspaces.yaml').read_text())
    runtime['parallel_search_enabled'] = admissions.get('approved_services', {}).get('parallel_search') is True
    version = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    final = INSTALL / 'versions' / version
    with tempfile.TemporaryDirectory(prefix='agentporter-candidate-', dir='/tmp') as directory:
        base = Path(directory)
        module.INSTALL = base / 'install'
        module.immutable_tree = lambda root: None  # root ownership belongs ONLY to the installer
        release, runtime = module.snapshot(runtime, (REPO / '.venv/bin/python').resolve().parent.parent,
                                            version, approvals=admissions, workspaces=workspaces)
        if set(admissions.get('worker_executables', {})) != set(runtime['workers']):
            raise ValueError('Every named worker needs an executable admission')
        for name, worker in runtime['workers'].items():
            for field in ('executable', 'code_mode_host'):
                if field in worker:
                    expected = admissions['worker_executables'][name].get(field, {})
                    if digest(worker[field]) != expected.get('sha256'):
                        raise ValueError(f'Worker executable differs from admitted digest: {name}/{field}')
        package_tools(release, admissions)
        # References must describe the immutable installed location, not staging.
        runtime = json.loads(json.dumps(runtime).replace(str(release), str(final)))
        for path in (release / 'venv/pyvenv.cfg', release / 'venv/lib/python3.13/site-packages/agentporter_development.pth'):
            path.write_text(path.read_text().replace(str(release), str(final)))
        (base / 'runtime.json').write_text(json.dumps(runtime, sort_keys=True) + '\n')
        (base / 'release-metadata.json').write_text(json.dumps({'version': version, 'profile': 'development',
            'resource_manifest_sha256': hashlib.sha256(json.dumps(admissions, sort_keys=True).encode()).hexdigest()}) + '\n')
        (release / 'release-resource-admissions.json').write_text(json.dumps(admissions, sort_keys=True) + '\n')
        # Freeze before hashing/tarring. No worker or service runs these files yet.
        freeze(release)
        (base / 'release-files.json').write_text(json.dumps(entries(release), sort_keys=True) + '\n')
        write_artifact(release, base, output)
        print(json.dumps({'artifact': str(output), 'sha256': digest(output, 8 * 1024**3), 'version': version,
                          'state': 'candidate; independent review and privileged authorization required'}))


def main():
    if os.geteuid() == 0:
        raise SystemExit('Never execute mutable candidate builder as root')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--admissions', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.inventory:
        args.inventory.write_text(json.dumps(inventory(), indent=2, sort_keys=True) + '\n')
    elif args.admissions and args.output:
        if args.output.exists():
            parser.error('Refusing to overwrite an existing artifact')
        build(json.loads(args.admissions.read_text()), args.output)
    else:
        parser.error('Choose --inventory PATH or --admissions PATH --output PATH')


if __name__ == '__main__':
    main()
