#!/usr/bin/python3
"""Unprivileged builder/verifier for the Asgard production-owned worker release.

Retargets an already reviewed development-profile release (extracted artifact
layout: release/, runtime.json, release-metadata.json, release-files.json) to
the independent agentporter-worker identity and replaces its source with the
reviewed production-profile source. It never reads credentials or runs as root,
and never touches /opt or /var/lib.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

import yaml

UNIT = 'agentporter-worker.service'
ACCOUNT = 'agentporter-worker'
INSTALL = '/opt/agentporter-worker'
DATA = '/var/lib/agentporter-worker'
AGENTS = ['jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie']
ROOTS = {'Qman': '/home/operator/repos/Qman', 'm3-poc': '/home/operator/m3-agent-poc'}
VERSION = re.compile(r'\d{8}T\d{6}\.\d{6}Z')
OLD_MARKERS = (b'agentporter-development', b'agentporter-dev')
RETARGET_FILES = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth',
                  }
DIRECT_URL = 'venv/lib/python3.13/site-packages/agentporter-0.1.0.dev0.dist-info/direct_url.json'
DROPPED = ('operator-plan',)
TOP = ('release', 'runtime.json', 'release-metadata.json', 'release-files.json')


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def entries(root):
    result = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(dirs + files):
            path = Path(current) / name
            rel = str(path.relative_to(root))
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve(strict=True).is_relative_to(Path(root).resolve()):
                    raise ValueError(f'External symlink: {rel}')
                result[rel] = {'link': os.readlink(path)}
            elif stat.S_ISREG(info.st_mode):
                result[rel] = {'sha256': digest(path), 'executable': bool(info.st_mode & 0o111)}
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f'Special file: {rel}')
    return result


def worker_runtime(base, old_prefix, new_prefix):
    """Derive the worker runtime document; fail if any development identity remains."""
    runtime = copy.deepcopy(base)
    text = json.dumps(runtime)
    text = text.replace(old_prefix, new_prefix).replace('/var/lib/agentporter-dev/', DATA + '/')
    runtime = json.loads(text)
    runtime['gateway_user'] = ACCOUNT
    runtime['service_unit'] = UNIT
    runtime['production_relay_agents'] = list(AGENTS)
    runtime['allowed_workspace_roots'] = [{'path': p, 'writable': False} for p in ROOTS.values()]
    check_runtime(runtime, new_prefix)
    return runtime


def check_runtime(runtime, release_prefix):
    problems = []
    if runtime.get('profile') != 'development' or runtime.get('enabled') is not True:
        problems.append('profile')
    if runtime.get('gateway_user') != ACCOUNT or runtime.get('service_unit') != UNIT:
        problems.append('identity')
    if runtime.get('production_relay_agents') != AGENTS or set(runtime.get('workers', {})) != set(AGENTS):
        problems.append('agents')
    if runtime.get('allowed_workspace_roots') != [{'path': p, 'writable': False} for p in ROOTS.values()]:
        problems.append('workspace roots')
    if (runtime.get('network_enabled') is not True or runtime.get('egress_policy') != 'provider_origin'
            or runtime.get('public_client_policy_required') is not True):
        problems.append('egress or client policy')
    for key in ('shared_obsidian', 'shared_toolkit'):
        if not str(runtime.get(key, '')).startswith(release_prefix + '/shared/'):
            problems.append(key)
    for name, spec in runtime.get('workers', {}).items():
        for field in ('executable', 'code_mode_host'):
            if field in spec and not spec[field].startswith(release_prefix + '/cli/'):
                problems.append(f'{name}.{field}')
        for target in spec.get('credentials', {}).values():
            if not target.startswith(f'{DATA}/credentials/{name}/'):
                problems.append(f'{name} credential path')
    blob = json.dumps(runtime).encode()
    if any(marker in blob for marker in OLD_MARKERS):
        problems.append('development identity remains')
    if problems:
        raise ValueError('Worker runtime invalid: ' + ', '.join(sorted(set(problems))))


def config_bundle():
    """Non-secret worker config. Keys and credentials are installed by the owner.

    allow_execute is required by the launcher's delegation gate (agent_dispatch AND execute). Raw
    execution is not exposed: the public-client policy grants only read/git_read/dispatch, workspaces
    stay read-only with Git disabled, and the relay forbids writable or publishing dispatch.
    """
    workspaces = {'workspaces': {name: {'path': path, 'writable': False, 'allow_agent_dispatch': True,
                                        'allow_execute': True, 'allow_git': False, 'auto_discover': False}
                                 for name, path in ROOTS.items()}}
    policy = {'version': 1, 'workspaces': {name: {'path': path, 'operations': ['read', 'git_read', 'dispatch']}
                                           for name, path in ROOTS.items()}}
    scope = {'version': 1, 'workspaces': dict(ROOTS)}
    dump = lambda doc: yaml.safe_dump(doc, sort_keys=False).encode()
    return {'workspaces.yaml': dump(workspaces), 'public-client-policy.yaml': dump(policy),
            'delegation-relay-scope.yaml': dump(scope)}


def _writable(root):
    for current, dirs, files in os.walk(root, followlinks=False):
        os.chmod(current, 0o700)
        for name in files:
            p = Path(current) / name
            if not p.is_symlink():
                p.chmod(0o700 if p.stat().st_mode & 0o111 else 0o600)


def required_executables(runtime, release_prefix):
    """Release-relative paths that must be executable: bundled Python and every configured CLI."""
    required = {'python/bin/python3.13'}
    for spec in runtime.get('workers', {}).values():
        for field in ('executable', 'code_mode_host'):
            if field in spec:
                required.add(os.path.relpath(spec[field], release_prefix))
    return required


def check_executables(files, runtime, release_prefix):
    for rel in sorted(required_executables(runtime, release_prefix)):
        entry = files.get(rel)
        if entry is None or entry.get('executable') is not True:
            raise ValueError(f'Required executable is missing or not executable: {rel}')


def source_digest(src):
    h = hashlib.sha256()
    for rel, entry in sorted(entries(src).items()):
        h.update(f'{rel}\0{entry.get("sha256", entry.get("link"))}\n'.encode())
    return h.hexdigest()


def build(base, source, version, out):
    base, source, out = Path(base), Path(source), Path(out)
    if not VERSION.fullmatch(version):
        raise ValueError('Version must be YYYYMMDDTHHMMSS.ffffffZ')
    meta = json.loads((base / 'release-metadata.json').read_text())
    base_runtime = json.loads((base / 'runtime.json').read_text())
    expected = json.loads((base / 'release-files.json').read_text())
    if meta.get('profile') != 'development' or entries(base / 'release') != expected:
        raise ValueError('Base release does not match its reviewed manifest')
    old_prefix = f'/opt/agentporter-development/versions/{meta["version"]}'
    new_prefix = f'{INSTALL}/versions/{version}'
    if out.exists():
        raise FileExistsError('Output directory already exists')
    release = out / 'release'
    out.mkdir(parents=True, mode=0o700)
    shutil.copytree(base / 'release', release, symlinks=True,
                    ignore=lambda d, names: [n for n in names if Path(d) == base / 'release' and n in DROPPED + ('src',)])
    _writable(release)
    shutil.copytree(source / 'src', release / 'src', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for rel in RETARGET_FILES:
        path = release / rel
        data = path.read_bytes()
        if old_prefix.encode() in data:
            path.write_bytes(data.replace(old_prefix.encode(), new_prefix.encode()))
    # The base records an editable install of the development checkout; point it at the packaged source.
    (release / DIRECT_URL).write_text(json.dumps({'url': f'file://{new_prefix}/src', 'dir_info': {}}))
    for path in release.rglob('*'):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            if any(marker in data for marker in OLD_MARKERS):
                rel = str(path.relative_to(release))
                if not rel.startswith('src/'):
                    raise ValueError(f'Unreviewed development reference in {rel}')
    files = entries(release)
    runtime = worker_runtime(base_runtime, old_prefix, new_prefix)
    check_executables(files, runtime, new_prefix)
    metadata = {'profile': 'development', 'service': UNIT, 'version': version,
                'resource_manifest_sha256': meta.get('resource_manifest_sha256'),
                'base_version': meta['version'], 'source_tree_sha256': source_digest(release / 'src')}
    for name, doc in (('runtime.json', runtime), ('release-metadata.json', metadata), ('release-files.json', files)):
        (out / name).write_text(json.dumps(doc, sort_keys=True) + '\n')
    config = out / 'config'
    config.mkdir(mode=0o700)
    for name, data in config_bundle().items():
        (config / name).write_bytes(data)
    artifact = out / 'artifact.tgz'
    write_artifact(out, artifact)
    report = {'artifact_sha256': digest(artifact), 'version': version, 'files': len(files),
              'source_tree_sha256': metadata['source_tree_sha256'], 'base_version': meta['version'],
              'config_sha256': {n: hashlib.sha256(d).hexdigest() for n, d in config_bundle().items()}}
    (out / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=1) + '\n')
    return report


def write_artifact(out, artifact):
    """Deterministic archive: sorted members, zero timestamps/owners, normalized modes."""
    def add(archive, path, name):
        info = tarfile.TarInfo(name)
        st = path.lstat()
        info.mtime = info.uid = info.gid = 0
        info.uname = info.gname = ''
        if stat.S_ISDIR(st.st_mode):
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(info)
        elif stat.S_ISLNK(st.st_mode):
            info.type, info.mode, info.linkname = tarfile.SYMTYPE, 0o777, os.readlink(path)
            archive.addfile(info)
        else:
            info.size, info.mode = st.st_size, 0o755 if st.st_mode & 0o111 else 0o644
            with open(path, 'rb') as stream:
                archive.addfile(info, stream)

    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, compresslevel=6) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as archive:
            release = out / 'release'
            add(archive, release, 'release')
            for current, dirs, files in os.walk(release, followlinks=False):
                dirs.sort()
                for name in sorted(dirs + files):
                    path = Path(current) / name
                    if '__pycache__' in path.parts:
                        continue
                    add(archive, path, str(path.relative_to(out)))
            for name in TOP[1:]:
                add(archive, out / name, name)
    Path(artifact).write_bytes(raw.getvalue())


def verify(artifact, expected_sha256=None):
    """Re-derive every claim from the archive bytes only."""
    if expected_sha256 and digest(artifact) != expected_sha256:
        raise ValueError('Artifact digest differs from the approved SHA-256')
    with tempfile.TemporaryDirectory(prefix='asgard-worker-verify-') as tmp:
        root = Path(tmp)
        with tarfile.open(artifact, 'r:gz') as archive:
            names = set()
            for member in archive:
                p = Path(member.name)
                if (p.is_absolute() or '..' in p.parts or member.name in names or p.parts[0] not in TOP
                        or not (member.isdir() or member.isfile() or member.issym())):
                    raise ValueError(f'Unsafe archive member: {member.name}')
                names.add(member.name)
                if member.issym():
                    target = os.path.normpath(os.path.join(os.path.dirname(member.name), member.linkname))
                    if member.linkname.startswith('/') or not target.startswith('release/'):
                        raise ValueError('Symlink escapes release')
                    (root / member.name).parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(member.linkname, root / member.name)
                elif member.isdir():
                    (root / member.name).mkdir(parents=True, exist_ok=True)
                else:
                    target = root / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
        if not set(TOP) <= {n.split('/')[0] for n in names}:
            raise ValueError('Artifact metadata missing')
        meta = json.loads((root / 'release-metadata.json').read_text())
        runtime = json.loads((root / 'runtime.json').read_text())
        if (meta.get('profile') != 'development' or meta.get('service') != UNIT
                or not VERSION.fullmatch(meta.get('version', ''))):
            raise ValueError('Invalid worker release metadata')
        if entries(root / 'release') != json.loads((root / 'release-files.json').read_text()):
            raise ValueError('Release contents differ from manifest')
        check_runtime(runtime, f'{INSTALL}/versions/{meta["version"]}')
        check_executables(entries(root / 'release'), runtime, f'{INSTALL}/versions/{meta["version"]}')
        if source_digest(root / 'release/src') != meta['source_tree_sha256']:
            raise ValueError('Packaged source differs from recorded source digest')
        for path in (root / 'release').rglob('*'):
            if path.is_file() and not path.is_symlink():
                rel = str(path.relative_to(root / 'release'))
                data = path.read_bytes()
                if rel.startswith('src/'):
                    continue
                if any(m in data for m in OLD_MARKERS):
                    raise ValueError(f'Development identity remains in {rel}')
                if re.search(r'(auth\.json|\.credentials\.json|secrets\.env|\.key)$', rel):
                    raise ValueError(f'Credential-like file in release: {rel}')
        if 'service_unit' not in (root / 'release/src/agentporter/resources.py').read_text():
            raise ValueError('Packaged source lacks worker service identity support')
        return {'verified': True, 'version': meta['version'], 'artifact_sha256': digest(artifact),
                'files': len(json.loads((root / 'release-files.json').read_text()))}


def check_unit(text):
    """Review-time check of the proposed systemd unit text."""
    required = [f'User={ACCOUNT}', f'Group={ACCOUNT}', 'Conflicts=agentporter-development.service',
                'Delegate=cpu memory pids', 'DelegateSubgroup=supervisor', 'NoNewPrivileges=true',
                f'Environment=AGENTPORTER_CONFIG_DIR={DATA}/config', f'Environment=AGENTPORTER_STATE_DIR={DATA}/state',
                f'ExecStart={INSTALL}/current/venv/bin/python -I -m agentporter.cli serve '
                f'--config-dir {DATA}/config --host 127.0.0.1 --port 8876']
    lines = set(text.splitlines())
    missing = [line for line in required if line not in lines]
    if missing or re.search(r'agentporter-dev\b|/var/lib/agentporter-dev|/opt/agentporter-development', text):
        raise ValueError(f'Unit invalid: {missing or "development path present"}')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    b.add_argument('--base', required=True)
    b.add_argument('--source', required=True)
    b.add_argument('--version', required=True)
    b.add_argument('--out', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--artifact', required=True)
    v.add_argument('--sha256')
    u = sub.add_parser('check-unit')
    u.add_argument('unit')
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit('Run unprivileged')
    if args.command == 'build':
        result = build(args.base, args.source, args.version, args.out)
    elif args.command == 'verify':
        result = verify(args.artifact, args.sha256)
    else:
        result = {'unit_ok': check_unit(Path(args.unit).read_text())}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
