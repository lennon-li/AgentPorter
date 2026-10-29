#!/usr/bin/python3
"""Build the reviewed v9 derivative from frozen v8, without running payloads.

Only two pinned Python sources and the admitted runtime/version relocation
documents may change. No providers, credentials, installed paths or services
are accessed. The output is a new immutable candidate requiring admission.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/tmp/agentporter-development-candidate-v8.tgz')
BASE_SHA256 = 'e9b9919f27b9a01e11b8f1274811e035a7d85ecbb809474e83eb6a0a7a89d929'
OUTPUT = Path('/tmp/agentporter-development-candidate-v9.tgz')
REPORT = Path('/tmp/agentporter-development-candidate-v9-review.json')
SOURCES = {
    'src/agentporter/agents/development.py': '6b09a3a870f6b7c7ab5859397353a59389864ea266d35f7555dafc4a76958be3',
    'src/agentporter/agents/broker.py': '7e7619504a38b895974f88a3a15e2f134ede85872162b94ddc9744bc976be32f',
}
HELPERS = {
    'build-development-candidate': 'c96e3eb28c55efa96c46e27167dabf3adf69829199508e9e8aff178a01cb2445',
    'provision-development-runtime': 'dca337645eb893b1fb347038af8dbd10f6ea56b7f5ceba45469165d18518c016',
    'install-development-artifact': '84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58',
}


def pinned_bytes(path, expected, bound=1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_size > bound:
            raise ValueError('Unsafe reviewed source')
        data = os.read(fd, bound + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size or
                (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                hashlib.sha256(data).hexdigest() != expected):
            raise ValueError(f'Reviewed source changed: {path.name}')
        return data
    finally:
        os.close(fd)


def helper(name):
    path = REPO / 'scripts' / (name + '.py')
    source = pinned_bytes(path, HELPERS[name])
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def replace_file(path, content):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Overlay target must be regular')
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    path.parent.chmod(parent_mode | 0o200)
    temporary = path.with_name('.overlay-' + secrets.token_hex(16))
    try:
        with temporary.open('xb') as stream:
            stream.write(content)
        temporary.chmod(stat.S_IMODE(info.st_mode))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
        path.parent.chmod(parent_mode)


def extract(installer, artifact, destination):
    destination.mkdir()
    fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with artifact.open('rb') as stream:
            installer.extract(stream, fd)
    finally:
        os.close(fd)


def main():
    if os.geteuid() == 0:
        raise PermissionError('Never prepare mutable candidates as root')
    os.umask(0o077)
    if OUTPUT.exists() or OUTPUT.is_symlink() or REPORT.exists() or REPORT.is_symlink():
        raise FileExistsError('Candidate/report output must be new')
    sources = {name: pinned_bytes(REPO / name, digest) for name, digest in SOURCES.items()}
    builder = helper('build-development-candidate')
    provision = helper('provision-development-runtime')
    installer = helper('install-development-artifact')
    allowed = provision.workspace_admissions(provision.document(provision.STAGE / 'workspaces.yaml'))
    with tempfile.TemporaryDirectory(prefix='agentporter-v9-overlay-', dir='/tmp') as temporary:
        base = Path(temporary)
        frozen = base / 'base.tgz'
        fd = os.open(BASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_size > installer.LIMIT):
                raise ValueError('Unsafe base archive')
            with os.fdopen(fd, 'rb', closefd=False) as incoming, frozen.open('xb') as outgoing:
                remaining = installer.LIMIT + 1
                while remaining:
                    block = incoming.read(min(1024**2, remaining))
                    if not block:
                        break
                    outgoing.write(block)
                    remaining -= len(block)
                if not remaining:
                    raise ValueError('Base exceeded copy limit')
        finally:
            os.close(fd)
        if builder.digest(frozen, installer.LIMIT) != BASE_SHA256:
            raise ValueError('Base archive digest differs from reviewed v8')
        original = base / 'original'
        extract(installer, frozen, original)
        release = original / 'release'
        old_manifest = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, old_manifest)
        metadata = installer.bounded_json(original / 'release-metadata.json')
        old_version = metadata['version']
        version = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        if version == old_version:
            raise ValueError('A unique release version is required')
        old_prefix = '/opt/agentporter-development/versions/' + old_version
        new_prefix = '/opt/agentporter-development/versions/' + version
        old_runtime = installer.bounded_json(original / 'runtime.json')
        runtime = json.loads(json.dumps(old_runtime).replace(old_prefix, new_prefix))
        runtime['allowed_workspace_roots'] = allowed
        for name, data in sources.items():
            replace_file(release / name, data)
        for name in ('venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'):
            path = release / name
            before = path.read_bytes()
            if old_prefix.encode() not in before:
                raise ValueError('Base relocation document lacks original release prefix')
            replace_file(path, before.replace(old_prefix.encode(), new_prefix.encode()))
        metadata['version'] = version
        replace_file(original / 'runtime.json', json.dumps(runtime, sort_keys=True).encode() + b'\n')
        replace_file(original / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        new_manifest = builder.entries(release)
        expected_changes = {*SOURCES, 'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        changed = {name for name in set(old_manifest) | set(new_manifest)
                   if old_manifest.get(name) != new_manifest.get(name)}
        if set(old_manifest) != set(new_manifest) or changed != expected_changes:
            raise ValueError('Overlay changed files outside its reviewed boundary')
        replace_file(original / 'release-files.json', json.dumps(new_manifest, sort_keys=True).encode() + b'\n')
        candidate = base / 'candidate.tgz'
        builder.write_artifact(release, original, candidate)
        verified = base / 'verified'
        extract(installer, candidate, verified)
        installer.verify_release(verified / 'release', new_manifest)
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            if (verified / name).read_bytes() != (original / name).read_bytes():
                raise ValueError('Round-trip metadata mismatch')
        candidate.chmod(0o400)
        report = {'artifact': str(OUTPUT), 'sha256': builder.digest(candidate, installer.LIMIT),
                  'base_sha256': BASE_SHA256, 'version': version, 'previous_version': old_version,
                  'release_manifest_entries': len(new_manifest), 'allowed_workspace_roots': allowed,
                  'resource_manifest_sha256': metadata['resource_manifest_sha256'],
                  'source_sha256': SOURCES,
                  'changed_release_files': {name: {'before': old_manifest[name], 'after': new_manifest[name]}
                                            for name in sorted(changed)},
                  'other_release_entries': 'byte-identical digest, execute flags and link targets',
                  'verification': 'real base and candidate extraction plus strict verify_release',
                  'payload_executed': False, 'service_changes': False,
                  'state': 'candidate; independent admission and privileged acceptance required'}
        os.link(candidate, OUTPUT, follow_symlinks=False)
        with REPORT.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
