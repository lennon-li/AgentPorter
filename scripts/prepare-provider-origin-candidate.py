#!/usr/bin/python3
"""Prepare an inactive v13 derivative; never run payloads or change services."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/tmp/agentporter-development-candidate-v12.tgz')
BASE_SHA256 = 'e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5'
OUTPUT = Path('/tmp/agentporter-development-candidate-v13.tgz')
REPORT = Path('/tmp/agentporter-development-candidate-v13-review.json')
SOURCES = {
    'src/agentporter/agents/development.py': '5ec03d1e8643789a9bf6f2cec9518e7ff85d62edb8b04c64a4baf1e32f0baa13',
    'src/agentporter/agents/development_egress.py': '8a90133b50b9dd39b38d17aa677ab345ab868d44e36f483f8b7a2a54f5982f31',
    'src/agentporter/agents/production_relay.py': '560adf284853aa55be9c35ce09b87ecf03b5a8fd6f9ccf8e921058b80f7d4107',
    'src/agentporter/agents/provider_egress.py': 'c7dfe964fe6d1b04f4b7a9d3c3258bbf4aafbc1360af73d08d829947be0bea83',
    'src/agentporter/server.py': '3538cd622768c274afb4152483dc827be9e957083fc6c9ad595e121f0cc4b31e',
}


def main():
    if os.geteuid() == 0:
        raise PermissionError('Never prepare mutable candidates as root')
    os.umask(0o077)
    if any(path.exists() or path.is_symlink() for path in (OUTPUT, REPORT)):
        raise FileExistsError('Candidate and report must be new')
    helper_path = REPO / 'scripts/prepare-development-overlay.py'
    helper_bytes = helper_path.read_bytes()
    if hashlib.sha256(helper_bytes).hexdigest() != '69bf234a1b8d1732daf2179823ab93a92a6a3a9f29e00ec1c4edd01b87c02ec0':
        raise ValueError('Reviewed unprivileged overlay helper changed')
    overlay = types.ModuleType('provider_origin_overlay')
    overlay.__file__ = str(helper_path)
    exec(compile(helper_bytes, str(helper_path), 'exec'), overlay.__dict__)
    sources = {name: overlay.pinned_bytes(REPO / name, digest) for name, digest in SOURCES.items()}
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    with tempfile.TemporaryDirectory(prefix='agentporter-v13-overlay-') as directory:
        root = Path(directory)
        frozen = root / 'base.tgz'
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
                    raise ValueError('Base archive exceeds bound')
        finally:
            os.close(fd)
        if builder.digest(frozen, installer.LIMIT) != BASE_SHA256:
            raise ValueError('Frozen v12 archive differs from reviewed digest')
        original = root / 'original'
        overlay.extract(installer, frozen, original)
        release = original / 'release'
        old_manifest = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, old_manifest)
        metadata = installer.bounded_json(original / 'release-metadata.json')
        old_runtime = installer.bounded_json(original / 'runtime.json')
        old_version = metadata['version']
        version = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        old_prefix = '/opt/agentporter-development/versions/' + old_version
        new_prefix = '/opt/agentporter-development/versions/' + version
        runtime = json.loads(json.dumps(old_runtime).replace(old_prefix, new_prefix))
        runtime.update(egress_policy='provider_origin', production_relay_agents=['liz', 'prof', 'ming'])
        if runtime.get('network_enabled') is not True:
            raise ValueError('Existing network-enabled runtime required')
        for name, content in sources.items():
            path = release / name
            if name in old_manifest:
                overlay.replace_file(path, content)
            else:
                # Exactly one explicitly pinned new Python module, in an
                # existing manifest-verified parent, without replacing links.
                if name != 'src/agentporter/agents/provider_egress.py':
                    raise ValueError('Unexpected added module')
                mode = stat.S_IMODE(path.parent.stat().st_mode)
                path.parent.chmod(mode | 0o200)
                try:
                    with path.open('xb') as stream:
                        stream.write(content)
                    path.chmod(0o444)
                finally:
                    path.parent.chmod(mode)
        relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        for name in relocations:
            before = (release / name).read_bytes()
            if old_prefix.encode() not in before:
                raise ValueError('Missing expected release relocation')
            overlay.replace_file(release / name, before.replace(old_prefix.encode(), new_prefix.encode()))
        metadata['version'] = version
        overlay.replace_file(original / 'runtime.json', json.dumps(runtime, sort_keys=True).encode() + b'\n')
        overlay.replace_file(original / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release)
        manifest = builder.entries(release)
        changed = {name for name in set(old_manifest) | set(manifest)
                   if old_manifest.get(name) != manifest.get(name)}
        if (set(manifest) != set(old_manifest) | {'src/agentporter/agents/provider_egress.py'}
                or changed != set(SOURCES) | relocations):
            raise ValueError('Unapproved payload delta')
        overlay.replace_file(original / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        candidate = root / 'candidate.tgz'
        builder.write_artifact(release, original, candidate)
        verified = root / 'verified'
        overlay.extract(installer, candidate, verified)
        installer.verify_release(verified / 'release', manifest)
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            if (original / name).read_bytes() != (verified / name).read_bytes():
                raise ValueError('Metadata round trip failed')
        candidate.chmod(0o400)
        report = {'artifact': str(OUTPUT), 'sha256': builder.digest(candidate, installer.LIMIT),
            'base_sha256': BASE_SHA256, 'version': version, 'previous_version': old_version,
            'release_manifest_entries': len(manifest), 'source_sha256': SOURCES,
            'runtime_changes_beyond_version_relocation': {
                'egress_policy': 'provider_origin', 'production_relay_agents': ['liz', 'prof', 'ming']},
            'changed_release_files': {name: {'before': old_manifest.get(name), 'after': manifest[name]}
                                      for name in sorted(changed)},
            'resource_manifest_sha256': metadata['resource_manifest_sha256'],
            'verification': 'real base/candidate extraction and strict manifests; no payload execution',
            'service_changes': False, 'state': 'inactive candidate; independent review and activation required'}
        os.link(candidate, OUTPUT, follow_symlinks=False)
        with REPORT.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
