#!/usr/bin/python3
"""Repair an admitted candidate's cache/manifest mismatch without running it.

Run unprivileged. Pin the original archive digest and choose a new output file.
Only unlisted regular .pyc files under __pycache__ may be removed. Preserve
every admitted release file and all three metadata documents exactly, then
exercise the real installer extraction and exact manifest verification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile


def load(name):
    path = Path(__file__).resolve().with_name(name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repack(artifact, expected_digest, output):
    previous_umask = os.umask(0o077)
    try:
        return _repack(artifact, expected_digest, output)
    finally:
        os.umask(previous_umask)


def _repack(artifact, expected_digest, output):
    if os.geteuid() == 0:
        raise PermissionError('Never run candidate repacking as root')
    if not re.fullmatch('[0-9a-f]{64}', expected_digest):
        raise ValueError('Explicit original archive SHA256 required')
    builder = load('build-development-candidate')
    installer = load('install-development-artifact')
    with tempfile.TemporaryDirectory(prefix='agentporter-repack-', dir='/tmp') as temporary:
        base = Path(temporary)
        frozen = base / 'original.tgz'
        fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_size > installer.LIMIT or info.st_mode & 0o022):
                raise ValueError('Original artifact must be a bounded operator-owned regular file')
            with os.fdopen(fd, 'rb', closefd=False) as incoming, frozen.open('xb') as destination:
                remaining = installer.LIMIT + 1
                while remaining:
                    block = incoming.read(min(1024**2, remaining))
                    if not block:
                        break
                    destination.write(block)
                    remaining -= len(block)
                if not remaining:
                    raise ValueError('Original artifact exceeded copy limit')
        finally:
            os.close(fd)
        if builder.digest(frozen, installer.LIMIT) != expected_digest:
            raise ValueError('Original archive is not the approved SHA256')
        original = base / 'original'
        original.mkdir()
        original_fd = os.open(original, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with frozen.open('rb') as stream:
                installer.extract(stream, original_fd)
        finally:
            os.close(original_fd)
        release = original / 'release'
        expected = installer.bounded_json(original / 'release-files.json')
        extras = []
        for location, dirs, files in os.walk(release, followlinks=False):
            for name in dirs + files:
                path = Path(location) / name
                info = path.lstat()
                relative = path.relative_to(release)
                if stat.S_ISDIR(info.st_mode) or str(relative) in expected:
                    continue
                if (not stat.S_ISREG(info.st_mode) or '__pycache__' not in relative.parts[:-1]
                        or relative.suffix != '.pyc'):
                    raise ValueError(f'Unapproved non-cache archive member: {relative}')
                extras.append(str(relative))
        if not extras:
            raise ValueError('Original archive has no cache mismatch to repair')
        # This validates all admitted bytes, execute bits, links and membership;
        # only the separately checked cache extras are intentionally excluded.
        if builder.entries(release) != expected:
            raise ValueError('Admitted original release contents differ from manifest')
        builder.freeze(release)
        candidate = base / 'candidate.tgz'
        builder.write_artifact(release, original, candidate)
        verified = base / 'verified'
        verified.mkdir()
        verified_fd = os.open(verified, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with candidate.open('rb') as stream:
                installer.extract(stream, verified_fd)
        finally:
            os.close(verified_fd)
        installer.verify_release(verified / 'release', expected)
        metadata_digests = {}
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            if (original / name).read_bytes() != (verified / name).read_bytes():
                raise ValueError(f'Candidate changed original metadata: {name}')
            metadata_digests[name] = hashlib.sha256((original / name).read_bytes()).hexdigest()
        candidate.chmod(0o400)
        checksum = builder.digest(candidate, installer.LIMIT)
        # Atomic publication into a new name only; never replace an artifact.
        os.link(candidate, output, follow_symlinks=False)
        result = {'artifact': str(output), 'sha256': checksum,
                  'original_sha256': expected_digest, 'removed_cache_files': len(extras),
                  'manifest_entries': len(expected), 'metadata': 'byte-identical',
                  'preserved_metadata_sha256': metadata_digests,
                  'verification': 'real installer extract + strict verify_release; no payload executed',
                  'state': 'candidate; no installation or service changes'}
        print(json.dumps(result, sort_keys=True), flush=True)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    repack(args.artifact, args.sha256, args.output)


if __name__ == '__main__':
    main()
