#!/usr/bin/python3
"""Trusted A7Dev artifact installer. Install root-owned outside all workspaces.

Accepts only a caller-approved complete archive SHA256, never executes archive
code as root, never provisions accounts/ACLs, and changes only the existing
A7Dev release and runtime config. Production has a separate review boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import pwd
import re
import secrets
import stat
import subprocess
import tarfile

INSTALL = Path('/opt/agentporter-development')
DATA = Path('/var/lib/agentporter-dev')
TRUSTED = Path('/usr/local/libexec/agentporter/install-development-artifact.py')
LIMIT = 8 * 1024**3
FILE_LIMIT = 1024**3
MEMBERS = 100_000


def trusted_program():
    path = Path(__file__)
    if path != TRUSTED or os.geteuid() != 0 or not __import__('sys').flags.isolated:
        raise PermissionError('Use the immutable installed helper with /usr/bin/python3 -I as root')
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Installer and ancestors must be root-owned and non-writable')


def directory(path, owner=0):
    """Pin every ancestor; subsequent operations use the returned capability."""
    path = Path(path)
    if not path.is_absolute():
        raise PermissionError('Absolute path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:], start=1):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            expected_owner = owner if index == len(path.parts) - 1 else 0
            if info.st_uid != expected_owner or info.st_mode & 0o022:
                raise PermissionError('Untrusted destination ancestor')
        info = os.fstat(fd)
        if info.st_uid != owner or info.st_mode & 0o022:
            raise PermissionError('Untrusted destination directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_write(parent, name, content, uid=0, gid=0):
    temporary = '.artifact-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
        os.fchown(fd, uid, gid)
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def replace_symlink(parent, name, target):
    """Atomically replace one symlink without following the existing link."""
    temporary = '.current-' + secrets.token_hex(16)
    os.symlink(str(target), temporary, dir_fd=parent)
    try:
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def restore_pair(base, config, previous_release, previous_runtime, uid, gid):
    """Attempt both compensations even if one fails; caller must keep service stopped."""
    failures = []
    try:
        replace_symlink(base, 'current', previous_release)
    except Exception:
        failures.append('release pointer')
    try:
        private_write(config, 'development-runtime.yaml', previous_runtime, uid, gid)
    except Exception:
        failures.append('runtime configuration')
    return failures


def switch_pair(base, config, candidate_release, candidate_runtime,
                previous_release, previous_runtime, uid, gid, activate=None, evidence=None):
    """Switch runtime and pointer as a compensating transaction.

    The service must remain quiesced while the two filesystem entries change.
    If activation fails, restore both entries and leave service recovery to the
    operator's gated procedure.
    """
    try:
        private_write(config, 'development-runtime.yaml', candidate_runtime, uid, gid)
        replace_symlink(base, 'current', candidate_release)
        if activate is not None:
            activate()
    except BaseException:
        failures = restore_pair(base, config, previous_release, previous_runtime, uid, gid)
        if failures:
            raise RuntimeError(
                'A7Dev install failed and automatic compensation was incomplete '
                f'({", ".join(failures)}); keep service stopped'
                + (f'; recovery evidence: {evidence}' if evidence else '')
            ) from None
        raise


def member_parent(root, path):
    fd = os.dup(root)
    try:
        for part in path.parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def extract(archive, root):
    seen = set()
    total = 0
    with tarfile.open(fileobj=archive, mode='r:gz') as stream:
        for item in stream:
            path = PurePosixPath(item.name)
            if (not item.name or path.is_absolute() or '..' in path.parts
                    or str(path) != item.name.rstrip('/') or len(path.parts) > 40
                    or item.name in seen or len(seen) >= MEMBERS
                    or path.parts[0] not in {'release', 'runtime.json', 'release-metadata.json', 'release-files.json'}
                    or (path.parts[0] != 'release' and len(path.parts) != 1)):
                raise ValueError('Unsafe or duplicate artifact member')
            seen.add(item.name)
            parent = member_parent(root, path)
            try:
                if item.isdir():
                    try:
                        os.mkdir(path.name, 0o700, dir_fd=parent)
                    except FileExistsError:
                        check = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                        os.close(check)
                elif item.issym():
                    target = posixpath.normpath(posixpath.join(str(path.parent), item.linkname))
                    if path.parts[0] != 'release' or item.linkname.startswith('/') or not target.startswith('release/'):
                        raise ValueError('Artifact symlink escapes release')
                    os.symlink(item.linkname, path.name, dir_fd=parent)
                elif item.isfile():
                    total += item.size
                    if not 0 <= item.size <= FILE_LIMIT or total > LIMIT:
                        raise ValueError('Artifact file/total limit exceeded')
                    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                    try:
                        source = stream.extractfile(item)
                        remaining = item.size
                        with os.fdopen(fd, 'wb', closefd=False) as destination:
                            while remaining:
                                data = source.read(min(1024**2, remaining))
                                if not data:
                                    raise ValueError('Truncated artifact member')
                                destination.write(data)
                                remaining -= len(data)
                        os.fchmod(fd, 0o555 if item.mode & 0o111 else 0o444)
                    finally:
                        os.close(fd)
                else:
                    raise ValueError('Hard links and special artifact files are forbidden')
            finally:
                os.close(parent)
    if not {'release', 'runtime.json', 'release-metadata.json', 'release-files.json'} <= seen:
        raise ValueError('Artifact metadata missing')


def bounded_json(path):
    with path.open('rb') as stream:
        data = stream.read(32 * 1024**2 + 1)
    if len(data) > 32 * 1024**2:
        raise ValueError('Artifact metadata too large')
    return json.loads(data)


def verify_release(root, expected):
    actual = set()
    for location, dirs, files, parent in os.fwalk(root, follow_symlinks=False):
        for name in dirs + files:
            relative = str((Path(location) / name).relative_to(root))
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                continue
            actual.add(relative)
            entry = expected.get(relative, {})
            if stat.S_ISLNK(info.st_mode):
                if entry != {'link': os.readlink(name, dir_fd=parent)}:
                    raise ValueError('Symlink differs from reviewed manifest')
                continue
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                if entry != {'sha256': digest, 'executable': bool(info.st_mode & 0o111)}:
                    raise ValueError('File differs from reviewed manifest')
            finally:
                os.close(fd)
        # The extraction directory is root-owned mode0700; no worker can race
        # this descriptor-relative transition to immutable release modes.
        os.fchmod(parent, 0o555)
    if actual != set(expected):
        raise ValueError('Release manifest file set mismatch')


def install(artifact, expected_digest, activate=False):
    if not re.fullmatch('[0-9a-f]{64}', expected_digest):
        raise ValueError('Explicit approved archive SHA256 required')
    account = pwd.getpwnam('agentporter-dev')
    owner = pwd.getpwnam('operator')
    base = directory(INSTALL)
    versions = directory(INSTALL / 'versions')
    source = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stage_name = '.candidate-' + secrets.token_hex(16)
    os.mkdir(stage_name, 0o700, dir_fd=base)
    stage = INSTALL / stage_name
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner.pw_uid or info.st_size > LIMIT or info.st_mode & 0o022:
            raise PermissionError('Artifact must be a bounded private operator-owned regular file')
        # Copy into root-private storage BEFORE verifying and extracting. The
        # operator may replace or modify the input, but cannot alter this copy.
        with os.fdopen(source, 'rb', closefd=False) as incoming, (stage / 'artifact.tgz').open('xb') as frozen:
            remaining = LIMIT + 1
            while remaining:
                block = incoming.read(min(1024**2, remaining))
                if not block:
                    break
                frozen.write(block)
                remaining -= len(block)
            if not remaining:
                raise ValueError('Artifact exceeds bounded copy limit')
        with (stage / 'artifact.tgz').open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected_digest:
                raise ValueError('Artifact is not the approved SHA256')
            stream.seek(0)
            stage_fd = directory(stage)
            try:
                extract(stream, stage_fd)
            finally:
                os.close(stage_fd)
        metadata = bounded_json(stage / 'release-metadata.json')
        version = metadata.get('version', '')
        if metadata.get('profile') != 'development' or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', version):
            raise ValueError('Invalid development release metadata')
        runtime = bounded_json(stage / 'runtime.json')
        final = INSTALL / 'versions' / version
        if (runtime.get('profile') != 'development' or runtime.get('gateway_user') != 'agentporter-dev'
                or runtime.get('production_uid') != owner.pw_uid
                or set(runtime.get('workers', {})) != {'jax','liz','prof','ming','wei','phil','argie'}
                or runtime.get('shared_obsidian') != str(final / 'shared/obsidian')
                or runtime.get('shared_toolkit') != str(final / 'shared/toolkit')):
            raise ValueError('Artifact runtime is not the approved development profile')
        verify_release(stage / 'release', bounded_json(stage / 'release-files.json'))
        # rename() must not overwrite an existing release directory.
        if version in os.listdir(versions):
            raise ValueError('Release already installed')
        os.rename(stage / 'release', version, dst_dir_fd=versions)
        config = directory(DATA / 'config', account.pw_uid)
        try:
            # Preserve exact previous runtime and release as the rollback pair.
            old = os.open('development-runtime.yaml', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=config)
            try:
                if not stat.S_ISREG(os.fstat(old).st_mode):
                    raise ValueError('Existing runtime must be regular')
                previous = os.read(old, 1024**2 + 1)
                if len(previous) > 1024**2:
                    raise ValueError('Existing runtime too large')
            finally:
                os.close(old)
            (stage / 'previous-runtime.yaml').write_bytes(previous)
            previous_release = os.readlink('current', dir_fd=base)
            previous_path = Path(previous_release)
            if (previous_path.parent != INSTALL / 'versions'
                    or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', previous_path.name)):
                raise ValueError('Existing A7Dev current pointer is outside the release set')
            (stage / 'rollback.json').write_text(json.dumps({'release': previous_release, 'candidate': version}) + '\n')
            def restart_development():
                subprocess.run(['/usr/bin/systemctl', 'restart', 'agentporter-development.service'], check=True,
                               env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}, stdin=subprocess.DEVNULL)
            switch_pair(base, config, final, json.dumps(runtime).encode() + b'\n',
                        previous_release, previous, account.pw_uid, account.pw_gid,
                        activate=restart_development if activate else None, evidence=stage)
        finally:
            os.close(config)
        print(json.dumps({'installed': str(final), 'rollback_evidence': str(stage), 'service_restarted': activate}))
    finally:
        os.close(source)
        os.close(versions)
        os.close(base)


def rollback(evidence_name, activate=False):
    if not re.fullmatch(r'\.candidate-[0-9a-f]{32}', evidence_name):
        raise ValueError('Invalid rollback evidence identifier')
    base = directory(INSTALL)
    evidence = INSTALL / evidence_name
    evidence_fd = directory(evidence)
    account = pwd.getpwnam('agentporter-dev')
    try:
        record = bounded_json(evidence / 'rollback.json')
        previous = Path(record['release'])
        prefix = INSTALL / 'versions'
        candidate = record.get('candidate', '')
        active = os.readlink('current', dir_fd=base)
        allowed_pair = {str(previous), str(prefix / candidate)}
        if (previous.parent != prefix or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', previous.name)
                or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', candidate)
                or active not in allowed_pair):
            raise ValueError('Rollback evidence does not match the current A7Dev release pair')
        release_fd = directory(previous)
        os.close(release_fd)
        config = directory(DATA / 'config', account.pw_uid)
        try:
            old = os.open('development-runtime.yaml', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=config)
            try:
                if not stat.S_ISREG(os.fstat(old).st_mode):
                    raise ValueError('Existing runtime must be regular')
                active_runtime = os.read(old, 1024**2 + 1)
                if len(active_runtime) > 1024**2:
                    raise ValueError('Existing runtime too large')
            finally:
                os.close(old)
            content = (evidence / 'previous-runtime.yaml').read_bytes()
            if len(content) > 1024**2:
                raise ValueError('Rollback runtime exceeds limit')

            def restart_development():
                subprocess.run(['/usr/bin/systemctl', 'restart', 'agentporter-development.service'], check=True,
                               env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}, stdin=subprocess.DEVNULL)

            # Rollback is the same paired transition as install: if the runtime,
            # active pointer, or restart fails, compensate back to the exact
            # pair observed before this attempt and leave recovery to the gate.
            switch_pair(base, config, str(previous), content, active, active_runtime,
                        account.pw_uid, account.pw_gid,
                        activate=restart_development if activate else None,
                        evidence=evidence)
        finally:
            os.close(config)
        print(json.dumps({'rolled_back': str(previous), 'service_restarted': activate}))
    finally:
        os.close(evidence_fd)
        os.close(base)


def main():
    trusted_program()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact')
    parser.add_argument('--sha256')
    parser.add_argument('--rollback')
    parser.add_argument('--activate', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if args.rollback and not (args.artifact or args.sha256):
        rollback(args.rollback, args.activate)
    elif args.artifact and args.sha256 and not args.rollback:
        install(args.artifact, args.sha256, args.activate)
    else:
        parser.error('Choose --artifact PATH --sha256 DIGEST or --rollback EVIDENCE_ID')


if __name__ == '__main__':
    main()
