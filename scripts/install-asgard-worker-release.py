#!/usr/bin/python3
"""Trusted installer for the Asgard production-owned worker release.

Install root-owned at /usr/local/libexec/agentporter/ and run with
`/usr/bin/python3 -I` as root. It reuses the audited extraction, manifest
verification and pointer-swap primitives of install-development-artifact.py
(installed beside it) but is bound to the independent agentporter-worker
identity. It never starts, stops or restarts any service, and never creates
accounts, keys or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess

BASE_PATH = Path(__file__).resolve().with_name('install-development-artifact.py')
TRUSTED = Path('/usr/local/libexec/agentporter/install-asgard-worker-release.py')
INSTALL = Path('/opt/agentporter-worker')
DATA = Path('/var/lib/agentporter-worker')
ACCOUNT = 'agentporter-worker'
UNIT = 'agentporter-worker.service'
AGENTS = {'jax', 'liz', 'prof', 'ming', 'wei', 'phil', 'argie'}
SYSTEMCTL = '/usr/bin/systemctl'
CGROUP = Path('/sys/fs/cgroup/system.slice') / UNIT
RUNTIME_NAME = 'development-runtime.yaml'
VERSION = re.compile(r'\d{8}T\d{6}\.\d{6}Z')


def load_base():
    spec = importlib.util.spec_from_file_location('install_development_artifact', BASE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def trusted_program():
    path = Path(__file__)
    if path != TRUSTED or os.geteuid() != 0 or not __import__('sys').flags.isolated:
        raise PermissionError('Use the immutable installed helper with /usr/bin/python3 -I as root')
    for item in (path, BASE_PATH, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Installer, base helper and ancestors must be root-owned and non-writable')


def check_runtime(runtime, version, owner_uid):
    final = INSTALL / 'versions' / version
    if (runtime.get('profile') != 'development' or runtime.get('gateway_user') != ACCOUNT
            or runtime.get('service_unit') != UNIT or runtime.get('production_uid') != owner_uid
            or set(runtime.get('workers', {})) != AGENTS
            or set(runtime.get('production_relay_agents', [])) != AGENTS
            or runtime.get('shared_obsidian') != str(final / 'shared/obsidian')
            or runtime.get('shared_toolkit') != str(final / 'shared/toolkit')
            or 'agentporter-dev' in json.dumps(runtime)):
        raise ValueError('Artifact runtime is not the approved worker profile')


def require_quiesced():
    """The worker must be fully stopped before any filesystem mutation."""
    result = subprocess.run([SYSTEMCTL, 'show', UNIT, '--property=ActiveState', '--value'],
                            capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin'})
    if result.returncode != 0 or result.stdout.strip() != 'inactive':
        raise PermissionError('Worker service must be stopped (inactive) before install')
    if os.path.lexists(CGROUP):
        raise PermissionError('Worker service cgroup still exists; wait for it to disappear')


def read_runtime(config):
    fd = os.open(RUNTIME_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=config)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Existing worker runtime is not a regular file')
        data = os.read(fd, 1024**2 + 1)
    finally:
        os.close(fd)
    if not data or len(data) > 1024**2:
        raise ValueError('Existing worker runtime has invalid size')
    return data


def existing_pair(root, config, versions, owner_uid):
    """Return None when BOTH pointer and runtime are absent; otherwise a validated consistent pair.

    Anything partial, foreign or inconsistent fails closed instead of being treated as a first install.
    """
    def absent(call):
        try:
            call()
        except FileNotFoundError:
            return True
        return False

    holder = {}

    def link():
        holder['release'] = os.readlink('current', dir_fd=root)

    def runtime():
        holder['runtime'] = read_runtime(config)

    no_link, no_runtime = absent(link), absent(runtime)
    if no_link and no_runtime:
        return None
    if no_link or no_runtime:
        raise RuntimeError('Incomplete worker install (only one of current/runtime exists); repair manually')
    previous = Path(holder['release'])
    if previous.parent != INSTALL / 'versions' or not VERSION.fullmatch(previous.name):
        raise ValueError('Existing worker pointer is outside the release set')
    if previous.name not in os.listdir(versions):
        raise ValueError('Existing worker pointer targets a missing release')
    try:
        document = json.loads(holder['runtime'])
        check_runtime(document, previous.name, owner_uid)
    except (ValueError, TypeError) as error:
        raise ValueError('Existing worker runtime does not match its current release') from error
    return holder['release'], holder['runtime']


def install(artifact, expected_digest):
    base = load_base()
    if not re.fullmatch('[0-9a-f]{64}', expected_digest):
        raise ValueError('Explicit approved archive SHA256 required')
    account = pwd.getpwnam(ACCOUNT)
    owner = pwd.getpwnam('operator')
    if account.pw_uid in (0, owner.pw_uid):
        raise PermissionError('Worker account must be a distinct unprivileged identity')
    require_quiesced()
    root = base.directory(INSTALL)
    versions = base.directory(INSTALL / 'versions')
    config = base.directory(DATA / 'config', account.pw_uid)
    source = -1
    try:
        pair = existing_pair(root, config, versions, owner.pw_uid)
        source = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        return _install(base, account, owner, root, versions, config, source, expected_digest, pair)
    finally:
        for fd in (source, config, versions, root):
            if fd >= 0:
                os.close(fd)


def _install(base, account, owner, root, versions, config, source, expected_digest, pair):
    stage_name = '.candidate-' + secrets.token_hex(16)
    os.mkdir(stage_name, 0o700, dir_fd=root)
    stage = INSTALL / stage_name
    info = os.fstat(source)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner.pw_uid
            or info.st_size > base.LIMIT or info.st_mode & 0o022):
        raise PermissionError('Artifact must be a bounded private operator-owned regular file')
    # Freeze a root-private copy before hashing so the operator cannot swap it afterwards.
    with os.fdopen(source, 'rb', closefd=False) as incoming, (stage / 'artifact.tgz').open('xb') as frozen:
        remaining = base.LIMIT + 1
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
        stage_fd = base.directory(stage)
        try:
            base.extract(stream, stage_fd)
        finally:
            os.close(stage_fd)
    metadata = base.bounded_json(stage / 'release-metadata.json')
    version = metadata.get('version', '')
    if (metadata.get('profile') != 'development' or metadata.get('service') != UNIT
            or not VERSION.fullmatch(version)):
        raise ValueError('Invalid worker release metadata')
    runtime = base.bounded_json(stage / 'runtime.json')
    check_runtime(runtime, version, owner.pw_uid)
    base.verify_release(stage / 'release', base.bounded_json(stage / 'release-files.json'))
    if version in os.listdir(versions):
        raise ValueError('Release already installed')
    os.rename(stage / 'release', version, dst_dir_fd=versions)
    final = INSTALL / 'versions' / version
    payload = json.dumps(runtime).encode() + b'\n'
    if pair is None:
        # First install: nothing to compensate to. Rollback is service-level.
        base.private_write(config, RUNTIME_NAME, payload, account.pw_uid, account.pw_gid)
        base.replace_symlink(root, 'current', final)
    else:
        previous_release, previous_runtime = pair
        (stage / 'previous-runtime.yaml').write_bytes(previous_runtime)
        (stage / 'rollback.json').write_text(json.dumps({'release': previous_release, 'candidate': version}) + '\n')
        base.switch_pair(root, config, final, payload, previous_release, previous_runtime,
                         account.pw_uid, account.pw_gid, evidence=stage)
    first = pair is None
    print(json.dumps({'installed': str(final), 'first_install': first, 'evidence': str(stage),
                      'service_started': False}))


def main():
    trusted_program()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    install(args.artifact, args.sha256)


if __name__ == '__main__':
    main()
