#!/usr/bin/python3
"""Operator-only CRAN opt-in with exact policy backups; never run as root.

Runs from a verified immutable A7Dev release as service UID 994 with isolated
Python. Changes only the approved flag, preserves all other owner settings and
requires a stopped, quiescent gateway for apply and rollback. No network access.
"""
import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sqlite3
import sys
import tempfile

import yaml
from agentporter.scoped_https import ScopedPublicHTTPSPolicy, _NoAliasOwnerPolicyLoader


CONFIG = Path('/var/lib/agentporter-dev/config')
STATE = Path('/var/lib/agentporter-dev/state/cran-download-policy')
POLICY = 'public-https.yaml'
STORAGE_SHA = 'b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def dependencies():
    require(os.getuid() == os.geteuid() == 994 and sys.flags.isolated,
        'Run as service UID 994 with isolated Python, never root')
    source = Path(__file__)
    release = source.parent.parent
    require(source.name == 'enable-a7dev-all-cran-paths.py'
        and source.parent.name == 'operator-plan'
        and release.parent == Path('/opt/agentporter-development/versions')
        and re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', release.name)
        and Path('/opt/agentporter-development/current').resolve() == release,
        'Run only from the current immutable development release')
    storage_path = source.with_name('authorize-a7dev-project-delegation.py')
    for path in (source, storage_path):
        for ancestor in (path, *path.parents):
            info = ancestor.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, 'Untrusted immutable operator helper')
        require(stat.S_ISREG(path.stat().st_mode), 'Operator helper must be regular')
    require(digest(storage_path.read_bytes()) == STORAGE_SHA, 'Storage helper hash changed')
    import agentporter.scoped_https as scoped
    require(Path(scoped.__file__).parent == release / 'src/agentporter',
        'HTTPS policy code must come from this immutable release')
    spec = importlib.util.spec_from_file_location('cran_operator_storage', storage_path)
    storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
    stopped = storage.quiet_and_stopped
    def quiet():
        stopped()
        strict_jobs(storage.STATE / 'jobs.db')
    storage.quiet_and_stopped = quiet
    return storage, release.name


def strict_jobs(database):
    terminal = ('completed', 'failed', 'cancelled', 'timed_out', 'output_limit_exceeded', 'interrupted')
    with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True, timeout=2) as db:
        db.execute('PRAGMA query_only=ON')
        require(db.execute('SELECT count(*) FROM jobs WHERE status IS NULL OR status NOT IN (?,?,?,?,?,?)',
            terminal).fetchone()[0] == 0, 'Active or unresolved development jobs')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require('job_admissions' not in tables or db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0,
            'Unresolved development admissions')


def validate(body, state):
    require(len(body) <= 16384, 'Owner HTTPS policy exceeds 16 KiB')
    # Exercise the real strict policy reader without publishing a new policy.
    # Temporary validation data stays under private service state, outside all
    # workspaces; it is removed before plan returns.
    with tempfile.TemporaryDirectory(prefix='.validate-cran-', dir=state) as temporary:
        p = Path(temporary) / POLICY
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(body)
        return ScopedPublicHTTPSPolicy(Path(temporary)).scopes


def proposal(body):
    try:
        document = yaml.load(body, Loader=_NoAliasOwnerPolicyLoader)
    except Exception:
        raise ValueError('Invalid owner HTTPS policy') from None
    require(document.get('version') == 2, 'Independent binary acquisition approval required')
    downloads = document['workspaces']['cranary']['downloads']
    require('cran.r-project.org' in downloads['hosts'], 'CRAN must already be owner-approved')
    require('cran_all_paths' not in downloads or type(downloads['cran_all_paths']) is bool,
        'Invalid owner CRAN opt-in type')
    if downloads.get('cran_all_paths') is True:
        return body
    after = copy.deepcopy(document)
    after['workspaces']['cranary']['downloads']['cran_all_paths'] = True
    return json.dumps(after, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'


def describe(before, after, state, release):
    old = validate(before, state); new = validate(after, state)
    expected = copy.deepcopy(old)
    expected['cranary']['downloads']['cran_all_paths'] = True
    require(new == expected, 'Only the owner-approved CRAN flag may change')
    grant = new['cranary']['downloads']
    return {'version': 1, 'release': release, 'before_sha256': digest(before),
        'after_sha256': digest(after), 'field': 'workspaces.cranary.downloads.cran_all_paths',
        'value': True, 'directory': grant['directory'], 'hosts': sorted(grant['hosts']),
        'max_response_bytes': grant['max_response_bytes'], 'timeout_seconds': grant['timeout_seconds']}


def plan(storage, config_fd, state, release):
    before = storage.private_read(config_fd, POLICY, os.getuid())
    validate(before, state)
    after = proposal(before)
    return describe(before, after, state, release), before, after


def expected_hash(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
        'Explicit SHA256 plan admission required')


def apply(storage, config_fd, state_fd, state, release, expected):
    expected_hash(expected); storage.quiet_and_stopped()
    admission, before, after = plan(storage, config_fd, state, release)
    require(digest(canonical(admission)) == expected, 'Owner policy plan changed; no policy modified')
    if before == after:
        return {'already_enabled': True, 'applied': False}
    name = 'cran-' + expected
    os.mkdir(name, 0o700, dir_fd=state_fd)
    recovery = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        for filename, body in [('before.yaml', before), ('after.yaml', after),
                ('plan.json', canonical(admission))]:
            storage.write(recovery, filename, body, exclusive=True)
        os.fsync(state_fd)
        require(storage.private_read(config_fd, POLICY, os.getuid()) == before,
            'Owner policy changed immediately before apply')
        storage.quiet_and_stopped()
        storage.write(config_fd, POLICY, after)
        require(storage.private_read(config_fd, POLICY, os.getuid()) == after,
            'Unexpected owner policy after apply')
    finally:
        os.close(recovery)
    return {'applied': True, 'plan_sha256': expected, 'recovery': name}


def rollback(storage, config_fd, state_fd, state, release, expected):
    expected_hash(expected); storage.quiet_and_stopped()
    name = 'cran-' + expected
    recovery = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        info = os.fstat(recovery)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Unsafe policy recovery directory')
        before = storage.private_read(recovery, 'before.yaml', os.getuid())
        after = storage.private_read(recovery, 'after.yaml', os.getuid())
        admission = describe(before, after, state, release)
        require(digest(canonical(admission)) == expected
            and storage.private_read(recovery, 'plan.json', os.getuid()) == canonical(admission),
            'Policy recovery hash mismatch')
        current = storage.private_read(config_fd, POLICY, os.getuid())
        require(current in (before, after), 'Newer owner policy; refuse rollback')
        if current == before:
            return {'already_restored': True}
        storage.write(config_fd, POLICY, before)
        require(storage.private_read(config_fd, POLICY, os.getuid()) == before,
            'Unexpected policy after rollback')
        return {'rolled_back': True, 'plan_sha256': expected}
    finally:
        os.close(recovery)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    storage, release = dependencies()
    if not args.plan:
        expected_hash(args.expected_plan_sha256); storage.quiet_and_stopped()
    os.umask(0o077)
    config = storage.open_directory(CONFIG, 994)
    parent = storage.open_directory(STATE.parent, 994)
    try:
        try:
            os.mkdir(STATE.name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        state = storage.open_directory(STATE, 994)
        os.fsync(parent)
    finally:
        os.close(parent)
    lock = None
    try:
        lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=state)
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 994 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe policy lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.plan:
            admission, _, _ = plan(storage, config, STATE, release)
            result = {'plan': admission, 'plan_sha256': digest(canonical(admission))}
        elif args.apply:
            result = apply(storage, config, state, STATE, release, args.expected_plan_sha256)
        else:
            result = rollback(storage, config, state, STATE, release, args.expected_plan_sha256)
        print(json.dumps(result, sort_keys=True))
    finally:
        if lock is not None:
            os.close(lock)
        os.close(state); os.close(config)


if __name__ == '__main__':
    main()
