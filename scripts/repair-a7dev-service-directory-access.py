#!/usr/bin/python3
"""Service-UID-only repair of human access on service-owned ordinary directories.

Exact owner-admitted roots only. No files, chown, chmod, defaults or service
lifecycle changes. Immutable sibling dependencies are checked before import.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time

INSTALLED = Path('/opt/agentporter-development/activation-tools/directory-access/repair-a7dev-service-directory-access.py')
STATE = Path('/var/lib/agentporter-dev/state/directory-access-repair')
PINS = {'authorize-a7dev-project-delegation.py': 'b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b',
        'repair-a7dev-shared-directory-defaults.py': '62f2e0e566515ece9260beb3322ef763998bce76f2c52df550921b3cb8c1b8df'}


def require(ok, message):
    if not ok: raise RuntimeError(message)


def dependencies():
    import hashlib
    require(os.getuid() == os.geteuid() == 994 and sys.flags.isolated and Path(__file__) == INSTALLED,
            'Run only the immutable installed helper as agentporter-dev UID994, never root')
    for path in (INSTALLED, *(INSTALLED.with_name(name) for name in PINS)):
        for entry in (path, *path.parents):
            info = entry.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Untrusted installed helper or ancestor')
        require(stat.S_ISREG(path.stat().st_mode) and stat.S_IMODE(path.stat().st_mode) == 0o555,
                'Helper must be root-owned immutable mode0555')
        if path.name in PINS:
            require(hashlib.sha256(path.read_bytes()).hexdigest() == PINS[path.name], 'Immutable dependency SHA mismatch')
    loaded = []
    for name in PINS:
        spec = importlib.util.spec_from_file_location('service_access_' + name.replace('-', '_'), INSTALLED.with_name(name))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); loaded.append(module)
    return loaded[0], loaded[1]


def target_access(d, original, mode, human_uid):
    entries = d.decode_acl(original) if original is not None else {
        (d.UOBJ, d.UNDEF): (mode >> 6) & 7, (d.GOBJ, d.UNDEF): (mode >> 3) & 7,
        (d.OTHER, d.UNDEF): mode & 7}
    old_mask = entries.get((d.MASK, d.UNDEF), 7)
    for key in entries:
        if key[0] in {d.USER, d.GOBJ, d.GROUP}: entries[key] &= old_mask
    entries[d.USER, human_uid] = 7
    mask = 0
    for (tag, uid), value in entries.items():
        if tag in {d.USER, d.GOBJ, d.GROUP}: mask |= value
    entries[d.MASK, d.UNDEF] = mask
    return d.encode_acl(entries), (mode & ~0o070) | (mask << 3)


def envelope(current, before):
    return all(current[key] == before[key] for key in ('dev', 'ino', 'uid', 'gid', 'mount_id'))


def plan(d, storage, inputs, names, human_uid=1000, service_uid=994):
    roots = d.authorize(storage, inputs, names)
    account = pwd.getpwuid(human_uid)
    groups = set(os.getgrouplist(account.pw_name, account.pw_gid))
    records, root_ids, skipped = [], {}, {}
    budget = {'entries': 0, 'dirs': 0, 'start': time.monotonic()}
    remaining = [0]
    def skip(reason): skipped[reason] = skipped.get(reason, 0) + 1
    def visit(fd, workspace, relative, root_dev, root_mount, depth):
        budget['dirs'] += 1
        require(budget['dirs'] <= d.MAX_DIRS and depth <= d.MAX_DEPTH
                and time.monotonic() - budget['start'] <= d.MAX_SECONDS, 'Directory access scan exceeded bounded budget')
        before = d.identity(fd)
        if before['dev'] != root_dev or before['mount_id'] != root_mount:
            skip('mount_boundary'); return
        if before['uid'] not in {human_uid, service_uid}:
            skip('foreign_owner'); return
        if not before['mode'] & 0o222 or os.fstatvfs(fd).f_flag & os.ST_RDONLY:
            skip('read_only'); return
        default = d.xattr(fd, d.DEFAULT)
        access = d.unb64(before['access'])
        if d.human_access(fd, human_uid, groups) != 7:
            if before['uid'] == service_uid and not before['mode'] & 0o7000:
                target, mode_after = target_access(d, access, before['mode'], human_uid)
                records.append({'workspace': workspace, 'relative': relative, 'before': before,
                                'default': d.b64(default), 'access_after': d.b64(target), 'mode_after': mode_after})
            else:
                remaining[0] += 1
                skip('human_owned_or_special_mode_blocker')
        with os.scandir(fd) as entries:
            for entry in entries:
                budget['entries'] += 1
                require(budget['entries'] <= d.MAX_ENTRIES and time.monotonic() - budget['start'] <= d.MAX_SECONDS,
                        'Directory access scan exceeded bounded budget')
                if d.private_name(entry.name): skip('private_or_cache'); continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode): skip('symlink'); continue
                if not stat.S_ISDIR(info.st_mode): skip('non_directory'); continue
                if info.st_uid not in {human_uid, service_uid}: skip('foreign_owner'); continue
                try:
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except PermissionError:
                    skip('inaccessible_ordinary_directory'); remaining[0] += 1; continue
                try:
                    actual = os.fstat(child)
                    require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino), 'Directory changed during scan')
                    visit(child, workspace, entry.name if relative == '.' else relative + '/' + entry.name,
                          root_dev, root_mount, depth + 1)
                finally: os.close(child)
        require(d.identity(fd) == before and d.xattr(fd, d.DEFAULT) == default, 'Directory metadata changed during scan')
    for workspace, path in roots.items():
        fd = d.open_root(Path(path))
        try:
            root_ids[workspace] = d.identity(fd)
            visit(fd, workspace, '.', root_ids[workspace]['dev'], root_ids[workspace]['mount_id'], 0)
        finally: os.close(fd)
    # Children first: parent ACL changes must not invalidate descendant checks.
    records.sort(key=lambda row: (-len(Path(row['relative']).parts) if row['relative'] != '.' else 0,
                                  row['workspace'], row['relative']))
    value = {'version': 1, 'workspaces': sorted(roots), 'config_hashes': {n: d.digest(inputs[n]) for n in storage.FILES},
             'roots': root_ids, 'records': records, 'skipped': skipped, 'directories_scanned': budget['dirs'],
             'remaining_human_access_blockers': remaining[0]}
    require(len(d.canonical(value)) <= d.MAX_PLAN, 'Private access plan exceeds metadata bound')
    return value


def current_allowed(d, fd, row, rollback=False):
    current = d.identity(fd)
    before = row['before']
    require(envelope(current, before) and current['uid'] != 1000, 'Directory identity/owner changed')
    require(d.xattr(fd, d.DEFAULT) == d.unb64(row['default']), 'Directory default ACL changed')
    original = current['mode'] == before['mode'] and current['access'] == before['access']
    target = current['mode'] == row['mode_after'] and current['access'] == row['access_after']
    require(original or target if rollback else current == before, 'Directory access changed since plan')
    return current


def root_allowed(d, fd, before, record):
    current = d.identity(fd)
    require(envelope(current, before), 'Workspace root identity changed')
    original = current['mode'] == before['mode'] and current['access'] == before['access']
    target = record is not None and current['mode'] == record['mode_after'] and current['access'] == record['access_after']
    require(original or target, 'Workspace root access changed')


def mutate(d, roots, document, recovery_fd, rollback=False):
    root_records = {row['workspace']: row for row in document['plan']['records'] if row['relative'] == '.'}
    opened = []
    def open_row(row):
        root = d.open_root(Path(roots[row['workspace']]))
        try:
            root_allowed(d, root, document['plan']['roots'][row['workspace']], root_records.get(row['workspace']))
            return d.open_relative(root, row['relative'])
        finally: os.close(root)
    def save(): d.write_private(recovery_fd, 'journal.json', {k: v for k, v in document.items() if k != 'plan'})
    try:
        for row in document['plan']['records']:
            fd = open_row(row)
            try: verified = current_allowed(d, fd, row, rollback)
            except BaseException: os.close(fd); raise
            opened.append((fd, row, verified))
        document['phase'] = 'rolling_back' if rollback else 'applying'; document['completed_directories'] = 0; save()
        for fd, row, verified in reversed(opened) if rollback else opened:
            check = open_row(row)
            try: require(d.identity(check) == verified, 'Repair path changed immediately before access update')
            finally: os.close(check)
            require(d.identity(fd) == verified and d.xattr(fd, d.DEFAULT) == d.unb64(row['default']),
                    'Directory ACL/default changed immediately before access update')
            value = d.unb64(row['before']['access'] if rollback else row['access_after'])
            if value is None:
                # A minimal access ACL restores mode bits and Linux removes the
                # redundant xattr itself; no chmod is used, even during rollback.
                mode = row['before']['mode']
                value = d.encode_acl({(d.UOBJ, d.UNDEF): (mode >> 6) & 7,
                                      (d.GOBJ, d.UNDEF): (mode >> 3) & 7, (d.OTHER, d.UNDEF): mode & 7})
            os.setxattr(fd, d.ACCESS, value); os.fsync(fd)
            after = d.identity(fd)
            expected_mode = row['before']['mode'] if rollback else row['mode_after']
            expected_access = row['before']['access'] if rollback else row['access_after']
            require(envelope(after, row['before']) and after['mode'] == expected_mode and after['access'] == expected_access
                    and d.xattr(fd, d.DEFAULT) == d.unb64(row['default']), 'Unexpected metadata change after access repair')
            document['completed_directories'] += 1; save()
        document['phase'] = 'rolled_back' if rollback else 'applied'; save()
    finally:
        for fd, row, verified in opened: os.close(fd)


def apply(d, storage, inputs, names, expected, state_fd, human_uid=1000, service_uid=994):
    value = plan(d, storage, inputs, names, human_uid, service_uid)
    require(d.digest(d.canonical(value)) == expected, 'Access repair plan changed; no access modified')
    if not value['records']: return {'already_compliant': True, 'modified_directories': 0}
    name = 'access-' + expected
    os.mkdir(name, 0o700, dir_fd=state_fd)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        document = {'plan_sha256': expected, 'phase': 'prepared', 'plan': value}
        d.write_private(fd, 'plan.json', value)
        d.write_private(fd, 'journal.json', {k: v for k, v in document.items() if k != 'plan'})
        os.fsync(state_fd)
        mutate(d, d.authorize(storage, inputs, names), document, fd)
    finally: os.close(fd)
    return {'modified_directories': len(value['records']), 'recovery': name,
            'remaining_human_access_blockers': value['remaining_human_access_blockers']}


def rollback(d, storage, inputs, names, expected, state_fd):
    require(re.fullmatch('[0-9a-f]{64}', expected or ''), 'Explicit access plan SHA required')
    fd = os.open('access-' + expected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        info = os.fstat(fd); require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe access recovery directory')
        def read(name):
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(file)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= d.MAX_PLAN, 'Unsafe access backup metadata')
                with os.fdopen(file, 'rb', closefd=False) as stream: return json.loads(stream.read(d.MAX_PLAN + 1))
            finally: os.close(file)
        document = read('journal.json'); document['plan'] = read('plan.json')
        require(document['plan_sha256'] == expected and d.digest(d.canonical(document['plan'])) == expected
                and sorted(names) == document['plan']['workspaces'], 'Access recovery plan/scope mismatch')
        mutate(d, d.authorize(storage, inputs, names), document, fd, rollback=True)
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument('--workspace', action='append'); targets.add_argument('--all-writable', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true'); mode.add_argument('--rollback', action='store_true')
    parser.add_argument('--list-workspaces', action='store_true'); parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    storage, d = dependencies()
    require(pwd.getpwnam('agentporter-dev').pw_uid == 994 and pwd.getpwnam('yeli').pw_uid == 1000, 'Unexpected accounts')
    def read_config():
        fd = storage.open_directory(storage.CONFIG, 994)
        try: return {name: storage.private_read(fd, name, 994) for name in storage.FILES}
        finally: os.close(fd)
    inputs = read_config()
    names, excluded = d.choose_all(storage, inputs) if args.all_writable else (args.workspace, [])
    require(names, 'No writable workspaces selected'); d.authorize(storage, inputs, names)
    if args.list_workspaces:
        require(not args.apply and not args.rollback, 'Scope enumeration is read-only')
        result = {'selected_workspaces': names, 'excluded_workspaces': excluded,
                  'config_sha256': d.digest(d.canonical({name: d.digest(inputs[name]) for name in storage.FILES}))}
    elif args.apply or args.rollback:
        require(re.fullmatch('[0-9a-f]{64}', args.expected_plan_sha256 or ''), 'Explicit access plan SHA required')
        d.quiet(storage); require(read_config() == inputs, 'Workspace configuration changed; replan')
        parent = d.open_root(STATE.parent)
        try:
            require(os.fstat(parent).st_uid == 994 and stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, 'Unsafe private service state')
            try: os.mkdir(STATE.name, 0o700, dir_fd=parent)
            except FileExistsError: pass
            state = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            require(os.fstat(state).st_uid == 994 and stat.S_IMODE(os.fstat(state).st_mode) == 0o700, 'Unsafe access repair state')
            os.fsync(parent)
        finally: os.close(parent)
        try:
            lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=state)
            try:
                info = os.fstat(lock)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 994 and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe access repair lock')
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.rollback:
                    rollback(d, storage, inputs, names, args.expected_plan_sha256, state); result = {'rolled_back': True}
                else: result = apply(d, storage, inputs, names, args.expected_plan_sha256, state)
            finally: os.close(lock)
        finally: os.close(state)
    else:
        value = plan(d, storage, inputs, names)
        result = {'plan_sha256': d.digest(d.canonical(value)), 'selected_workspaces': names,
                  'directories_to_modify': len(value['records']), 'remaining_human_access_blockers': value['remaining_human_access_blockers'],
                  'skipped_counts': value['skipped']}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
