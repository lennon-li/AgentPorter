#!/usr/bin/python3
"""Bounded, root-only default-ACL repair for existing owner-authorized A7Dev roots.

Plans are read-only. No file contents/access ACLs/ownership are changed. Apply
requires quiet development, stopped discovery, an exact plan hash and durable
root-private metadata backup. Never import project code or start services.
"""
import argparse
import base64
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys
import time

INSTALLED = Path('/opt/agentporter-development/activation-tools/directory-defaults/repair-a7dev-shared-directory-defaults.py')
STORAGE_SHA = 'b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b'
STATE = Path('/var/lib/agentporter-dev-directory-defaults')
DEFAULT = 'system.posix_acl_default'
ACCESS = 'system.posix_acl_access'
MAX_ENTRIES, MAX_DIRS, MAX_DEPTH, MAX_SECONDS = 50000, 2000, 24, 60
MAX_PLAN = 16 * 1024**2
SKIP = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.cache', 'cache', 'caches',
        '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox', '.nox', '.ssh', '.aws', '.codex',
        '.agents', '.development', '.claude', '.copilot', '.copilot-phil', '.opencode',
        '.github-copilot', '.antigravitycli', '.gemini', '.config', '.local', '.gnupg', 'runtime',
        'auth.json', 'credentials.json', '.credentials.json', 'credentials', 'secrets', '.secrets',
        'id_rsa', 'id_ed25519', '.bashrc', '.bash_profile', '.profile', '.zshrc'}
UOBJ, USER, GOBJ, GROUP, MASK, OTHER, UNDEF = 1, 2, 4, 8, 16, 32, 0xffffffff


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def b64(value):
    return None if value is None else base64.b64encode(value).decode('ascii')


def unb64(value):
    return None if value is None else base64.b64decode(value, validate=True)


def xattr(fd, name):
    try:
        value = os.getxattr(fd, name)
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise RuntimeError('ACL metadata unavailable') from None
    require(len(value) <= 16384, 'ACL metadata exceeds bound')
    return value


def decode_acl(value):
    require(value is not None and len(value) >= 4 and (len(value) - 4) % 8 == 0
            and struct.unpack_from('<I', value)[0] == 2, 'Invalid POSIX ACL metadata')
    entries = {}
    for tag, perm, uid in struct.iter_unpack('<HHI', value[4:]):
        require(tag in {UOBJ, USER, GOBJ, GROUP, MASK, OTHER} and 0 <= perm <= 7
                and (uid != UNDEF if tag in {USER, GROUP} else uid == UNDEF)
                and (tag, uid) not in entries, 'Invalid POSIX ACL entry')
        entries[tag, uid] = perm
    require(all((tag, UNDEF) in entries for tag in (UOBJ, GOBJ, OTHER)), 'Incomplete POSIX ACL')
    require(not any(tag in {USER, GROUP} for tag, uid in entries) or (MASK, UNDEF) in entries,
            'Named POSIX ACL entry requires mask')
    return entries


def encode_acl(entries):
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, value, uid)
                                         for (tag, uid), value in sorted(entries.items()))


def repaired_default(value, human_uid, service_uid):
    entries = decode_acl(value) if value is not None else {
        (UOBJ, UNDEF): 7, (GOBJ, UNDEF): 0, (OTHER, UNDEF): 0, (USER, service_uid): 0}
    old_mask = entries.get((MASK, UNDEF), 7)
    # Preserve every other named/group entry's EFFECTIVE rights before widening.
    for key in entries:
        if key[0] in {USER, GOBJ, GROUP}:
            entries[key] &= old_mask
    entries[USER, human_uid] = 7
    entries[MASK, UNDEF] = 0
    for (tag, uid), value in entries.items():
        if tag in {USER, GOBJ, GROUP}:
            entries[MASK, UNDEF] |= value
    return encode_acl(entries)



def human_access(fd, uid, groups):
    info = os.fstat(fd)
    raw = xattr(fd, ACCESS)
    entries = decode_acl(raw) if raw is not None else {
        (UOBJ, UNDEF): (info.st_mode >> 6) & 7, (GOBJ, UNDEF): (info.st_mode >> 3) & 7,
        (OTHER, UNDEF): info.st_mode & 7}
    if info.st_uid == uid: return entries[UOBJ, UNDEF]
    mask = entries.get((MASK, UNDEF), 7)
    if (USER, uid) in entries: return entries[USER, uid] & mask
    matches = [value for (tag, ident), value in entries.items() if tag == GROUP and ident in groups]
    if info.st_gid in groups: matches.append(entries[GOBJ, UNDEF])
    if matches:
        combined = 0
        for value in matches: combined |= value
        return combined & mask
    return entries[OTHER, UNDEF]


def private_name(name):
    low = name.lower()
    return low in SKIP or low.startswith(('.codex-', '.env')) or low.endswith(('.env', '.pem', '.key'))


def identity(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode), 'Directory changed type')
    return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'mount_id': mount_id(fd), 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
            'access': b64(xattr(fd, ACCESS))}


def mount_id(fd):
    with open(f'/proc/self/fdinfo/{fd}', 'r', encoding='ascii') as stream:
        lines = stream.read(4096).splitlines()
    values = [line.split(':', 1)[1].strip() for line in lines if line.startswith('mnt_id:')]
    require(len(values) == 1 and values[0].isdigit(), 'Mount identity unavailable')
    return int(values[0])


def open_root(path):
    require(path.is_absolute() and str(path) == os.path.realpath(path), 'Noncanonical workspace root')
    parts = path.parts[1:]
    # Ancestors require traversal, not directory-listing access. In particular,
    # the service has an execute-only ACL on /home and the owner's home.
    # Keep a readable descriptor for the final root used by scans and xattrs.
    ancestor_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', ancestor_flags if parts else root_flags)
    try:
        for index, name in enumerate(parts):
            flags = root_flags if index == len(parts) - 1 else ancestor_flags
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_relative(root_fd, relative):
    parts = [] if relative == '.' else relative.split('/')
    require(all(part not in {'', '.', '..'} and not private_name(part) for part in parts), 'Unsafe repair path')
    fd = os.dup(root_fd)
    try:
        for name in parts:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def authorize(storage, inputs, names):
    try:
        import yaml
        policy, registry, runtime = [yaml.load(inputs[n], Loader=storage.UniqueLoader) for n in storage.FILES]
    except Exception:
        raise RuntimeError('Invalid private workspace configuration') from None
    require(isinstance(names, list) and names and len(set(names)) == len(names), 'Explicit unique workspaces required')
    require(runtime.get('enabled') is True and runtime.get('profile') == 'development', 'Development runtime required')
    roots = runtime.get('allowed_workspace_roots')
    require(isinstance(roots, list) and all(isinstance(row, dict) and set(row) == {'path', 'writable'}
            and isinstance(row['path'], str) and type(row['writable']) is bool for row in roots), 'Invalid runtime roots')
    require(len({row['path'] for row in roots}) == len(roots), 'Duplicate runtime roots')
    approved = {}
    for name in sorted(names):
        require(name in storage.EXPECTED_ROOTS and name not in storage.PROTECTED, 'Protected/unknown workspace')
        path = storage.EXPECTED_ROOTS[name]
        row = registry.get('workspaces', {}).get(name, {})
        scope = policy.get('workspaces', {}).get(name, {})
        require(row.get('path') == scope.get('path') == path
                and all(row.get(key) is True for key in ('writable', 'allow_execute', 'allow_agent_dispatch'))
                and {'write', 'dispatch', 'dispatch_write'} <= set(scope.get('operations', []))
                and {'path': path, 'writable': True} in roots, 'Workspace lacks effective writable scope')
        require(not any(other['path'] != path and Path(other['path']).is_relative_to(path) for other in roots),
                'Workspace is an overlapping parent')
        approved[name] = path
    return approved


def choose_all(storage, inputs):
    selected, excluded = [], []
    for name in sorted(storage.EXPECTED_ROOTS):
        try:
            authorize(storage, inputs, [name])
        except (RuntimeError, ValueError, TypeError, AttributeError):
            excluded.append(name)
        else:
            selected.append(name)
    return selected, excluded


def plan(storage, inputs, names, human_uid=1000, service_uid=994):
    approved = authorize(storage, inputs, names)
    records, root_ids, skipped = [], {}, {}
    account = pwd.getpwuid(human_uid)
    human_groups = set(os.getgrouplist(account.pw_name, account.pw_gid))
    access_blockers = [0]
    budget = {'entries': 0, 'dirs': 0, 'start': time.monotonic()}
    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1
    def visit(fd, workspace, relative, root_dev, root_mount, depth):
        budget['dirs'] += 1
        require(budget['dirs'] <= MAX_DIRS and time.monotonic() - budget['start'] <= MAX_SECONDS,
                'Directory repair scan exceeded bounded budget')
        require(depth <= MAX_DEPTH, 'Directory repair depth bound exceeded')
        before = identity(fd)
        if before['dev'] != root_dev or mount_id(fd) != root_mount:
            skip('mount_boundary'); return
        if before['uid'] not in {human_uid, service_uid}:
            skip('foreign_owner'); return
        if not before['mode'] & 0o222 or os.fstatvfs(fd).f_flag & os.ST_RDONLY:
            skip('read_only'); return
        if human_access(fd, human_uid, human_groups) != 7:
            access_blockers[0] += 1
        original = xattr(fd, DEFAULT)
        target = repaired_default(original, human_uid, service_uid)
        if original != target:
            records.append({'workspace': workspace, 'relative': relative, 'before': before,
                            'default_before': b64(original), 'default_after': b64(target)})
        with os.scandir(fd) as entries:
            for entry in entries:
                budget['entries'] += 1
                require(budget['entries'] <= MAX_ENTRIES and time.monotonic() - budget['start'] <= MAX_SECONDS,
                        'Directory repair scan exceeded bounded budget')
                if private_name(entry.name):
                    skip('private_or_cache'); continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    skip('symlink'); continue
                if not stat.S_ISDIR(info.st_mode):
                    skip('non_directory'); continue
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    actual = os.fstat(child)
                    require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino), 'Directory changed during scan')
                    visit(child, workspace, entry.name if relative == '.' else relative + '/' + entry.name,
                          root_dev, root_mount, depth + 1)
                finally:
                    os.close(child)
        require(identity(fd) == before and xattr(fd, DEFAULT) == original, 'Directory metadata changed during scan')
    for workspace, path in approved.items():
        fd = open_root(Path(path))
        try:
            root_ids[workspace] = identity(fd)
            visit(fd, workspace, '.', root_ids[workspace]['dev'], mount_id(fd), 0)
        finally:
            os.close(fd)
    result = {'version': 1, 'workspaces': sorted(approved), 'config_hashes': {n: digest(inputs[n]) for n in storage.FILES},
              'roots': root_ids, 'records': sorted(records, key=lambda row: (row['workspace'], row['relative'])),
              'skipped': skipped, 'existing_human_access_blockers': access_blockers[0], 'directories_scanned': budget['dirs'], 'entries_scanned': budget['entries']}
    require(len(canonical(result)) <= MAX_PLAN, 'Private repair plan exceeds metadata bound')
    return result


def stable_identity(current, before):
    return all(current[key] == before[key] for key in ('dev', 'ino', 'uid', 'gid', 'mode', 'mount_id', 'access'))


def write_private(fd, name, document):
    data = canonical(document) + b'\n'
    require(len(data) <= MAX_PLAN, 'Repair journal exceeds bound')
    temporary = '.journal-' + __import__('secrets').token_hex(12)
    file = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(file, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(file)
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(file)
        try: os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError: pass


def save_journal(fd, document):
    write_private(fd, 'journal.json', {key: value for key, value in document.items() if key != 'plan'})


def mutate(storage, approved, document, recovery_fd, rollback=False):
    # Verify ALL original identities and ACLs before changing any directory.
    opened = []
    try:
        for row in document['plan']['records']:
            root = open_root(Path(approved[row['workspace']]))
            try:
                require(stable_identity(identity(root), document['plan']['roots'][row['workspace']]), 'Workspace root identity changed')
                fd = open_relative(root, row['relative'])
            finally:
                os.close(root)
            opened.append((fd, row, identity(fd), xattr(fd, DEFAULT)))
            current = identity(fd)
            require(stable_identity(current, row['before']), 'Directory identity/access changed')
            original, target = unb64(row['default_before']), unb64(row['default_after'])
            current_default = xattr(fd, DEFAULT)
            require(current_default in (original, target) if rollback else
                    current == row['before'] and current_default == original, 'Directory changed since plan')
        document['phase'] = 'rolling_back' if rollback else 'applying'
        save_journal(recovery_fd, document)
        for fd, row, verified_identity, verified_default in reversed(opened) if rollback else opened:
            # Reopen the exact path to catch a rename/replacement after validation.
            root = open_root(Path(approved[row['workspace']]))
            try:
                check = open_relative(root, row['relative'])
            finally:
                os.close(root)
            try:
                require(identity(check) == verified_identity, 'Repair path identity changed')
                require(os.fstat(check).st_ino == os.fstat(fd).st_ino, 'Repair descriptor identity changed')
            finally:
                os.close(check)
            before_access = identity(fd)
            require(before_access == verified_identity and xattr(fd, DEFAULT) == verified_default,
                    'Directory ACL/metadata changed immediately before repair')
            value = unb64(row['default_before'] if rollback else row['default_after'])
            if value is None:
                if xattr(fd, DEFAULT) is not None: os.removexattr(fd, DEFAULT)
            else:
                os.setxattr(fd, DEFAULT, value)
            os.fsync(fd)
            require(stable_identity(identity(fd), before_access) and xattr(fd, DEFAULT) == value,
                    'Unexpected access ACL/ownership/mode change')
            document['completed_directories'] = document.get('completed_directories', 0) + 1
            save_journal(recovery_fd, document)
        document['phase'] = 'rolled_back' if rollback else 'applied'
        save_journal(recovery_fd, document)
    finally:
        for fd, row, verified_identity, verified_default in opened: os.close(fd)


def apply(storage, inputs, names, expected, state_fd, human_uid=1000, service_uid=994):
    current = plan(storage, inputs, names, human_uid, service_uid)
    require(digest(canonical(current)) == expected, 'Repair plan changed; no defaults modified')
    if not current['records']:
        return {'already_compliant': True, 'modified_directories': 0}
    name = 'defaults-' + expected
    os.mkdir(name, 0o700, dir_fd=state_fd)  # Existing backups are never overwritten.
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        document = {'plan_sha256': expected, 'phase': 'prepared', 'plan': current}
        write_private(fd, 'plan.json', current)  # Durable immutable original metadata BEFORE first mutation.
        save_journal(fd, document)
        os.fsync(state_fd)
        mutate(storage, authorize(storage, inputs, names), document, fd)
    finally:
        os.close(fd)
    return {'modified_directories': len(current['records']), 'recovery': name}


def rollback(storage, inputs, names, expected, state_fd):
    require(re.fullmatch('[0-9a-f]{64}', expected or ''), 'Explicit repair plan SHA required')
    fd = os.open('defaults-' + expected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        info = os.fstat(fd); require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe recovery directory')
        def read_record(name):
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(file)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_PLAN, 'Unsafe recovery metadata')
                with os.fdopen(file, 'rb', closefd=False) as stream: return json.loads(stream.read(MAX_PLAN + 1))
            finally: os.close(file)
        document = read_record('journal.json')
        document['plan'] = read_record('plan.json')
        require(document['plan_sha256'] == expected and digest(canonical(document['plan'])) == expected
                and sorted(names) == document['plan']['workspaces'], 'Recovery plan hash/workspace mismatch')
        mutate(storage, authorize(storage, inputs, names), document, fd, rollback=True)
    finally: os.close(fd)


def trusted_storage():
    require(os.geteuid() == 0 and Path(__file__) == INSTALLED and sys.flags.isolated,
            'Run only immutable installed root helper with python3 -I')
    source = INSTALLED.with_name('authorize-a7dev-project-delegation.py')
    for path in (INSTALLED, source):
        for item in (path, *path.parents):
            info = item.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Untrusted installed helper/ancestor')
        require(stat.S_IMODE(path.stat().st_mode) == 0o555, 'Helper must be immutable mode0555')
    require(digest(source.read_bytes()) == STORAGE_SHA, 'Storage helper SHA changed')
    spec = importlib.util.spec_from_file_location('directory_default_storage', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def quiet(storage):
    storage.quiet_and_stopped()
    for unit in ('agentporter-dev-autodiscovery.timer', 'agentporter-dev-autodiscovery.service'):
        result = subprocess.run(['/usr/bin/systemctl', 'is-active', unit], capture_output=True, text=True, timeout=10)
        require(result.returncode == 3 and result.stdout.strip() in {'inactive', 'failed'}, 'Stop discovery timer/service before default repair')
    require(not Path('/sys/fs/cgroup/system.slice/agentporter-dev-autodiscovery.service').exists(), 'Discovery cgroup still active')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument('--workspace', action='append')
    targets.add_argument('--all-writable', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true'); mode.add_argument('--rollback', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--list-workspaces', action='store_true', help='Read-only scope enumeration without traversing project trees')
    args = parser.parse_args()
    storage = trusted_storage()
    human, service = pwd.getpwnam('yeli').pw_uid, pwd.getpwnam('agentporter-dev').pw_uid
    require((human, service) == (1000, 994), 'Unexpected human/service identity')
    config = storage.open_directory(storage.CONFIG, service)
    try: inputs = {name: storage.private_read(config, name, service) for name in storage.FILES}
    finally: os.close(config)
    names, excluded = choose_all(storage, inputs) if args.all_writable else (args.workspace, [])
    require(names, 'No authorized writable workspaces selected')
    authorize(storage, inputs, names)
    if args.list_workspaces:
        require(not args.apply and not args.rollback, 'Scope enumeration is read-only')
        print(json.dumps({'selected_workspaces': names, 'selected_count': len(names),
                          'excluded_workspaces': excluded, 'excluded_count': len(excluded),
                          'config_sha256': digest(canonical({name: digest(inputs[name]) for name in storage.FILES}))}, sort_keys=True))
        return
    if args.apply or args.rollback:
        require(re.fullmatch('[0-9a-f]{64}', args.expected_plan_sha256 or ''), 'Explicit repair plan SHA required')
        quiet(storage)
        latest = storage.open_directory(storage.CONFIG, service)
        try:
            require(inputs == {name: storage.private_read(latest, name, service) for name in storage.FILES},
                    'Workspace configuration changed; replan')
        finally: os.close(latest)
        # Fixed root-owned private state only; never an arbitrary output path.
        parent = open_root(STATE.parent)
        try:
            require(os.fstat(parent).st_uid == 0 and not os.fstat(parent).st_mode & 0o022, 'Unsafe state parent')
            try: os.mkdir(STATE.name, 0o700, dir_fd=parent)
            except FileExistsError: pass
            state = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            require(os.fstat(state).st_uid == 0 and stat.S_IMODE(os.fstat(state).st_mode) == 0o700, 'Unsafe repair state')
            os.fsync(parent)  # Persist the root-private state directory entry before backup use.
        finally: os.close(parent)
        try:
            require(os.fstat(state).st_uid == 0 and stat.S_IMODE(os.fstat(state).st_mode) == 0o700, 'Unsafe repair state')
            lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=state)
            try:
                info = os.fstat(lock)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe repair lock')
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.rollback:
                    rollback(storage, inputs, names, args.expected_plan_sha256, state)
                    result = {'rolled_back': True}
                else: result = apply(storage, inputs, names, args.expected_plan_sha256, state, human, service)
            finally: os.close(lock)
        finally: os.close(state)
    else:
        value = plan(storage, inputs, names, human, service)
        result = {'plan_sha256': digest(canonical(value)), 'selected_workspaces': names,
                  'selected_count': len(names), 'excluded_count': len(excluded), 'excluded_workspaces': excluded,
                  'directories_to_modify': len(value['records']),
                  'existing_human_access_blockers': value['existing_human_access_blockers'], 'directories_scanned': value['directories_scanned'],
                  'skipped_counts': value['skipped']}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
