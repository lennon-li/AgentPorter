#!/usr/bin/python3
"""A7Dev descriptor-pinned reconciliation. Default is a read-only plan.

Installed root entry point only; --admission-barrier is the service-UID child.
No imports from project code, credentials, shell execution or remote networking.
"""
import argparse
import base64
import contextlib
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import sqlite3
import stat
import subprocess
import sys
import time

import yaml

INSTALLED = '/opt/agentporter-autodiscovery/autodiscover-a7dev.py'
CONFIG = '/var/lib/agentporter-dev/config'
STATE = '/var/lib/agentporter-dev-autodiscovery'
JOBS = '/var/lib/agentporter-dev/state/jobs.db'
REPOS = '/home/yeli/repos'
SERVICE = 'agentporter-development.service'
FILES = ('workspaces.yaml', 'public-client-policy.yaml', 'development-runtime.yaml')
LIMIT = 65536
PROTECTED = {'obsidian', 'agentporter', 'AgentPorter', 'repos', 'asgard-hermes-review'}
MASK_DIRS = {'.ssh', '.aws', '.codex', '.agents', '.development', '.claude', '.copilot',
             '.copilot-phil', '.opencode', '.github-copilot', '.antigravitycli', '.gemini', 'runtime'}
TERMINAL = {'completed', 'failed', 'cancelled', 'timed_out', 'output_limit_exceeded', 'interrupted'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        require(not self.check_event(yaml.AliasEvent), 'YAML aliases forbidden')
        require(self.peek_event().anchor is None, 'YAML anchors forbidden')
        return super().compose_node(parent, index)


def mapping(loader, node, deep=False):
    result = {}
    for keynode, valnode in node.value:
        key = loader.construct_object(keynode, deep=deep)
        require(isinstance(key, str) and key not in result, 'Duplicate/nonstring YAML key')
        result[key] = loader.construct_object(valnode, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load_yaml(body):
    require(len(body) <= LIMIT, 'Oversized YAML')
    result = yaml.load(body, Loader=StrictLoader)
    require(isinstance(result, dict), 'Expected YAML mapping')
    return result


def private_name(name):
    lower = name.lower()
    sensitive = {'id_rsa', 'id_ed25519', 'secrets.env', '.bashrc', '.bash_profile', '.profile', '.zshrc',
                 '.gnupg', 'auth.json', 'credentials.json', '.config', '.cache', '.local', '.npm', '.npmrc',
                 '.netrc', '.pypirc', '.docker', '.kube', '.azure', '.git-credentials', '.gitconfig',
                 '.yarnrc', '.yarnrc.yml'}
    return (lower in MASK_DIRS or lower in sensitive or lower.startswith('.codex-')
            or lower.startswith('.env') or lower.endswith(('.env', '.pem', '.key'))
            or (lower == '.git' and name != '.git'))


@contextlib.contextmanager
def directory(path):
    """Open every component without following links, including ancestors."""
    path = os.fspath(path)
    require(os.path.isabs(path) and os.path.normpath(path) == path, 'Noncanonical directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.split('/')[1:]:
            if not name:
                continue
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def metadata(fd, uid, mode=None):
    s = os.fstat(fd)
    require(s.st_uid == uid, 'Unexpected owner')
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'Unexpected private permissions')
    return s


def private_read(fd, name, uid, limit=LIMIT):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        s = metadata(f, uid, 0o600)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= limit, 'Unsafe private file')
        body = os.read(f, limit + 1)
        require(len(body) <= limit, 'Oversized control file')
        return body
    finally:
        os.close(f)


def atomic_write(fd, name, body, uid):
    temporary = '.autodiscover-' + secrets.token_hex(16)
    f = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchown(f, uid, -1)
        with os.fdopen(f, 'wb', closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(f)
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(f)
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def mount_id(fd):
    # st_dev alone misses same-device bind mounts. proc fdinfo describes the
    # already pinned descriptor, not the user-controlled directory pathname.
    with open(f'/proc/self/fdinfo/{fd}', encoding='ascii') as stream:
        for line in stream:
            if line.startswith('mnt_id:'):
                return int(line.split()[1])
    raise ValueError('Missing descriptor mount identity')


def bounded_names(fd, limit):
    with os.scandir(fd) as entries:
        for count, entry in enumerate(entries):
            require(count < limit, 'Directory entry bound exceeded')
            yield entry.name


def discover(parent_fd, parent_path, owner):
    parent = os.fstat(parent_fd)
    result = {}
    for name in sorted(bounded_names(parent_fd, 10000)):
        if (name in PROTECTED or private_name(name) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name)):
            continue
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            continue
        try:
            s = os.fstat(fd)
            if s.st_uid == owner and s.st_dev == parent.st_dev and mount_id(fd) == mount_id(parent_fd):
                result[name] = {'path': parent_path + '/' + name, 'dev': s.st_dev, 'ino': s.st_ino}
        finally:
            os.close(fd)
    return result


def pin_candidate(parent, name, row, owner):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        s = os.fstat(fd)
        require(s.st_uid == owner and s.st_dev == row['dev'] and s.st_ino == row['ino'] and mount_id(fd) == mount_id(parent), 'Candidate replaced/owner changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def profile(path):
    return {'path': path, 'writable': True, 'allow_execute': True, 'allow_git': True,
            'allow_artifacts': True, 'allow_agent_dispatch': True, 'auto_discover': False,
            'local_http_ports': [], 'allow_venkata_ssh': False, 'allow_venkata_transfer': False,
            'allow_scinet_diagnostic': False, 'allow_scinet_training': False}


def generated(path):
    return {'registry': profile(path), 'policy': {'path': path, 'operations': ['read', 'write', 'git_read', 'exec', 'dispatch']},
            'runtime': {'path': path, 'writable': False}}


def plan(documents, managed, candidates):
    docs = copy.deepcopy(documents)
    registry = docs[FILES[0]]['workspaces']
    policy = docs[FILES[1]]['workspaces']
    runtime = docs[FILES[2]]['allowed_workspace_roots']
    require(isinstance(registry, dict) and isinstance(policy, dict) and set(docs[FILES[1]]) == {'version', 'workspaces'}
            and type(docs[FILES[1]].get('version')) is int and docs[FILES[1]]['version'] == 1, 'Malformed configuration')
    require(isinstance(runtime, list) and 1 <= len(runtime) <= 64, 'Runtime root capacity/shape')
    for rows in (registry, policy):
        require(all(isinstance(k, str) and isinstance(v, dict) and isinstance(v.get('path'), str) for k, v in rows.items()), 'Invalid row')
    for name, row in policy.items():
        require(set(row) == {'path', 'operations'} and name in registry and row['path'] == registry[name]['path']
                and isinstance(row['operations'], list) and all(isinstance(op, str) and op in
                {'read', 'write', 'exec', 'https', 'git_read', 'git_write', 'dispatch'} for op in row['operations'])
                and len(set(row['operations'])) == len(row['operations']), 'Invalid public policy row')
    require(all(isinstance(r, dict) and set(r) == {'path', 'writable'} and isinstance(r['path'], str)
                and type(r['writable']) is bool for r in runtime), 'Invalid runtime row')
    require(len({r['path'] for r in runtime}) == len(runtime), 'Duplicate runtime roots')
    state = copy.deepcopy(managed)
    report = {'added': [], 'removed': [], 'pending': [], 'overridden': [], 'overlaps': [], 'revoked': []}
    matched = set()
    for name, old in state.items():
        require(isinstance(old, dict) and set(old) == {'identity', 'rows'}, 'Invalid managed state')
        expected = old['rows']
        require(expected == generated(old['identity']['path']) and name not in PROTECTED, 'Invalid generated managed row')
        if (registry.get(name) == expected['registry'] and policy.get(name) == expected['policy']
                and expected['runtime'] in runtime):
            matched.add(name)
    authoritative = {row['path'] for rows in (registry, policy) for name, row in rows.items() if name not in matched}
    auto_runtime = [state[name]['rows']['runtime'] for name in matched]
    authoritative.update(row['path'] for row in runtime if row not in auto_runtime)
    for name, old in list(state.items()):
        require(isinstance(old, dict) and set(old) == {'identity', 'rows'}, 'Invalid managed state')
        expected = old['rows']
        require(expected == generated(old['identity']['path']) and name not in PROTECTED, 'Invalid generated managed row')
        # A single explicit edit relinquishes all authority over this managed row.
        matches = (registry.get(name) == expected['registry'] and policy.get(name) == expected['policy']
                   and expected['runtime'] in runtime)
        if not matches:
            del state[name]
            report['overridden'].append(name)
        elif any(p != REPOS and (Path(expected['registry']['path']).is_relative_to(p)
                or Path(p).is_relative_to(expected['registry']['path'])) for p in authoritative):
            del registry[name]
            del policy[name]
            # Same-path aliases independently retain the unique runtime row.
            if expected['runtime']['path'] not in authoritative:
                runtime.remove(expected['runtime'])
            del state[name]
            report['revoked'].append(name)
        elif candidates.get(name) != old['identity']:
            del registry[name]
            del policy[name]
            runtime.remove(expected['runtime'])
            del state[name]
            report['removed'].append(name)
    paths = {r['path'] for r in registry.values()} | {r['path'] for r in policy.values()} | {r['path'] for r in runtime}
    for name, identity in sorted(candidates.items()):
        path = identity['path']
        if name in PROTECTED or name in registry or name in policy or path in paths:
            continue
        overlaps = [p for p in paths if p != REPOS and (Path(path).is_relative_to(p) or Path(p).is_relative_to(path))]
        if overlaps:
            report['overlaps'].append(name)
            continue
        if len(runtime) >= 64:
            report['pending'].append(name)
            continue
        rows = generated(path)
        registry[name] = rows['registry']
        policy[name] = rows['policy']
        runtime.append(rows['runtime'])
        state[name] = {'identity': copy.deepcopy(identity), 'rows': copy.deepcopy(rows)}
        paths.add(path)
        report['added'].append(name)
    require(1 <= len(runtime) <= 64, 'Reconciliation would invalidate runtime capacity')
    return docs, state, report


def acl_entries(fd):
    text = subprocess.check_output(['/usr/bin/getfacl', '-cpn', '--', f'/proc/self/fd/{fd}'],
                                   pass_fds=(fd,), text=True, timeout=15)
    entries = {}
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            parts = line.split(':')
            entries[':'.join(parts[:-1])] = parts[-1]
    return entries


def set_acl(fd, recipient, access, default=False):
    entries = acl_entries(fd)
    changes = []
    # Expanding the mask must not restore permissions previously masked from
    # unrelated named users/groups. Preserve their existing effective rights.
    for prefix in ('', 'default:'):
        mask = entries.get(prefix + 'mask:', 'rwx')
        for key, bits in entries.items():
            if key.startswith('default:') != bool(prefix):
                continue
            local = key[len(prefix):]
            if (local.startswith('group:') or (local.startswith('user:') and local != 'user:'
                    and local != f'user:{recipient}')):
                effective = ''.join(bit if bit in mask else '-' for bit in bits)
                changes.append(key + ':' + effective)
    changes.append(f'u:{recipient}:{access}')
    if default:
        # Newly created private files must not inherit a permissive service ACL.
        changes.append(f'd:u:{recipient}:---')
    subprocess.run(['/usr/bin/setfacl', '-m', ','.join(changes), '--', f'/proc/self/fd/{fd}'],
                   pass_fds=(fd,), check=True, timeout=15, stdout=subprocess.DEVNULL)


def grant_tree(root_fd, owner, recipient, git=False, budget=None, depth=0):
    """No path traversal by ACL subprocesses; all targets are inherited FDs."""
    if budget is None:
        budget = [100000, time.monotonic() + 120]
    require(depth <= 128, 'ACL traversal depth exceeded; candidate deferred')
    root = os.fstat(root_fd)
    require(root.st_uid == owner and stat.S_ISDIR(root.st_mode), 'Unsafe ACL root')
    set_acl(root_fd, recipient, 'r-x' if git else 'rwx', default=True)
    for name in bounded_names(root_fd, 100000):
        budget[0] -= 1
        require(budget[0] >= 0 and time.monotonic() < budget[1], 'ACL traversal bound exceeded; candidate deferred')
        try:
            fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=root_fd)
        except OSError:
            continue
        try:
            s = os.fstat(fd)
            if s.st_uid != owner or s.st_dev != root.st_dev or mount_id(fd) != mount_id(root_fd):
                continue
            isdir = stat.S_ISDIR(s.st_mode)
            if not isdir and (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1):
                continue
            if isdir:
                readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = readable
            # Revalidate metadata immediately before each operation. A descriptor
            # prevents replacement links from redirecting a privileged traversal.
            if private_name(name):
                set_acl(fd, recipient, '---', default=isdir)
            elif isdir:
                grant_tree(fd, owner, recipient, git=git or name == '.git', budget=budget, depth=depth + 1)
            else:
                access = 'r--' if git or name == '.git' else ('rwx' if s.st_mode & 0o111 else 'rw-')
                set_acl(fd, recipient, access)
        finally:
            os.close(fd)


class Busy(Exception):
    pass


@contextlib.contextmanager
def admission_transaction(path):
    """Service-account connection holds the SQLite writer reservation until exit."""
    db = sqlite3.connect('file:' + path + '?mode=rw', uri=True, timeout=0)
    try:
        try:
            db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as exc:
            raise Busy('Admissions writer busy') from exc
        statuses = {row[0] for row in db.execute('SELECT DISTINCT status FROM jobs')}
        if statuses - TERMINAL:
            raise Busy('Active/unresolved jobs')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'job_admissions' in tables and db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]:
            raise Busy('Unresolved admissions')
        yield db
    finally:
        db.rollback()
        db.close()


def guard_sql(token):
    require(bool(re.fullmatch('[0-9a-f]{32}', token)), 'Invalid guard token')
    return {f'a7dev_autodiscovery_guard_{operation.lower()}':
            f"CREATE TRIGGER a7dev_autodiscovery_guard_{operation.lower()} BEFORE {operation} ON job_admissions "
            f"BEGIN SELECT RAISE(ABORT, 'A7Dev reconciliation {token}'); END"
            for operation in ('INSERT', 'UPDATE')}


def check_guards(db, token, allow_absent=False):
    expected = guard_sql(token)
    actual = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'a7dev_autodiscovery_guard_%'"))
    require(actual == expected or (allow_absent and not actual), 'Unknown admission guard; preserve and refuse')
    return actual


def install_guards(path, token):
    # The owner token must already be durably recorded by root before this call.
    with admission_transaction(path) as db:
        actual = check_guards(db, token, allow_absent=True)
        if not actual:
            for sql in guard_sql(token).values():
                db.execute(sql)
        db.commit()


def release_guards(path, token):
    with admission_transaction(path) as db:
        check_guards(db, token)
        for name in guard_sql(token):
            db.execute('DROP TRIGGER ' + name)
        db.commit()


def barrier_child(token):
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    require(os.geteuid() == uid and uid != 0, 'Barrier must run as service account')
    with directory(os.path.dirname(JOBS)) as fd:
        metadata(fd, uid, 0o700)
        f = os.open('jobs.db', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            s = metadata(f, uid, 0o600)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'Unsafe jobs database')
        finally:
            os.close(f)
        path = f'/proc/self/fd/{fd}/jobs.db'
        try:
            install_guards(path, token)
            print('READY', flush=True)
            # EOF/crash deliberately leaves the durable admission blockade.
            for command in sys.stdin:
                if command.strip() == 'RELEASE':
                    release_guards(path, token)
                    print('RELEASED', flush=True)
                    return 0
                require(command.strip() == 'VERIFY', 'Invalid barrier protocol')
                with admission_transaction(path) as db:
                    check_guards(db, token)
                print('VERIFIED', flush=True)
        except Busy:
            print('BUSY', flush=True)
            return 75
    return 0


def launch_barrier_child(token):
    account = pwd.getpwnam('agentporter-dev')
    return subprocess.Popen(['/usr/bin/python3', '-I', INSTALLED, '--admission-barrier', '--guard-token', token],
                            user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/var/lib/agentporter-dev/home'},
                            cwd='/', close_fds=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def child_failure(process, reason):
    # Terminate before draining stderr: neither a hung child nor a full pipe may
    # turn diagnostics into an unbounded wait. Ownership journal/guards survive.
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            process.wait(timeout=2)
    detail = b''
    if process.stderr is not None:
        os.set_blocking(process.stderr.fileno(), False)
        try:
            detail = os.read(process.stderr.fileno(), 4096)
        except BlockingIOError:
            pass
    clean = ''.join(c if 32 <= ord(c) <= 126 or c in '\n\t' else '?' for c in detail.decode('utf-8', errors='replace'))
    return f'{reason}; child exit={process.poll()}; {clean.strip() or "no child stderr"}; preserve guard evidence'


def child_line(process, timeout=10):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise ValueError(child_failure(process, 'Admission barrier timed out'))
        return process.stdout.readline().strip()


@contextlib.contextmanager
def barrier(state_fd):
    try:
        record = json.loads(private_read(state_fd, 'guard.json', 0))
        require(set(record) == {'version', 'token'} and record['version'] == 1, 'Invalid guard ownership journal')
        token = record['token']
        guard_sql(token)
    except FileNotFoundError:
        token = secrets.token_hex(16)
        atomic_write(state_fd, 'guard.json', canonical({'version': 1, 'token': token}), 0)
    process = launch_barrier_child(token)
    try:
        line = child_line(process)
        if line == 'BUSY':
            raise Busy('Active jobs/admissions; deferred')
        if line != 'READY' or process.poll() is not None:
            raise ValueError(child_failure(process, 'Admission barrier failed'))
        try:
            yield process
        except BaseException:
            try:
                previous = json.loads(private_read(state_fd, 'journal.json', 0, limit=1024 * 1024))
            except FileNotFoundError:
                previous = None
            if previous is None or previous.get('phase') in {'committed', 'rolled_back'}:
                release_child(process, state_fd)
            raise
        else:
            release_child(process, state_fd)
    finally:
        if process.stdin:
            with contextlib.suppress(BrokenPipeError):
                process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def release_child(process, state_fd):
    require(process.poll() is None, 'Admission barrier unexpectedly exited')
    process.stdin.write('RELEASE\n')
    process.stdin.flush()
    require(child_line(process) == 'RELEASED', 'Guard release failed; preserve evidence')
    require(process.wait(timeout=10) == 0, 'Guard child failed')
    os.unlink('guard.json', dir_fd=state_fd)
    os.fsync(state_fd)


def verify_barrier(process):
    require(process.poll() is None, 'Lost admission barrier')
    process.stdin.write('VERIFY\n')
    process.stdin.flush()
    require(child_line(process) == 'VERIFIED', 'Admission guard lost/changed')


def systemctl(*args, check=True):
    return subprocess.run(['/usr/bin/systemctl', *args, SERVICE], check=check, timeout=60,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def health():
    for _ in range(30):
        connection = http.client.HTTPConnection('127.0.0.1', 8876, timeout=1)
        try:
            connection.request('GET', '/health')
            response = connection.getresponse()
            if response.status == 200:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(0.5)
    raise ValueError('A7Dev health check failed')


def read_state(fd):
    try:
        body = private_read(fd, 'managed.json', 0, limit=1024 * 1024)
        value = json.loads(body)
    except FileNotFoundError:
        return {}, b'{}'
    require(isinstance(value, dict), 'Invalid managed state')
    return value, body


def encode(body):
    return base64.b64encode(body).decode('ascii')


def decode(body):
    return base64.b64decode(body, validate=True)


def journal_write(fd, record):
    atomic_write(fd, 'journal.json', canonical(record), 0)


def recovery_images(config_fd, state_fd, uid, receipt):
    """Restore only exact recorded bytes; called with admissions held and stopped."""
    require(receipt.get('version') == 1 and set(receipt['before']) == set(FILES)
            and set(receipt['after']) == set(FILES), 'Invalid recovery journal')
    old = {n: decode(receipt['before'][n]) for n in FILES}
    new = {n: decode(receipt['after'][n]) for n in FILES}
    for name in FILES:
        require(private_read(config_fd, name, uid) in (old[name], new[name]), 'Unknown/newer config; refuse recovery')
    _, current_state = read_state(state_fd)
    require(current_state in (decode(receipt['state_before']), decode(receipt['state_after'])), 'Unknown managed state; refuse recovery')
    return old


def recover(config_fd, state_fd, uid, receipt):
    old = recovery_images(config_fd, state_fd, uid, receipt)
    for name in FILES:
        if private_read(config_fd, name, uid) != old[name]:
            atomic_write(config_fd, name, old[name], uid)
    if receipt.get('state_existed', True):
        atomic_write(state_fd, 'managed.json', decode(receipt['state_before']), 0)
    else:
        try:
            os.unlink('managed.json', dir_fd=state_fd)
            os.fsync(state_fd)
        except FileNotFoundError:
            pass
    if receipt['was_active']:
        systemctl('start')
        health()
    receipt['phase'] = 'rolled_back'
    journal_write(state_fd, receipt)


def transaction(config_fd, state_fd, uid, before, after, state_before, state_after, check_barrier=lambda: None):
    try:
        os.stat('managed.json', dir_fd=state_fd, follow_symlinks=False)
        state_existed = True
    except FileNotFoundError:
        state_existed = False
    receipt = {'version': 1, 'phase': 'prepared', 'was_active': True, 'state_existed': state_existed,
               'before': {n: encode(before[n]) for n in FILES}, 'after': {n: encode(after[n]) for n in FILES},
               'state_before': encode(state_before), 'state_after': encode(state_after)}
    # Journal contains exact backups before any mutation. Keep a separate durable
    # historical receipt as well so later successful scans don't erase evidence.
    journal_write(state_fd, receipt)
    atomic_write(state_fd, 'backup-' + str(time.time_ns()) + '.json', canonical(receipt), 0)
    try:
        check_barrier()
        systemctl('stop')
        require(systemctl('is-active', check=False).returncode == 3, 'Service did not stop')
        for name in FILES:
            check_barrier()
            require(private_read(config_fd, name, uid) == before[name], 'Configuration changed before write')
            atomic_write(config_fd, name, after[name], uid)
        check_barrier()
        systemctl('start')
        health()
        check_barrier()
        atomic_write(state_fd, 'managed.json', state_after, 0)
        receipt['phase'] = 'committed'
        journal_write(state_fd, receipt)
    except BaseException:
        # Unknown bytes are detected before touching any config during recovery.
        systemctl('stop')
        recover(config_fd, state_fd, uid, receipt)
        raise


def installed_identity():
    require(os.path.abspath(__file__) == INSTALLED and sys.flags.isolated, 'Use immutable installed helper with python -I')
    for parent in Path(INSTALLED).parents:
        with directory(str(parent)) as ancestor:
            metadata(ancestor, 0)
            require(not os.fstat(ancestor).st_mode & 0o022, 'Writable installation ancestor')
    with directory(os.path.dirname(INSTALLED)) as fd:
        metadata(fd, 0)
        require(not os.fstat(fd).st_mode & 0o022, 'Writable helper directory')
        f = os.open(os.path.basename(INSTALLED), os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            s = metadata(f, 0)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and not s.st_mode & 0o022, 'Mutable installed helper')
        finally:
            os.close(f)


def run(apply):
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    owner = pwd.getpwnam('yeli').pw_uid
    if apply:
        require(os.geteuid() == 0, '--apply requires root')
        installed_identity()
        # Installer creates this fixed root-private directory, never project code.
    with contextlib.ExitStack() as stack:
        cfd = stack.enter_context(directory(CONFIG))
        metadata(cfd, uid, 0o700)
        rfd = stack.enter_context(directory(REPOS))
        metadata(rfd, owner)
        sfd = stack.enter_context(directory(STATE))
        metadata(sfd, 0, 0o700)
        if apply:
            lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=sfd)
            stack.callback(os.close, lock)
            s = metadata(lock, 0, 0o600)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'Unsafe lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            receipt = json.loads(private_read(sfd, 'journal.json', 0, limit=1024 * 1024))
        except FileNotFoundError:
            receipt = None
        if receipt and receipt.get('phase') not in {'committed', 'rolled_back'}:
            require(apply, 'Pending transaction requires --apply recovery')
            with barrier(sfd) as child:
                verify_barrier(child)
                recovery_images(cfd, sfd, uid, receipt)
                systemctl('stop')
                recover(cfd, sfd, uid, receipt)
        before = {n: private_read(cfd, n, uid) for n in FILES}
        docs = {n: load_yaml(before[n]) for n in FILES}
        managed, old_state = read_state(sfd)
        candidates = discover(rfd, REPOS, owner)
        result, next_managed, report = plan(docs, managed, candidates)
        after = {n: before[n] if result[n] == docs[n] else yaml.safe_dump(result[n], sort_keys=False).encode() for n in FILES}
        require(all(len(b) <= LIMIT for b in after.values()), 'Generated config exceeds reader limit')
        new_state = canonical(next_managed)
        report['configuration_changed'] = after != before
        report['apply'] = apply
        if not apply:
            return report
        # Even no-op scans refresh classified ACLs for newly created files, with
        # defaults denied. Existing explicit trees are never traversed.
        with barrier(sfd) as child:
            def check():
                verify_barrier(child)
            budget = [100000, time.monotonic() + 120]
            for name, row in next_managed.items():
                check()
                try:
                    fd = pin_candidate(rfd, name, row['identity'], owner)
                    try:
                        grant_tree(fd, owner, uid, budget=budget)
                    finally:
                        os.close(fd)
                    verification = pin_candidate(rfd, name, row['identity'], owner)
                    os.close(verification)
                except (ValueError, OSError, subprocess.SubprocessError) as exc:
                    report['deferred_acl'] = {'workspace': name, 'reason': str(exc)}
                    report['configuration_changed'] = False
                    return report
            require(all(private_read(cfd, n, uid) == before[n] for n in FILES), 'Config changed during ACL enrollment')
            if after != before:
                if systemctl('is-active', check=False).returncode != 0:
                    report['deferred'] = 'A7Dev inactive; preserve service state'
                    return report
                transaction(cfd, sfd, uid, before, after, old_state, new_state, check)
            elif old_state != new_state:
                atomic_write(sfd, 'managed.json', new_state, 0)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--admission-barrier', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--guard-token', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.admission_barrier:
        installed_identity()
        return barrier_child(args.guard_token)
    try:
        print(json.dumps(run(args.apply), sort_keys=True))
    except Busy as exc:
        print(json.dumps({'deferred': str(exc)}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
