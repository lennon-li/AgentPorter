#!/usr/bin/env python3
"""Root-only production CONFIG migration. Never controls services or workspace DAC.

Review `plan --gateway-home /home/OWNER`, then use its hash with `apply`.
New central directory is root:root 0711; trusted existing modes are preserved.
Policy/public key root:root 0644;
issuer private key and recovery snapshots root:root 0600/0700.
Worker needs traversal and read/write DAC/ACL access to registered roots for
transaction apply. This helper deliberately does not grant that access.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
import subprocess
import sys

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CENTRAL = Path('/etc/agentporter')
POLICY = CENTRAL / 'production-workspace-policy.yaml'
WORKER = Path('/var/lib/agentporter-worker')
WORKER_RELEASE = Path('/opt/agentporter-worker')
LIBEXEC = Path('/usr/local/libexec/agentporter')
WORKER_USER = 'agentporter-worker'
ROOT_UID = 0
ROOT_GID = 0
SPECIAL = ('allow_scinet_diagnostic', 'allow_scinet_training', 'allow_venkata_ssh', 'allow_venkata_transfer')
REF_NAMES = ('workspaces.yaml', 'public-client-policy.yaml', 'delegation-relay-scope.yaml')
MAX = 1024 * 1024


def require(ok, message=None):
    if not ok:
        caller = sys._getframe(1)
        raise ValueError('Production migration precondition failed: '
                         + (message or f'{caller.f_code.co_name}:{caller.f_lineno}'))


class Loader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        require(not self.check_event(yaml.AliasEvent))
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        pairs = self.construct_pairs(node, deep=deep)
        result = {}
        for k, v in pairs:
            require(k not in result)
            result[k] = v
        return result


def digest(body):
    return hashlib.sha256(body).hexdigest()


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    for p in (path, *path.parents):
        require(not p.is_symlink())
    return path


def secure_parent(path, owners):
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in owners | {0})
        require(not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX))


def read(path, owner, private=True):
    secure_parent(path, {ROOT_UID, owner})
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == owner)
        require(not s.st_mode & (0o077 if private else 0o022) and s.st_size <= MAX)
        data = os.read(fd, MAX + 1)
        require(len(data) <= MAX)
        return data, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid
    finally:
        os.close(fd)


def document(path, owner):
    result = yaml.load(read(path, owner)[0], Loader=Loader)
    require(isinstance(result, dict))
    return result


def dumped(doc):
    return yaml.safe_dump(doc, sort_keys=False).encode()


def account(home):
    canonical(home)
    s = home.stat()
    require(s.st_uid != ROOT_UID)
    user = pwd.getpwuid(s.st_uid)
    require(Path(user.pw_dir) == home and user.pw_uid == s.st_uid)
    return user


def stopped(user):
    env = {'PATH': '/usr/bin:/bin', 'XDG_RUNTIME_DIR': f'/run/user/{user.pw_uid}',
           'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{user.pw_uid}/bus'}
    commands = [(['/usr/sbin/runuser', '-u', user.pw_name, '--', '/usr/bin/systemctl', '--user', 'show', 'agentporter.service', '--property=ActiveState', '--value'], env),
                (['/usr/bin/systemctl', 'show', 'agentporter-worker.service', '--property=ActiveState', '--value'], {'PATH': '/usr/bin:/bin'})]
    for command, environment in commands:
        result = subprocess.run(command, env=environment, check=True, capture_output=True, text=True)
        require(result.stdout.strip() in {'inactive', 'failed'})


def idle(path, owner):
    # Opening only after regular-file/ownership checks avoids following a DB symlink.
    secure_parent(path, {ROOT_UID, owner})
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == owner and not info.st_mode & 0o077)
    finally:
        os.close(descriptor)
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        require(db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running','cancelling','cleanup_failed')").fetchone()[0] == 0)
        require(db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0)


def inspect(home, *, require_stopped=True):
    require(os.geteuid() == ROOT_UID)
    user = account(home)
    worker = pwd.getpwnam(WORKER_USER)
    require(worker.pw_uid != ROOT_UID and worker.pw_uid != user.pw_uid)
    if require_stopped:
        stopped(user)
    for db, uid in ((home / '.local/state/agentporter/jobs.db', user.pw_uid),
                    (WORKER / 'state/jobs.db', worker.pw_uid)):
        idle(db, uid)
    return user, worker


def validate_central_directory():
    if CENTRAL.exists() or CENTRAL.is_symlink():
        canonical(CENTRAL)
        secure_parent(CENTRAL / 'placeholder', {ROOT_UID})
        info = CENTRAL.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID
                and not info.st_mode & 0o022 and info.st_mode & 0o001,
                'central directory must be root-owned, traversable and not writable by others')
    else:
        secure_parent(CENTRAL, {ROOT_UID})


def build(home, *, require_stopped=True):
    user, worker = inspect(home, require_stopped=require_stopped)
    validate_central_directory()
    cfg = home / '.config/agentporter'
    wc = WORKER / 'config'
    registrations = document(cfg / 'workspaces.yaml', user.pw_uid)
    if registrations.get('version') == 2:
        return existing_shared_changes(cfg, wc, user, worker)
    require(registrations.get('version', 1) == 1)
    rows = registrations.get('workspaces')
    require(isinstance(rows, dict) and len(rows) == 11)
    public = document(cfg / 'public-client-policy.yaml', user.pw_uid)
    require(public.get('version') == 1)
    grants = public.get('workspaces', {})
    require(isinstance(grants, dict) and set(grants) <= set(rows))
    newrows = {}
    seen = set()
    for name, row in rows.items():
        require(isinstance(row, dict))
        root = str(canonical(row['path']))
        require(Path(root).is_dir() and root not in seen)
        seen.add(root)
        new = {'path': root}
        for key in ('description', 'local_http_ports', *SPECIAL):
            if key in row:
                new[key] = row[key]
        operations = grants.get(name, [])
        if isinstance(operations, dict):
            operations = operations.get('operations', [])
        require(isinstance(operations, list))
        # Only explicit old public specialized grants are preserved.
        for key in SPECIAL:
            if key.removeprefix('allow_') in operations:
                new[key] = True
        newrows[name] = new
    protected = [cfg, home / '.local/state/agentporter', home / '.cache/agentporter',
                 home / '.local/share/agentporter', home / '.local/libexec/agentporter-production-20261028',
                 CENTRAL, LIBEXEC, WORKER_RELEASE, WORKER]
    for path in protected:
        if path != CENTRAL or path.exists():
            canonical(path)
    policy = {'version': 1, 'workspace_defaults': dict.fromkeys(('readable', 'writable', 'execute', 'git', 'artifacts', 'agent_dispatch'), True),
              'delegation': {'enabled_by_default': True, 'read_only_default': True, 'writable_with_authorization': True},
              'approval': dict.fromkeys(('commit', 'push', 'destructive_operations'), 'required'),
              'workspaces': newrows, 'workspace_overrides': {}, 'protected_paths': list(map(str, protected))}
    changes = {}
    def change(path, body, uid, gid, mode, existing=True):
        before = read(path, uid, private=mode != 0o644) if existing or path.exists() else None
        changes[str(path)] = {'before': before, 'after': (body, mode, uid, gid)}
    reference = dumped({'version': 2, 'policy_file': str(POLICY)})
    for name in ('workspaces.yaml', 'public-client-policy.yaml', 'delegation-upstream.yaml'):
        old = document(cfg / name, user.pw_uid)
        require(old.get('version', 1) == 1)
        change(cfg / name, reference, user.pw_uid, user.pw_gid, 0o600)
    for name in REF_NAMES:
        old = document(wc / name, worker.pw_uid)
        require(old.get('version', 1) == 1)
        change(wc / name, reference, worker.pw_uid, worker.pw_gid, 0o600)
    runtime = document(wc / 'development-runtime.yaml', worker.pw_uid)
    require(runtime.get('service_unit') == 'agentporter-worker.service')
    runtime['workspace_policy_file'] = str(POLICY)
    runtime.pop('allowed_workspace_roots', None)
    runtime.pop('production_relay_agents', None)
    change(wc / 'development-runtime.yaml', dumped(runtime), worker.pw_uid, worker.pw_gid, 0o600)
    change(POLICY, dumped(policy), ROOT_UID, ROOT_GID, 0o644, existing=False)
    private, publickey = CENTRAL / 'approval-issuer.key', CENTRAL / 'approval-issuer.pub'
    require(private.exists() == publickey.exists())
    if private.exists():
        priv = read(private, ROOT_UID)[0]
        pub = read(publickey, ROOT_UID, private=False)[0]
        key = serialization.load_pem_private_key(priv, password=None)
        require(isinstance(key, Ed25519PrivateKey))
        require(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == pub)
        for path, mode in ((private, 0o600), (publickey, 0o644)):
            before = read(path, ROOT_UID, private=mode != 0o644)
            require(before[1] == mode)
            change(path, before[0], ROOT_UID, ROOT_GID, mode)
    else:
        change(private, b'GENERATE_ED25519_PRIVATE', ROOT_UID, ROOT_GID, 0o600, existing=False)
        change(publickey, b'GENERATE_ED25519_PUBLIC', ROOT_UID, ROOT_GID, 0o644, existing=False)
    return changes


def existing_shared_changes(cfg, wc, user, worker):
    """Allow runtime repairs while preserving an already migrated policy exactly."""
    reference = {'version': 2, 'policy_file': str(POLICY)}
    changes = {}
    def retain(path, uid, mode):
        before = read(path, uid, private=mode != 0o644)
        require(before[1] == mode, 'Existing shared control mode changed')
        changes[str(path)] = {'before': before, 'after': before}
    for directory, identity, names in (
        (cfg, user, ('workspaces.yaml', 'public-client-policy.yaml', 'delegation-upstream.yaml')),
        (wc, worker, REF_NAMES)):
        for name in names:
            require(document(directory / name, identity.pw_uid) == reference,
                    'Mixed or unexpected existing shared policy reference')
            retain(directory / name, identity.pw_uid, 0o600)
    policy = yaml.load(read(POLICY, ROOT_UID, private=False)[0], Loader=Loader)
    require(isinstance(policy, dict), 'Existing shared policy must be a mapping')
    require(policy.get('version') == 1 and len(policy.get('workspaces', {})) == 11,
            'Existing shared policy is invalid')
    retain(POLICY, ROOT_UID, 0o644)
    runtime = document(wc / 'development-runtime.yaml', worker.pw_uid)
    require(runtime.get('service_unit') == 'agentporter-worker.service'
            and runtime.get('workspace_policy_file') == str(POLICY)
            and 'allowed_workspace_roots' not in runtime and 'production_relay_agents' not in runtime,
            'Existing worker runtime is not bound to the shared policy')
    retain(wc / 'development-runtime.yaml', worker.pw_uid, 0o600)
    private, public = CENTRAL / 'approval-issuer.key', CENTRAL / 'approval-issuer.pub'
    retain(private, ROOT_UID, 0o600); retain(public, ROOT_UID, 0o644)
    key = serialization.load_pem_private_key(changes[str(private)]['before'][0], password=None)
    require(isinstance(key, Ed25519PrivateKey)
            and key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo) == changes[str(public)]['before'][0],
            'Existing approval key pair does not match')
    return changes


def fingerprint(changes):
    def summarize(v):
        return None if v is None else [digest(v[0]), *v[1:]]
    body = {p: {k: summarize(v) for k, v in values.items()} for p, values in changes.items()}
    return digest(json.dumps(body, sort_keys=True).encode())


def atomic(path, value):
    body, mode, uid, gid = value
    temporary = path.parent / ('.policy-' + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        temporary.unlink(missing_ok=True)


def encode(value):
    return None if value is None else [base64.b64encode(value[0]).decode(), *value[1:]]


def decode(value):
    return None if value is None else (base64.b64decode(value[0], validate=True), *value[1:])


def restore(changes):
    for path, row in reversed(list(changes.items())):
        if row['before'] is None:
            Path(path).unlink(missing_ok=True)
        else:
            atomic(Path(path), row['before'])


def recovery_path(expected, attempt_id=None):
    require(len(expected) == 64 and all(c in '0123456789abcdef' for c in expected),
            'invalid plan fingerprint')
    require(attempt_id is None or isinstance(attempt_id, str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,119}', attempt_id),
            'invalid recovery attempt identifier')
    return CENTRAL / ('policy-recovery-' + expected + ('-' + attempt_id if attempt_id else ''))


def apply(home, expected, *, attempt_id=None):
    recovery = recovery_path(expected, attempt_id)
    changes = build(home)
    require(fingerprint(changes) == expected)
    validate_central_directory()
    if not CENTRAL.exists():
        CENTRAL.mkdir(mode=0o711)
        CENTRAL.chmod(0o711)
    private = str(CENTRAL / 'approval-issuer.key')
    if changes[private]['before'] is None:
        key = Ed25519PrivateKey.generate()
        changes[private]['after'] = (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600, ROOT_UID, ROOT_GID)
        changes[str(CENTRAL / 'approval-issuer.pub')]['after'] = (key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644, ROOT_UID, ROOT_GID)
    # The reviewed plan can be identical after rollback, while generated keys
    # differ. Never overwrite/reuse another attempt's recovery snapshot.
    recovery.mkdir(mode=0o700)
    recovery.chmod(0o700)
    manifest = {'home': str(home), 'plan_sha256': expected, 'attempt_id': attempt_id,
                'changes': {p: {k: encode(v) for k, v in row.items()} for p, row in changes.items()}}
    atomic(recovery / 'snapshot.json', (json.dumps(manifest).encode(), 0o600, ROOT_UID, ROOT_GID))
    try:
        # Detect config drift after snapshot as well as against the reviewed plan.
        for p, row in changes.items():
            require((read(Path(p), row['before'][2], private=row['before'][1] != 0o644) if row['before'] else None) == row['before'])
            if row['before'] is None:
                require(not Path(p).exists() and not Path(p).is_symlink())
        for p, row in changes.items():
            atomic(Path(p), row['after'])
    except Exception:
        restore(changes)
        raise
    return len(changes)


def rollback(home, expected, *, attempt_id=None):
    inspect(home)
    manifest = json.loads(read(recovery_path(expected, attempt_id) / 'snapshot.json', ROOT_UID)[0])
    require(manifest['home'] == str(home) and manifest['plan_sha256'] == expected)
    require(manifest.get('attempt_id') == attempt_id, 'recovery attempt does not match')
    changes = {p: {k: decode(v) for k, v in row.items()} for p, row in manifest['changes'].items()}
    expected_paths = {home / '.config/agentporter' / n for n in ('workspaces.yaml', 'public-client-policy.yaml', 'delegation-upstream.yaml')}
    expected_paths |= {WORKER / 'config' / n for n in (*REF_NAMES, 'development-runtime.yaml')}
    expected_paths |= {POLICY, CENTRAL / 'approval-issuer.key', CENTRAL / 'approval-issuer.pub'}
    require(set(changes) == set(map(str, expected_paths)))
    for p, row in changes.items():
        require(read(Path(p), row['after'][2], private=row['after'][1] != 0o644) == row['after'])
    try:
        restore(changes)
    except Exception:
        for p, row in changes.items():
            atomic(Path(p), row['after'])
        raise
    return len(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'rollback'))
    parser.add_argument('--gateway-home', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--attempt-id', help='Unique installation attempt; use the same value for rollback')
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            changes = build(args.gateway_home)
            result = {'files': len(changes), 'workspaces': 11, 'plan_sha256': fingerprint(changes), 'worker_workspace_DAC_review_required': True}
        else:
            require(args.expected_plan_sha256 is not None)
            count = (apply if args.action == 'apply' else rollback)(
                args.gateway_home, args.expected_plan_sha256, attempt_id=args.attempt_id)
            result = {'files': count, args.action: True}
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # Fail closed without disclosing YAML, keys, registration paths, or subprocess output.
        print('Production migration refused; precondition or transaction failed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
