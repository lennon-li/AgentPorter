"""Production workspace ACL planning, preserving other users' effective rights.

Only directories need write access for atomic publication. Ordinary files need
read access; hardlinked/private/privileged files are never granted new rights.
Git controls receive read/traverse only. Ancestors receive traversal only.
"""
from __future__ import annotations

import base64
import errno
import os
from pathlib import Path
import stat
import struct
import time

ACCESS = 'system.posix_acl_access'
DEFAULT = 'system.posix_acl_default'
UOBJ, USER, GOBJ, GROUP, MASK, OTHER, UNDEF = 1, 2, 4, 8, 16, 32, 0xffffffff
PRIVATE = {'.ssh', '.aws', '.codex', '.agents', '.claude', '.copilot', '.copilot-phil',
           '.opencode', '.gemini', '.gnupg', '.config', '.local', '.development',
           '.github-copilot', '.antigravitycli', 'runtime', 'credentials', 'secrets', '.secrets'}


def _get(fd, name):
    try: return os.getxattr(fd, name)
    except OSError as exc:
        if exc.errno == errno.ENODATA: return None
        raise


def decode(raw, mode):
    if raw is None:
        return {(UOBJ, UNDEF): (mode >> 6) & 7, (GOBJ, UNDEF): (mode >> 3) & 7,
                (OTHER, UNDEF): mode & 7}
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from('<I', raw)[0] != 2:
        raise ValueError('Invalid POSIX ACL')
    result = {}
    for tag, perm, ident in struct.iter_unpack('<HHI', raw[4:]):
        if (tag not in {UOBJ, USER, GOBJ, GROUP, MASK, OTHER} or perm > 7
                or (tag, ident) in result or (ident == UNDEF) != (tag not in {USER, GROUP})):
            raise ValueError('Invalid POSIX ACL entry')
        result[tag, ident] = perm
    if not {(UOBJ, UNDEF), (GOBJ, UNDEF), (OTHER, UNDEF)} <= set(result):
        raise ValueError('Incomplete POSIX ACL')
    return result


def encode(entries):
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, ident)
                                         for (tag, ident), perm in sorted(entries.items()))


def grant(raw, mode, file_uid, target_uid, permissions):
    entries = decode(raw, mode)
    if file_uid == target_uid and entries[UOBJ, UNDEF] & permissions == permissions:
        return raw
    mask = entries.get((MASK, UNDEF), 7)
    for key in entries:
        if key[0] in {USER, GOBJ, GROUP}: entries[key] &= mask
    key = (UOBJ, UNDEF) if file_uid == target_uid else (USER, target_uid)
    entries[key] = entries.get(key, 0) | permissions
    entries[MASK, UNDEF] = 0
    for (tag, ident), value in entries.items():
        if tag in {USER, GOBJ, GROUP}: entries[MASK, UNDEF] |= value
    return encode(entries)


def _b64(value): return None if value is None else base64.b64encode(value).decode('ascii')
def _unb64(value): return None if value is None else base64.b64decode(value, validate=True)


def identity(fd):
    info = os.fstat(fd)
    return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'access': _b64(_get(fd, ACCESS)),
            'default': _b64(_get(fd, DEFAULT)) if stat.S_ISDIR(info.st_mode) else None}


def _open(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError('Noncanonical access target')
    # Every component is opened below with O_NOFOLLOW. Resolving the complete
    # path first duplicates all ancestor lookups for each metadata record and
    # supplies no additional symlink protection over these pinned descriptors.
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NONBLOCK if last else os.O_PATH | os.O_DIRECTORY
            if last and directory: flags |= os.O_DIRECTORY
            child = os.open(part, flags | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise


def plan(policy, target_uid, *, max_entries=2000000, max_seconds=300, include_ancestors=True,
         progress=None):
    records = {}; scanned = 0; skipped = 0; started = time.monotonic()
    roots = [Path(row['path']) for row in policy.workspaces.values()]
    # Compile immutable policy lookups once. Constructing every registered Path
    # and recomputing its capabilities for every filesystem entry is quadratic
    # in the registry size, and used to exhaust the production time budget.
    protected = {str(path) for path in policy.protected_paths}
    protected_prefixes = tuple(path.rstrip('/') + '/' for path in protected)
    readonly_roots = {row['path'] for name, row in policy.workspaces.items()
                      if not policy.capabilities(name)['writable']}
    readonly_prefixes = tuple(path.rstrip('/') + '/' for path in readonly_roots)
    last_progress = started

    def record(path, wanted, directory, defaults=False):
        fd = _open(path, directory)
        try:
            before = identity(fd)
            raw = _unb64(before['access'])
            after = grant(raw, before['mode'], before['uid'], target_uid, wanted)
            default = _unb64(before['default'])
            after_default = grant(default, 0o700, -1, target_uid, wanted) if defaults else default
            existing = records.get(str(path))
            if existing:
                # A registered writable root can also be another root's ancestor.
                after = grant(_unb64(existing['after']['access']), before['mode'],
                              before['uid'], target_uid, wanted)
                if existing['after']['default'] is not None:
                    after_default = _unb64(existing['after']['default'])
            if raw != after or default != after_default:
                records[str(path)] = {'before': before, 'after': {'access': _b64(after),
                    'default': _b64(after_default)}, 'directory': directory}
        finally: os.close(fd)

    def visit(path, readonly=False, root_dev=None):
        nonlocal scanned, skipped, last_progress
        scanned += 1
        now = time.monotonic()
        if scanned > max_entries or now - started > max_seconds:
            reason = 'entry' if scanned > max_entries else 'time'
            raise ValueError(f'Production ACL metadata plan exceeded its {reason} budget '
                             f'after {scanned} entries and {now - started:.1f} seconds')
        if progress is not None and now - last_progress >= 10:
            progress({'scanned': scanned, 'records': len(records), 'seconds': round(now - started, 1)})
            last_progress = now
        text = str(path)
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_mode & 0o7000
                or text in protected or text.startswith(protected_prefixes)
                or root_dev is not None and info.st_dev != root_dev):
            skipped += 1; return
        name = path.name
        if (name in PRIVATE or name.startswith(('.codex-', '.env'))
                or name.endswith(('.env', '.key', '.pem'))):
            skipped += 1; return
        readonly = (readonly or name == '.git' or text in readonly_roots
                    or text.startswith(readonly_prefixes))
        if stat.S_ISDIR(info.st_mode):
            record(path, 5 if readonly else 7, True, defaults=True)
            with os.scandir(path) as entries:
                for entry in entries: visit(path / entry.name, readonly, info.st_dev)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                skipped += 1; return
            # World-readable files already satisfy the view's lower-layer read.
            if not info.st_mode & 0o004: record(path, 4, False)
        else: skipped += 1

    # Traverse enclosing roots once; child exceptions are checked at every node.
    for root in roots:
        if not any(other != root and root.is_relative_to(other) for other in roots): visit(root)
    if include_ancestors:
        for root in roots:
            for ancestor in root.parents:
                if ancestor != Path('/') and not any(ancestor == r or ancestor.is_relative_to(r) for r in roots):
                    record(ancestor, 1, True)
    return {'version': 1, 'target_uid': target_uid, 'scanned': scanned, 'skipped': skipped,
            'records': dict(sorted(records.items(), key=lambda item: (-len(Path(item[0]).parts), item[0])))}


def apply(plan, *, rollback=False, applied_paths=None):
    """Root-owned journal is written by the caller before applying any record."""
    rows = ((path, plan['records'][path]) for path in reversed(applied_paths)) if rollback and applied_paths is not None else (
        reversed(list(plan['records'].items())) if rollback else plan['records'].items())
    for path, row in rows:
        fd = _open(path, row['directory'])
        try:
            current = identity(fd); before = row['before']; after = row['after']
            if any(current[key] != before[key] for key in ('dev', 'ino', 'uid', 'gid')):
                raise ValueError('Access target identity changed')
            if rollback:
                if current['access'] == before['access'] and current['default'] == before['default']: continue
                # An error may occur between setting access and default ACLs.
                # Accept only our exact before/after values for each attribute.
                if any(current[key] not in (before[key], after[key]) for key in ('access', 'default')):
                    raise ValueError('Access metadata changed after migration')
                target = before
            else:
                if current != before: raise ValueError('Access metadata changed after planning')
                target = after
                if applied_paths is not None: applied_paths.append(path)
            for name, key in ((ACCESS, 'access'), (DEFAULT, 'default')):
                if name == DEFAULT and not row['directory']: continue
                value = _unb64(target[key])
                if value is not None: os.setxattr(fd, name, value)
                else:
                    try: os.removexattr(fd, name)
                    except OSError as exc:
                        if exc.errno != errno.ENODATA: raise
            if rollback: os.fchmod(fd, before['mode'])
        finally: os.close(fd)
