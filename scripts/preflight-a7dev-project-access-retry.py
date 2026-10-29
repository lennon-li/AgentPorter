#!/usr/bin/env python3
"""Service-UID-only project-access retry preflight; never changes policy/runtime.

The default plan reads only configuration and rollback evidence. The sole
mutation, --preserve-rolled-back-recovery, requires stopped/quiet A7Dev and moves
an exactly authenticated rolled-back recovery into a new private archive.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import types

OLD_RELEASE = Path('/opt/agentporter-development/versions/20261021T212000.000019Z')
NEW_RELEASE = Path('/opt/agentporter-development/versions/20261021T232414.837654Z')
HELPER = NEW_RELEASE / 'operator-plan/authorize-a7dev-project-delegation.py'
HELPER_SHA = 'e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0'
PLAN_SHA = '2c4b78429001d4a3f3e5acdfa074d2a0ea5987a3980b04e6d378177d5f9c196c'
BEFORE = {
    'development-runtime.yaml': 'fa33ac76062ce50e333a71d21310808bf6ea64658117da6224c6b4dab484a3fe',
    'public-client-policy.yaml': '97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043',
    'public-https.yaml': 'e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf',
    'workspaces.yaml': 'ffded407f4cd22dd8e30f1488cba12887158114617fd16b7f01c6560d4e0aacc',
}
AFTER = {
    'development-runtime.yaml': '1ead69fa8d365fe9e1a062ce1906180a6b8caec1d124cf01282efc8253a96ae7',
    'public-client-policy.yaml': 'b7fe90d3872896f114944affbce5a4c84ddcadf82c32e37b7b0f9f07e6121c0b',
    'workspaces.yaml': 'ffded407f4cd22dd8e30f1488cba12887158114617fd16b7f01c6560d4e0aacc',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_helper():
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o222 and info.st_size <= 128 * 1024,
                'Installed helper is not immutable regular code')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            source = stream.read(128 * 1024 + 1)
    finally:
        os.close(fd)
    require(hashlib.sha256(source).hexdigest() == HELPER_SHA, 'Installed helper hash changed')
    helper = types.ModuleType('_frozen_project_delegation_authorization')
    helper.__file__ = str(HELPER)
    exec(compile(source, str(HELPER), 'exec'), helper.__dict__)
    return helper


def guard_old_release(helper):
    require(os.readlink(helper.CURRENT) == str(OLD_RELEASE), 'Current release changed; require old v19')


def validate(helper, config_fd, recovery_fd, uid):
    guard_old_release(helper)
    raw_receipt = helper.private_read(recovery_fd, 'receipt.json', uid)
    receipt = json.loads(raw_receipt)
    require(receipt.get('state') == 'rolled_back', 'Recovery is not rolled back')
    plan = receipt.get('plan')
    require(isinstance(plan, dict) and helper.digest(helper.canonical(plan)) == PLAN_SHA,
            'Recovery plan hash changed')
    require(plan.get('before') == BEFORE and plan.get('after') == AFTER, 'Unexpected plan file hashes')
    require(plan.get('release') == str(NEW_RELEASE), 'Unexpected recovery release')
    admitted = sorted(set(helper.EXPECTED_ROOTS) - helper.PROTECTED)
    require(len(admitted) == 41 and plan.get('admitted_workspaces') == admitted and
            plan.get('protected_workspaces') == sorted(helper.PROTECTED) and len(helper.PROTECTED) == 5,
            'Unexpected project scope')
    require(plan.get('https_workspaces') == ['cranary'] and plan.get('generic_shell_network') is False
            and plan.get('production_changed') is False, 'Unexpected network/production scope')
    for name in helper.FILES:
        require(helper.digest(helper.private_read(recovery_fd, name, uid)) == BEFORE[name],
                'Recovery backup changed: ' + name)
    for name in ('public-client-policy.yaml', 'workspaces.yaml', 'public-https.yaml'):
        require(helper.digest(helper.private_read(config_fd, name, uid)) == BEFORE[name],
                'Current configuration changed: ' + name)
    current_runtime = helper.private_read(config_fd, 'development-runtime.yaml', uid)
    runtime = helper.yaml.load(current_runtime, Loader=helper.UniqueLoader)
    require(helper.digest(helper.canonical(helper.normalize_release(runtime, OLD_RELEASE))) == helper.RUNTIME_SHA,
            'Current old-v19 runtime changed')
    return {'passed': True, 'plan_sha256': PLAN_SHA, 'receipt_sha256': helper.digest(raw_receipt),
            'current_release': str(OLD_RELEASE), 'retry_release': str(NEW_RELEASE),
            'current_runtime_sha256': helper.digest(current_runtime),
            'admitted_projects': 41, 'protected_projects': 5, 'https_workspaces': ['cranary'],
            'generic_shell_network': False, 'policy_changed': False, 'production_changed': False}


def rename_noreplace(source_fd, source, destination_fd, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    require(rename is not None, 'Atomic no-overwrite directory rename unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), destination)


def preserve(helper, config_fd, recovery_fd, uid):
    helper.quiet_and_stopped()
    result = validate(helper, config_fd, recovery_fd, uid)
    original = os.fstat(recovery_fd)
    source = os.stat(helper.RECOVERY, dir_fd=config_fd, follow_symlinks=False)
    require((source.st_dev, source.st_ino) == (original.st_dev, original.st_ino), 'Recovery directory changed')
    name = 'project-delegation-retry-archive-' + secrets.token_hex(12)
    os.mkdir(name, 0o700, dir_fd=config_fd)  # exclusive, never reuse prior archives
    archive_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=config_fd)
    try:
        guard_old_release(helper)
        rename_noreplace(config_fd, helper.RECOVERY, archive_fd, 'previous')
        os.fsync(archive_fd)
        os.fsync(config_fd)
        moved = os.stat('previous', dir_fd=archive_fd, follow_symlinks=False)
        require((moved.st_dev, moved.st_ino) == (original.st_dev, original.st_ino), 'Archived recovery identity mismatch')
        result.update(preserved=True, archive=str(helper.CONFIG / name / 'previous'))
    finally:
        os.close(archive_fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true')
    modes.add_argument('--preserve-rolled-back-recovery', action='store_true')
    args = parser.parse_args()
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    require(uid != 0 and os.geteuid() == uid, 'Run only as agentporter-dev, never root')
    helper = load_helper()
    config_fd = helper.open_directory(helper.CONFIG, uid)
    recovery_fd = None
    try:
        recovery_fd = helper.open_directory(helper.CONFIG / helper.RECOVERY, uid)
        if args.preserve_rolled_back_recovery:
            result = preserve(helper, config_fd, recovery_fd, uid)
        else:
            result = validate(helper, config_fd, recovery_fd, uid)
            result['preserved'] = False
        print(json.dumps(result, sort_keys=True))
    finally:
        if recovery_fd is not None:
            os.close(recovery_fd)
        os.close(config_fd)


if __name__ == '__main__':
    main()
