#!/usr/bin/python3
"""Create-only root staging of the reviewed CLI; never switch a live service.

No downloads, credentials, policy edits, process launches, unit changes, or
deletions. Inputs are fixed, byte-pinned copies of the already installed CLI.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

SOURCE = Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112/shared-cli-0.167.2')
PARENT = Path('/opt/agentporter-bcc/shared-cli')
DESTINATION = PARENT/'codex-0.167.2'
FILES = {
    'codex': ('a9672d0fa0dd8fcf8cad136fa0d056b914bc046f5ac3d78f4a5cf390655af56b', 320248296),
    'codex-code-mode-host': ('007c62795a7215c27ee85486ecb95e714b33118a2d18c6d7b09b0d9793c72ff4', 79213840),
}


def trusted_directory(path):
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Root CLI staging ancestry changed')


def content(path, *, output=None, installed=False):
    expected, size = FILES[path.name]
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size != size or before.st_nlink != 1
                or installed and (before.st_uid != 0 or before.st_mode & 0o6222)):
            raise PermissionError('CLI payload metadata differs')
        digest = hashlib.sha256()
        total = 0
        while block := os.read(descriptor, 1024*1024):
            total += len(block)
            if total > size:
                raise PermissionError('CLI payload grew during staging')
            digest.update(block)
            if output is not None:
                output.write(block)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (digest.hexdigest() != expected or total != size
                or any(getattr(before, key) != getattr(after, key) for key in fields)):
            raise PermissionError('CLI payload bytes differ from reviewed input')
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    for name in FILES:
        content(SOURCE/name)
    trusted_directory(PARENT if PARENT.exists() else PARENT.parent)
    if os.path.lexists(DESTINATION):
        trusted_directory(DESTINATION/'bin')
        for name in FILES:
            content(DESTINATION/'bin'/name, installed=True)
        print(json.dumps({'status': 'existing_staging_verified', 'path': str(DESTINATION), 'services_changed': False}))
        return
    if not args.apply:
        print(json.dumps({'status': 'inputs_verified', 'path': str(DESTINATION), 'services_changed': False}))
        return
    if os.geteuid() != 0:
        raise PermissionError('Root staging requires explicit operator execution')
    PARENT.mkdir(mode=0o755, exist_ok=True)
    trusted_directory(PARENT)
    stage = PARENT/('.codex-0.167.2-stage-'+uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    binary = stage/'bin'
    binary.mkdir(mode=0o755)
    for name in FILES:
        path = binary/name
        with path.open('xb') as output:
            content(SOURCE/name, output=output)
            output.flush()
            os.fsync(output.fileno())
        path.chmod(0o555)
        content(path, installed=True)
    with (stage/'MANIFEST.json').open('x') as output:
        json.dump({'version': 1, 'cli_version': '0.167.2',
            'files': {name: {'sha256': values[0], 'size': values[1]} for name, values in FILES.items()}}, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    (stage/'MANIFEST.json').chmod(0o444)
    stage.chmod(0o555)
    for directory in (binary, stage):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(DESTINATION), 1):
        raise OSError(ctypes.get_errno(), 'Create-only CLI staging publication refused')
    descriptor = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({'status': 'root_staging_installed', 'path': str(DESTINATION),
                      'services_changed': False, 'credentials_changed': False}))


if __name__ == '__main__':
    main()
