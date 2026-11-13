#!/usr/bin/env python3
"""Freeze the already-installed native CLI, without downloading or installing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

SOURCE = Path('/home/yeli/.codex-prof/packages/app-server-daemon/releases/0.167.2-x86_64-unknown-linux-musl/bin')
DESTINATION = Path('/opt/agentporter-bcc/shared-cli/codex-0.167.2/bin')


def freeze(output):
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'version': 1, 'cli_version': '0.167.2', 'installed': False, 'files': {}}
    for name in ('codex', 'codex-code-mode-host'):
        source = (SOURCE/name).resolve(strict=True)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_mode & 0o6022 or before.st_nlink != 1):
                raise PermissionError('Native CLI input lost trusted file custody')
            digest = hashlib.sha256()
            first = True
            with (output/name).open('xb') as stream:
                while block := os.read(descriptor, 1024*1024):
                    if first and block[:4] != b'\x7fELF':
                        raise PermissionError('Native CLI input is not an ELF executable')
                    first = False
                    digest.update(block)
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            after = os.fstat(descriptor)
            current = source.lstat()
            if any(getattr(before, f) != getattr(s, f) for s in (after, current) for f in fields):
                raise PermissionError('Native CLI input changed during freeze')
            (output/name).chmod(0o555)
            manifest['files'][name] = {'source': str(source), 'destination': str(DESTINATION/name),
                                     'sha256': digest.hexdigest(), 'size': before.st_size}
        finally:
            os.close(descriptor)
    (output/'MANIFEST.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({'output': str(output), 'cli_version': manifest['cli_version'], 'installed': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    freeze(parser.parse_args().output.resolve())
