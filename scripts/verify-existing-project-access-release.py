#!/usr/bin/env python3
"""Read-only check of the already installed, independently reviewed release."""
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path('/opt/agentporter-development/versions/20261021T232414.837654Z')
MANIFEST = Path(__file__).resolve().parents[1] / 'review-artifacts/a7dev-project-access-release-files.json'
MANIFEST_SHA = 'c47044f4ca5bcd1558c8abe355dea949df7d571e370f162d51db1d118f619716'


def main():
    if os.geteuid() == 0:
        raise PermissionError('Verify as the ordinary owner, not root')
    body = MANIFEST.read_bytes()
    if len(body) > 32 * 1024**2 or hashlib.sha256(body).hexdigest() != MANIFEST_SHA:
        raise ValueError('Reviewed manifest changed')
    expected = json.loads(body)
    for path in (ROOT, *ROOT.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Installed release ancestors must be immutable root-owned directories')
    actual = set()
    for current, directories, files in os.walk(ROOT, followlinks=False):
        current_info = Path(current).lstat()
        if current_info.st_uid != 0 or current_info.st_mode & 0o222:
            raise PermissionError('Untrusted installed directory')
        for name in directories + files:
            path = Path(current) / name
            relative = str(path.relative_to(ROOT))
            info = path.lstat()
            if info.st_uid != 0:
                raise PermissionError('Installed payload ownership mismatch')
            if stat.S_ISDIR(info.st_mode):
                continue
            actual.add(relative)
            record = expected.get(relative)
            if stat.S_ISLNK(info.st_mode):
                if record != {'link': os.readlink(path)} or not path.resolve(strict=True).is_relative_to(ROOT):
                    raise ValueError('Installed symlink changed or escaped')
            elif stat.S_ISREG(info.st_mode):
                if info.st_mode & 0o222:
                    raise PermissionError('Installed payload became writable')
                with path.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                if record != {'sha256': digest, 'executable': bool(info.st_mode & 0o111)}:
                    raise ValueError('Installed payload differs: ' + relative)
            else:
                raise ValueError('Unexpected installed special file')
    if actual != set(expected) or len(actual) != 26359:
        raise ValueError('Installed payload inventory mismatch')
    print(json.dumps({'passed': True, 'installed_release': str(ROOT),
                      'manifest_sha256': MANIFEST_SHA, 'entries_verified': len(actual),
                      'mutations': 0}))


if __name__ == '__main__':
    main()
