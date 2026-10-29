#!/usr/bin/python3
"""Read-only A7Dev preinstall gate: private runtime hash and current release.

Run as agentporter-dev AFTER stopping/quiescing development and immediately
before the reviewed installer. Prints hashes only; never credential paths/data.
This gate does not itself grant installation or start/stop services.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-version', required=True)
    parser.add_argument('--expected-canonical-sha256', required=True)
    args = parser.parse_args()
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    if os.geteuid() != uid or uid == 0:
        raise PermissionError('Run only as agentporter-dev')
    if not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.expected_version):
        raise ValueError('Invalid expected release')
    if not re.fullmatch('[a-f0-9]{64}', args.expected_canonical_sha256):
        raise ValueError('Invalid expected runtime SHA256')
    current = Path('/opt/agentporter-development/current').resolve(strict=True)
    if current != Path('/opt/agentporter-development/versions') / args.expected_version:
        raise ValueError('Active A7Dev release changed; rebuild/review the candidate')
    fd = os.open('/var/lib/agentporter-dev/config/development-runtime.yaml',
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
                or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > 1024**2):
            raise PermissionError('Unsafe A7Dev runtime control file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(1024**2 + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError('Runtime changed during preinstall validation')
    finally:
        os.close(fd)
    runtime = yaml.safe_load(data)
    if not isinstance(runtime, dict) or runtime.get('profile') != 'development':
        raise ValueError('Not an A7Dev runtime')
    canonical = json.dumps(runtime, sort_keys=True, separators=(',', ':')).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != args.expected_canonical_sha256:
        raise ValueError('Active A7Dev runtime differs from candidate baseline; refuse install and rebuild with reviewed active runtime')
    print(json.dumps({'runtime_install_gate': 'passed', 'current_version': current.name,
                      'active_runtime_canonical_sha256': digest, 'production_changed': False}))


if __name__ == '__main__':
    main()
