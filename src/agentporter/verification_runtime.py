"""Optional sealed Python test tools; never mount a user environment or HOME."""
import json
import os
from pathlib import Path
import stat

ROOT = Path('/opt/agentporter-bcc/verification-runtime')
TARGET = '/opt/agentporter/verification'


def add_verification_runtime(args):
    current = ROOT / 'current'
    if not os.path.lexists(current):
        return False
    root = ROOT.resolve(strict=True)
    release = current.resolve(strict=True)
    if release.parent != root / 'releases':
        raise PermissionError('Verification runtime selection escapes its sealed releases')
    for path in (root, root / 'releases', release, release / 'MANIFEST.json',
                 release / 'pyvenv.cfg', release / 'bin', release / 'lib'):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise PermissionError('Verification runtime must be root-owned and protected')
    manifest = json.loads((release / 'MANIFEST.json').read_text())
    if manifest.get('code_only') is not True or manifest.get('python_minor') != '3.13':
        raise PermissionError('Unverified verification runtime')
    args.extend(['--ro-bind', str(release), TARGET])
    return True
