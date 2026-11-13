"""Read the root-managed shared CLI selection without account or session data."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/opt/agent-clis')


def selected_cli(provider, *, deadline=None, file_field='binary'):
    """Verify root custody and selected provider bytes within the caller's bound.

    The root-owned manifest selects the version; a user-owned PATH entry never
    supplies a quota collector executable. No authentication is inspected here.
    """
    if provider not in {'codex','claude','copilot','opencode','agy'} or file_field not in {'binary','sdk'}:
        raise PermissionError('Unknown shared CLI object')
    current = ROOT/'current'
    link = current.lstat()
    if not stat.S_ISLNK(link.st_mode) or link.st_uid != 0:
        raise PermissionError('Untrusted shared CLI selection')
    release = current.resolve(strict=True)
    if release.parent != ROOT/'releases' or not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{8}',release.name):
        raise PermissionError('Invalid shared CLI release')
    for path in (release,*release.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted shared CLI ancestor')
    manifest_path = release/'MANIFEST.json'
    descriptor = os.open(manifest_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size>8*1024**2:
            raise PermissionError('Untrusted shared CLI manifest')
        raw=os.read(descriptor,8*1024**2+1)
        if len(raw)!=info.st_size:
            raise PermissionError('Shared CLI manifest changed')
    finally:
        os.close(descriptor)
    manifest=json.loads(raw)
    row=manifest['providers'][provider]
    version=row['version']
    relative=Path(row[file_field])
    if (manifest['schema']!=1 or manifest['account_data_included'] is not False
            or not re.fullmatch(r'\d+\.\d+\.\d+',version)
            or relative.is_absolute() or '..' in relative.parts):
        raise PermissionError('Invalid shared Codex descriptor')
    executable=release/relative
    for path in (executable,*list(executable.parents)[:len(relative.parts)-1]):
        info=path.lstat()
        if info.st_uid!=0 or info.st_mode&0o022 or stat.S_ISLNK(info.st_mode):
            raise PermissionError('Untrusted shared Codex path')
    descriptor=os.open(executable,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(descriptor)
        expected=manifest['files'][relative.as_posix()]
        if (not stat.S_ISREG(before.st_mode) or (file_field=='binary' and not before.st_mode&0o111)
                or before.st_size!=expected['size'] or not 0<before.st_size<=512*1024**2):
            raise PermissionError('Invalid shared Codex executable')
        digest=sha256()
        while True:
            if deadline is not None and time.monotonic()>=deadline:
                raise TimeoutError('Shared CLI verification deadline')
            block=os.read(descriptor,1024*1024)
            if not block:
                break
            digest.update(block)
        after=os.fstat(descriptor)
        if (digest.hexdigest()!=expected['sha256'] or before!=after
                or executable.stat()!=after):
            raise PermissionError('Shared Codex bytes differ from manifest')
    finally:
        os.close(descriptor)
    return executable,version


def selected_codex(*, deadline=None):
    return selected_cli('codex',deadline=deadline)
