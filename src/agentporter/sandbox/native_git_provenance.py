"""Fixed native FD bridge; production packages supply a frozen library/manifest.

The source-checkout compiler fallback is a development prototype prerequisite.
It must be replaced by a reviewed frozen artifact in a production release.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def _artifact(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>4*1024*1024:
            raise PermissionError('Untrusted native Git bridge artifact')
        with os.fdopen(os.dup(descriptor),'rb') as stream:data=stream.read(4*1024*1024+1)
        after=os.fstat(descriptor)
        if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise PermissionError('Native Git bridge artifact changed during read')
        return data
    finally:os.close(descriptor)


def load_prebuilt(directory,artifact,manifest,*,source_sha256):
    """Copy only the frozen adjacent package artifact verified by its manifest."""
    expected=json.loads(_artifact(manifest))
    library=_artifact(artifact)
    digest=hashlib.sha256(library).hexdigest()
    if (not isinstance(expected,dict) or set(expected)!={'schema','source_sha256','library_sha256'}
            or expected['schema']!=1 or expected['source_sha256']!=source_sha256
            or expected['library_sha256']!=digest or not library.startswith(b'\x7fELF')):
        raise PermissionError('Frozen native Git bridge differs from package manifest')
    target=Path(directory)/'native-git-provenance.so'
    descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o500)
    try:
        with os.fdopen(os.dup(descriptor),'wb') as stream:stream.write(library);stream.flush()
        os.fsync(descriptor)
    finally:os.close(descriptor)
    return {'source_sha256':source_sha256,'library_sha256':digest,'prototype_compile_used':False}


def build(directory):
    source_path=Path(__file__).with_suffix('.c');source=source_path.read_bytes()
    source_hash=hashlib.sha256(source).hexdigest()
    # A distinct asset basename cannot shadow this Python wrapper as an extension module.
    frozen=source_path.with_name('native-git-provenance.so');manifest=source_path.with_name('native-git-provenance.json')
    if os.path.lexists(frozen) or os.path.lexists(manifest):
        return load_prebuilt(directory,frozen,manifest,source_sha256=source_hash)
    target=Path(directory)/'native-git-provenance.so'
    subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
        '-Wl,-z,relro,-z,now','-x','c','-','-o',str(target),'-ldl'],input=source,
        check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    target.chmod(0o500)
    descriptor=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    return {'source_sha256':source_hash,'library_sha256':hashlib.sha256(_artifact(target)).hexdigest(),
            'prototype_compile_used':True}
