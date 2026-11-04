#!/usr/bin/env python3
"""Normalize tar/gzip timestamps and owners without changing payload bytes.

The pinned candidate builder supplies a stable member order. No extraction,
payload execution, service changes or privileged operations.
"""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import tarfile


def canonicalize(source, expected, destination):
    if os.geteuid()==0:
        raise PermissionError('Unprivileged artifact preparation only')
    with source.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=expected:
            raise ValueError('Original artifact hash mismatch')
    with source.open('rb') as incoming,destination.open('xb') as outgoing:
        with tarfile.open(fileobj=incoming,mode='r|gz') as original:
            with gzip.GzipFile(fileobj=outgoing,mode='wb',filename='',mtime=0,compresslevel=1) as zipped:
                with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as packed:
                    seen=set();total=0
                    for entry in original:
                        if entry.name in seen or not (entry.isdir() or entry.isreg() or entry.issym()):
                            raise ValueError('Unreviewed archive member')
                        seen.add(entry.name)
                        total+=entry.size
                        if total>8*1024**3:raise ValueError('Expansion limit')
                        stream=original.extractfile(entry) if entry.isreg() else None
                        entry.uid=entry.gid=0;entry.uname=entry.gname='';entry.mtime=0;entry.pax_headers={}
                        packed.addfile(entry,stream)
    destination.chmod(0o400)
    with destination.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(canonicalize(args.artifact,args.sha256,args.output),flush=True)


if __name__=='__main__':main()
