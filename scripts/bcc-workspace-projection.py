"""Owner-controlled read-only workspace projection provisioning for BCC.

Default is plan-only. Install a reviewed root-owned copy outside workspaces;
run using /usr/bin/python3 -I -S. --apply creates a persistent idmapped mount.
"""
import ctypes
import json
import os
from pathlib import Path
import pwd
import select
import signal
import stat

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def checked(result, operation):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, operation + ': ' + os.strerror(error))
    return result


def mapping_namespace(owner, worker):
    ready_read, ready_write = os.pipe()
    hold_read, hold_write = os.pipe()
    process = os.fork()
    if process == 0:
        os.close(ready_read)
        os.close(hold_write)
        try:
            checked(LIBC.unshare(0x10000000), 'unshare user namespace')
            os.write(ready_write, b'R')
            os.read(hold_read, 1)
            os._exit(0)
        except BaseException:
            os.write(ready_write, b'E')
            os._exit(111)
    os.close(ready_write)
    os.close(hold_read)
    try:
        require(bool(select.select([ready_read], [], [], 5)[0]), 'User namespace helper timed out')
        require(os.read(ready_read, 1) == b'R', 'User namespace helper failed')
        proc = Path('/proc') / str(process)
        (proc / 'setgroups').write_text('deny')
        # Mount idmaps map on-disk IDs (column 1) to projected IDs (column 2).
        (proc / 'uid_map').write_text(f'{owner.pw_uid} {worker.pw_uid} 1\n')
        (proc / 'gid_map').write_text(f'{owner.pw_gid} {worker.pw_gid} 1\n')
        return os.open(proc / 'ns/user', os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(hold_write)
        os.close(ready_read)
        try:
            os.kill(process, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(process, 0)


class MountAttributes(ctypes.Structure):
    _fields_ = [('attr_set', ctypes.c_uint64), ('attr_clr', ctypes.c_uint64),
                ('propagation', ctypes.c_uint64), ('userns_fd', ctypes.c_uint64)]


def trusted_directory(path, *, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for component in path.parts[1:]:
            if create:
                try:
                    os.mkdir(component, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Untrusted projection parent')
    finally:
        os.close(fd)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--publication', action='store_true', help='Provision a trusted writable publication view; never mount it in a job')
    args = parser.parse_args()
    source = Path(args.source)
    require(source.is_absolute() and source.is_relative_to(Path('/home/yeli/repos')) and source != Path('/home/yeli/repos')
            and source.resolve(strict=True) == source and source.is_dir(),
            'Source must be one canonical directory inside BCC repositories')
    owner = pwd.getpwnam('yeli')
    worker = pwd.getpwnam('agentporter-bcc-worker')
    require((owner.pw_uid, owner.pw_gid, worker.pw_uid, worker.pw_gid)
            == (2056259175, 2056259276, 997, 997), 'Unexpected BCC account identities')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    source_fd = os.open(source, flags)
    namespace = mount = None
    attached = created = False
    root = Path('/var/lib/agentporter-bcc/publication-views' if args.publication else '/var/lib/agentporter-bcc/projections')
    try:
        identity = os.fstat(source_fd)
        require(identity.st_uid == owner.pw_uid, 'Unexpected source owner')
        target = root / f'{identity.st_dev:x}-{identity.st_ino:x}'
        plan = {'source': str(source), 'source_uid': identity.st_uid,
                'worker_uid': worker.pw_uid, 'projection': str(target), 'read_only': not args.publication}
        if not args.apply:
            print(json.dumps(dict(plan, action='PLAN_ONLY'), sort_keys=True))
            return
        require(os.getuid() == 0 and os.geteuid() == 0, 'Apply requires owner sudo authentication')
        script = Path(__file__)
        for ancestor in reversed(script.parents):
            metadata = ancestor.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                    and not metadata.st_mode & 0o022, 'Install helper outside writable directories')
        metadata = script.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022, 'Install a root-owned reviewed helper')
        trusted_directory(root, create=True)
        if os.path.lexists(target):
            metadata = target.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and
                    (metadata.st_dev, metadata.st_ino) == (identity.st_dev, identity.st_ino)
                    and metadata.st_uid == worker.pw_uid and metadata.st_gid == worker.pw_gid
                    and bool(os.statvfs(target).f_flag & os.ST_RDONLY) != args.publication,
                    'Existing projection requires owner inspection')
            print(json.dumps(dict(plan, action='ALREADY_PROVISIONED'), sort_keys=True))
            return
        target.mkdir(mode=0o755)
        created = True
        namespace = mapping_namespace(owner, worker)
        # Clone the pinned source descriptor; never resolve the source name again.
        mount = checked(LIBC.syscall(428, ctypes.c_int(source_fd), ctypes.c_char_p(b''),
                        ctypes.c_uint(1 | os.O_CLOEXEC | 0x1000)), 'clone pinned source mount')
        attributes = MountAttributes(0x00100000 | (0 if args.publication else 1) | 2 | 4, 0, 0, namespace)
        checked(LIBC.syscall(442, ctypes.c_int(mount), ctypes.c_char_p(b''), ctypes.c_uint(0x1000),
                    ctypes.byref(attributes), ctypes.c_size_t(ctypes.sizeof(attributes))), 'set read-only mapped mount')
        checked(LIBC.syscall(429, ctypes.c_int(mount), ctypes.c_char_p(b''), ctypes.c_int(-100),
                    ctypes.c_char_p(os.fsencode(target)), ctypes.c_uint(4)), 'attach mapped projection')
        attached = True
        metadata = target.stat()
        require((metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid) ==
                (identity.st_dev, identity.st_ino, worker.pw_uid, worker.pw_gid), 'Projection identity check failed')
        require(bool(os.statvfs(target).f_flag & os.ST_RDONLY) != args.publication, 'Projection access mode differs from plan')
        print(json.dumps(dict(plan, action='PROVISIONED'), sort_keys=True))
        created = False
    except BaseException:
        if attached:
            checked(LIBC.umount2(ctypes.c_char_p(os.fsencode(target)), 0), 'remove failed projection')
        if created:
            target.rmdir()
        raise
    finally:
        os.close(source_fd)
        if mount is not None:
            os.close(mount)
        if namespace is not None:
            os.close(namespace)


if __name__ == '__main__':
    main()
