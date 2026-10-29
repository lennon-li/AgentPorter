"""Pin an owner-provisioned read-only idmapped lower for a foreign-owned project."""
import os
from pathlib import Path

PROJECTION_ROOT = Path('/var/lib/agentporter-bcc/projections')
PUBLICATION_ROOT = Path('/var/lib/agentporter-bcc/publication-views')


def _require_trusted_parent(info):
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('Untrusted workspace projection parent')


def _open_workspace_view(source_fd: int, *, publication: bool = False) -> int:
    """Return a verified lower FD; the caller retains the canonical publication FD.

    Only root can provision views. Every parent is checked using no-follow
    directory descriptors. Matching device/inode pins the same directory,
    while the differing UID and read-only filesystem check constrain its view.
    """
    source = os.fstat(source_fd)
    view_root = PUBLICATION_ROOT if publication else PROJECTION_ROOT
    name = f'{source.st_dev:x}-{source.st_ino:x}'
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent = os.open('/', flags)
    projection = None
    try:
        for component in view_root.parts[1:]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            _require_trusted_parent(info)
        projection = os.open(name, flags, dir_fd=parent)
        mapped = os.fstat(projection)
        if (mapped.st_dev, mapped.st_ino) != (source.st_dev, source.st_ino):
            raise PermissionError('Workspace projection does not match canonical directory')
        if mapped.st_uid != os.getuid() or mapped.st_gid != os.getgid():
            raise PermissionError('Workspace projection does not map to the worker identity')
        read_only = bool(os.fstatvfs(projection).f_flag & os.ST_RDONLY)
        if read_only == publication:
            raise PermissionError('Workspace publication view must be writable' if publication else 'Workspace projection must be read-only')
        result, projection = projection, None
        return result
    except FileNotFoundError as error:
        raise PermissionError('Foreign-owned workspace requires an owner-provisioned idmapped projection') from error
    finally:
        if projection is not None:
            os.close(projection)
        os.close(parent)


def open_workspace_projection(source_fd: int) -> int:
    return _open_workspace_view(source_fd)


def open_workspace_publication(source_fd: int) -> int:
    """Trusted publisher only; never pass this directory FD to a job process."""
    return _open_workspace_view(source_fd, publication=True)
