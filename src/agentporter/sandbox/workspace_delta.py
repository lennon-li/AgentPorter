"""Fail-closed validation of a quiescent workspace overlay before publication.

The caller must first stop the entire job cgroup and retain exclusive control of
its overlay. Validation alone does not publish data or grant commit authority.
"""
import os
import stat
from pathlib import Path

from agentporter.workspaces.paths import check_sensitive_components


class UnsafeWorkspaceDelta(PermissionError):
    """An overlay contains a change that must not be published."""


def _require_public_path(relative_path: str) -> None:
    try:
        check_sensitive_components(relative_path, relative_path)
    except ValueError as error:
        raise UnsafeWorkspaceDelta('Protected workspace path changed') from error


def validate_workspace_delta(root: Path, *, max_entries: int = 100_000) -> None:
    if max_entries <= 0:
        raise ValueError('max_entries must be positive')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    base_fd = os.open(root, flags)
    remaining = max_entries
    try:
        def inspect(fd: int, depth: int, parts: tuple[str, ...] = ()) -> None:
            nonlocal remaining
            if depth > 128:
                raise UnsafeWorkspaceDelta('Workspace delta exceeds depth limit')
            if any(name.startswith(('user.overlay.', 'trusted.overlay.'))
                   for name in os.listxattr(fd) if name not in {'user.overlay.origin', 'trusted.overlay.origin',
                                         'user.overlay.uuid', 'trusted.overlay.uuid',
                                         'user.overlay.impure', 'trusted.overlay.impure'}):
                raise UnsafeWorkspaceDelta('Unsupported overlay metadata')
            with os.scandir(fd) as entries:
                for entry in entries:
                    remaining -= 1
                    if remaining < 0:
                        raise UnsafeWorkspaceDelta('Workspace delta exceeds entry limit')
                    relative_parts = parts + (entry.name,)
                    _require_public_path('/'.join(relative_parts))
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            inspect(child, depth + 1, relative_parts)
                        finally:
                            os.close(child)
                    elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                          or info.st_mode & 0o7000 or info.st_size > 64 * 1024 * 1024):
                        raise UnsafeWorkspaceDelta('Unsupported workspace delta entry')
                    else:
                        child = os.open(entry.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                        dir_fd=fd)
                        try:
                            if any(name.startswith(('user.overlay.', 'trusted.overlay.'))
                                   for name in os.listxattr(child) if name not in {'user.overlay.origin', 'trusted.overlay.origin',
                                         'user.overlay.uuid', 'trusted.overlay.uuid',
                                         'user.overlay.impure', 'trusted.overlay.impure'}):
                                raise UnsafeWorkspaceDelta('Unsupported overlay metadata')
                        finally:
                            os.close(child)
        inspect(base_fd, 0)
    finally:
        os.close(base_fd)


def publish_workspace_file(
    workspace: Path,
    relative_path: str,
    source: Path,
    *,
    expected_sha256: str | None,
    max_bytes: int = 64 * 1024 * 1024,
) -> str:
    """Replace one ordinary file without following destination inode aliases.

    Internal primitive only: the caller must own an exclusive workspace mutation
    lease, stop every job process, and retain exclusive custody of the validated
    delta. This function does not authorize a job, Git action, or publication,
    and does not provide a multi-file transaction or crash-recovery journal.
    A missing expected digest means create-only; existing files require a match.
    """
    import hashlib
    import secrets

    parts = relative_path.split('/')
    if not relative_path or any(part in {'', '.', '..'} for part in parts):
        raise UnsafeWorkspaceDelta('Invalid relative workspace path')
    _require_public_path(relative_path)
    if max_bytes <= 0:
        raise ValueError('max_bytes must be positive')
    if expected_sha256 is not None and (
        len(expected_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_sha256)
    ):
        raise ValueError('Expected digest must be lowercase SHA256')

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK

    def read_checked(fd):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UnsafeWorkspaceDelta('File must be regular with one link')
        if info.st_mode & 0o7000 or info.st_size > max_bytes:
            raise UnsafeWorkspaceDelta('Unsupported file mode or size')
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise UnsafeWorkspaceDelta('File exceeds size limit')
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise UnsafeWorkspaceDelta('File changed during inspection')
        return bytes(data), after

    source_fd = os.open(source, file_flags)
    try:
        data, source_info = read_checked(source_fd)
    finally:
        os.close(source_fd)
    parent_fd = os.open(workspace, directory_flags)
    temporary_name = None
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        name = parts[-1]
        try:
            existing_fd = os.open(name, file_flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if expected_sha256 is not None:
                raise UnsafeWorkspaceDelta('Workspace edit conflicts with missing file')
            existing_info = None
            mode = source_info.st_mode & 0o777
        else:
            try:
                existing, existing_info = read_checked(existing_fd)
            finally:
                os.close(existing_fd)
            if expected_sha256 is None or hashlib.sha256(existing).hexdigest() != expected_sha256:
                raise UnsafeWorkspaceDelta('Workspace edit conflicts with existing file')
            mode = existing_info.st_mode & 0o777

        temporary_name = '.agentporter-edit-' + secrets.token_hex(16)
        output_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                            | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(output_fd, data[offset:offset + 65536])
            os.fchmod(output_fd, mode)
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if existing_info is None:
            if current is not None:
                raise UnsafeWorkspaceDelta('Workspace destination appeared during publication')
            # link() has create-only semantics; rename() would overwrite a new entry.
            os.link(temporary_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    follow_symlinks=False)
            os.unlink(temporary_name, dir_fd=parent_fd)
        else:
            if current is None or (
                current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                current.st_ctime_ns, current.st_nlink
            ) != (
                existing_info.st_dev, existing_info.st_ino, existing_info.st_size,
                existing_info.st_mtime_ns, existing_info.st_ctime_ns, 1
            ):
                raise UnsafeWorkspaceDelta('Workspace destination changed during publication')
            os.replace(temporary_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary_name = None
        os.fsync(parent_fd)
        return hashlib.sha256(data).hexdigest()
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
