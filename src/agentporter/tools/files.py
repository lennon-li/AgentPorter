"""File and search operations scoped to workspaces."""

import os
import hashlib
import logging
import ctypes
import errno
import uuid
import contextlib
import stat
from typing import Optional
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.bounded import read_regular, walk_files, capture_bounded
from agentporter.workspaces.shared_access import atomic_write, acl, human_can_traverse, share

logger = logging.getLogger("agentporter.tools.files")

MAX_FULL_READ_BYTES = 1024 * 1024
MAX_WRITE_BYTES = 5 * 1024 * 1024
MAX_PATCH_BYTES = 2 * 1024 * 1024
MAX_RANGE_LINES = 5000
MAX_SEARCH_RESULTS = 200
MAX_HASH_READ_BYTES = 8 * 1024 * 1024

RG_SENSITIVE_EXCLUDES = [
    "!.git/**",
    "!.ssh/**",
    "!**/.git/**",
    "!**/.ssh/**",
    "!**/.env",
    "!**/.env.*",
    "!**/secrets.env",
    "!**/id_rsa",
    "!**/id_ed25519",
    "!**/*.pem",
    "!**/*.key",
]


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@contextlib.contextmanager
def _mutation_parent(root, path, *, create=False, repair_trash_parent=False):
    """Resolve lexical components through pinned, non-symlink directory fds.

    Do not use realpath's resolved spelling: that would silently accept an
    in-workspace symlink ancestor. Directory relocation by an external host
    owner is outside the application lock boundary; confinement remains required.
    """
    validate_workspace_path(root, path)
    components = os.path.normpath(path).split(os.sep)
    with contextlib.ExitStack() as stack:
        fd = os.open(root, _DIRECTORY_FLAGS)
        stack.callback(os.close, fd)
        owner = os.fstat(fd).st_uid
        device = os.fstat(fd).st_dev
        for component in components[:-1]:
            created = False
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            stack.callback(os.close, child)
            if os.fstat(child).st_dev != device:
                raise ValueError("Mutation across a filesystem boundary is unsupported")
            if created:
                try:
                    # mkdir(mode=0700) can mask inherited access ACL rights.
                    # Build the child's access ACL from the parent's default ACL,
                    # then retain the inherited default ACL for future children.
                    share(child, owner, acl(fd, default=True), directory=True)
                    if not human_can_traverse(child, owner):
                        raise PermissionError("Workspace owner cannot traverse the new directory")
                except BaseException:
                    try:
                        os.rmdir(component, dir_fd=fd)
                    except OSError:
                        pass
                    raise
            elif not human_can_traverse(child, owner) and not (
                    repair_trash_parent and component == ".trash"
                    and os.fstat(child).st_uid == os.geteuid()):
                # Never report success for a mutation hidden behind a
                # preexisting service-owned/private ancestor. Repairing an
                # existing ACL is an explicit operator action, not an implicit
                # consequence of writing a descendant.
                raise PermissionError(
                    "Workspace owner cannot traverse an existing mutation parent"
                )
            fd = child
        yield fd, components[-1], owner


def _rename_noreplace(source_fd, source, destination_fd, destination):
    """Linux atomic rename only: no cross-device copy or overwrite fallback."""
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOSYS, "Atomic no-replace rename unavailable")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd,
              os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _ordinary_source(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise ValueError("Move requires a regular file or directory; symlinks are unsupported")


def create_file_tools(registry: WorkspaceRegistry):
    def list_files(workspace_id: str, path: str = "", depth: Optional[int] = 1) -> list[str]:
        """List non-hidden files at the requested depth (default: one level)."""
        ws = registry.get(workspace_id)
        return sorted(walk_files(ws.path, path, depth))

    def search_text(workspace_id: str, query: str, glob: str = "*", max_results: int = 50) -> list[dict]:
        """Search text without exposing paths that normal file reads would block."""
        ws = registry.get(workspace_id)
        ws_root = ws.path
        max_results = max(1, min(int(max_results), MAX_SEARCH_RESULTS))

        cmd = [
            "rg",
            "--line-number",
            "--color",
            "never",
            "--max-count",
            str(max_results),
            '--max-filesize', str(MAX_FULL_READ_BYTES), '--max-depth', '16',
        ]
        for excluded in RG_SENSITIVE_EXCLUDES:
            cmd.extend(["--glob", excluded])
        if glob and glob != "*":
            cmd.extend(["--glob", glob])
        cmd.extend(["--", query, ws_root])

        try:
            code, stdout, stderr = capture_bounded(cmd)
            if code not in (0, 1):
                raise RuntimeError(stderr.strip() or f"ripgrep failed with exit {code}")

            results = []
            for line in stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) != 3:
                    continue
                filepath, line_no, text = parts
                rel_path = os.path.relpath(filepath, ws_root)
                try:
                    validate_workspace_path(ws_root, rel_path)
                except ValueError:
                    continue
                results.append({
                    "path": rel_path,
                    "line": int(line_no) if line_no.isdigit() else line_no,
                    "text": text,
                })
                if len(results) >= max_results:
                    break
            return results
        except Exception as e:
            logger.error("search_text error: %s", e)
            return []

    def read_file(
        workspace_id: str,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> dict:
        """Read a bounded file; sha256 and size_bytes describe original bytes.

        Lines use Python's Unicode splitlines boundaries (including CR, LF,
        and CRLF). A ranged response reports the normalized requested bounds;
        total_lines states how many decoded lines actually exist.
        """
        ws = registry.get(workspace_id)
        full_path = validate_workspace_path(ws.path, path)
        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"File not found: '{path}'")

        ranged = start_line is not None or end_line is not None
        data = read_regular(ws.path, path, MAX_HASH_READ_BYTES if ranged else MAX_FULL_READ_BYTES)
        size = len(data)
        full_sha256 = hashlib.sha256(data).hexdigest()
        text = data.decode('utf-8', errors='replace')

        if start_line is None and end_line is None:
            if size > MAX_FULL_READ_BYTES:
                raise ValueError(
                    f"File is {size} bytes; full reads are limited to {MAX_FULL_READ_BYTES}. "
                    "Use start_line/end_line."
                )
            content = text
            if len(content.encode('utf-8')) > MAX_FULL_READ_BYTES:
                raise ValueError('Decoded full read exceeds output budget')
            total_lines = len(content.splitlines())
            return {
                "path": path,
                "content": content,
                "sha256": full_sha256,
                "size_bytes": size,
                "total_lines": total_lines,
                "range": {"start_line": 1, "end_line": total_lines},
            }

        start = 1 if start_line is None else int(start_line)
        end = (start + MAX_RANGE_LINES - 1) if end_line is None else int(end_line)
        if start < 1 or end < 1:
            raise ValueError("Line bounds must be positive integers")
        if end < start:
            raise ValueError("end_line must be >= start_line")
        if end - start + 1 > MAX_RANGE_LINES:
            raise ValueError(f"Line ranges are limited to {MAX_RANGE_LINES} lines")

        selected = []
        lines = text.splitlines(keepends=True)
        total_lines = len(lines)
        for number, line in enumerate(lines, start=1):
            if start <= number <= end:
                selected.append(line)
        if len(''.join(selected).encode('utf-8')) > MAX_FULL_READ_BYTES:
            raise ValueError('Selected lines exceed output budget')
        return {
            "path": path,
            "content": "".join(selected),
            "sha256": full_sha256,
            "size_bytes": size,
            "total_lines": total_lines,
            "range": {"start_line": start, "end_line": end},
        }

    def write_file(
        workspace_id: str,
        path: str,
        content: str,
        expected_sha256: Optional[str] = None,
    ) -> dict:
        """Atomically write bounded UTF-8 content with optional stale-file protection."""
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")

        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_WRITE_BYTES:
            raise ValueError(f"write_file content exceeds {MAX_WRITE_BYTES} bytes")

        atomic_write(ws.path, path, content_bytes, expected_sha256)

        return {
            "path": path,
            "status": "written",
            "bytes": len(content_bytes),
            "sha256": hashlib.sha256(content_bytes).hexdigest(),
        }

    def apply_patch(workspace_id: str, patch: str) -> dict:
        """Apply a bounded unified diff after validating every target path."""
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        if len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
            raise ValueError(f"Patch exceeds {MAX_PATCH_BYTES} bytes")

        from agentporter.workspaces.patching import apply_workspace_patch
        proc = apply_workspace_patch(ws.path, patch, MAX_WRITE_BYTES)
        if proc.returncode != 0:
            return {"status": "failed", "exit_code": proc.returncode,
                    "stdout": proc.stdout[:100000], "stderr": proc.stderr[:100000]}
        return {
            "status": "applied",
            "exit_code": 0,
            "stdout": proc.stdout[:100000],
        }

    def mkdir(workspace_id: str, path: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        validate_workspace_path(ws.path, path)
        if os.path.normpath(path) == ".":
            raise ValueError("Root directory not allowed for this operation")
        # Resolve the final directory as a parent of a synthetic child, so
        # every component is opened with O_NOFOLLOW and new ACLs are shared.
        with _mutation_parent(ws.path, os.path.join(path, "child"), create=True):
            pass
        return {"path": path, "status": "created"}

    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        with _mutation_parent(ws.path, source) as (src, name, _):
            _ordinary_source(src, name)
            with _mutation_parent(ws.path, destination, create=True) as (dst, target, _):
                _rename_noreplace(src, name, dst, target)
        return {"source": source, "destination": destination, "status": "moved"}

    def trash_path(workspace_id: str, path: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        validate_workspace_path(ws.path, path)
        if os.path.normpath(path).split(os.sep)[0] == ".trash":
            raise ValueError("The trash directory is not a source for trash_path")
        with _mutation_parent(ws.path, path) as (src, name, owner):
            _ordinary_source(src, name)
            with _mutation_parent(ws.path, ".trash/child", create=True,
                                  repair_trash_parent=True) as (trash, _, _):
                # Repair only our own trash directory, retaining effective ACL
                # restrictions for unrelated users. Never chmod/chown user files.
                if os.fstat(trash).st_uid == os.geteuid():
                    share(trash, owner, directory=True)
                if not human_can_traverse(trash, owner):
                    raise PermissionError("Workspace owner cannot access the trash directory")
                # Keep NAME_MAX-safe even for maximum-length UTF-8 basenames.
                limit = os.fpathconf(trash, "PC_NAME_MAX") - 33
                prefix = name
                while prefix and len(os.fsencode(prefix)) > limit:
                    prefix = prefix[:-1]
                dest_name = uuid.uuid4().hex + "_" + prefix
                _rename_noreplace(src, name, trash, dest_name)
        return {"path": path, "status": "trashed",
                "trash_location": ".trash/" + dest_name}

    return (
        list_files,
        search_text,
        read_file,
        write_file,
        apply_patch,
        mkdir,
        move_path,
        trash_path,
    )
