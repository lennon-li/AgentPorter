"""File and search operations scoped to workspaces."""

import os
import base64
import json
import time
import shutil
import hashlib
import subprocess
import logging
from typing import Optional
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.bounded import read_regular, walk_files, capture_bounded, read_workspace_root, _read_regular_at
from agentporter.workspaces.shared_access import atomic_write, workspace_mkdir, workspace_move

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


def create_file_tools(registry: WorkspaceRegistry, *, mutation_state_dir=None):
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
            "--json",
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
        cmd.extend(["--", query])

        try:
            with read_workspace_root(ws_root) as root_fd:
                search_root = f'/proc/self/fd/{root_fd}/.'
                code, stdout, stderr = capture_bounded(cmd + [search_root], workspace_fd=root_fd, workspace_relative=True)
                if code not in (0, 1):
                    raise RuntimeError(stderr.strip() or f"ripgrep failed with exit {code}")
                results = []
                for line in stdout.splitlines():
                    record = json.loads(line)
                    if record.get('type') != 'match':
                        continue
                    match = record['data']
                    path_record = match['path']
                    if set(path_record) != {'text'} or not isinstance(path_record['text'], str):
                        continue  # Non-UTF8 filenames have no safe public text path.
                    filepath = path_record['text']
                    filepath.encode('utf-8', errors='strict')
                    if not filepath.startswith('./') or '\x00' in filepath:
                        continue
                    line_no = match['line_number']
                    if type(line_no) is not int or line_no < 1:
                        continue
                    captured = match['lines']
                    if set(captured) == {'text'}:
                        rg_line = captured['text'].encode('utf-8', errors='strict')
                    elif set(captured) == {'bytes'}:
                        rg_line = base64.b64decode(captured['bytes'], validate=True)
                    else:
                        continue
                    rel_path = filepath[2:]
                    try:
                        validate_workspace_path(ws_root, rel_path)
                        # Only validated bytes from the actual named file may
                        # become public text. RG text is merely a match hint.
                        data = _read_regular_at(root_fd, rel_path, MAX_FULL_READ_BYTES)
                    except (ValueError, FileNotFoundError):
                        continue
                    lines = data.split(b'\n')
                    if line_no > len(lines):
                        continue
                    actual = lines[line_no - 1] + (b'\n' if line_no < len(lines) else b'')
                    if actual != rg_line:
                        continue  # Atomic replacement/change since RG searched.
                    text = actual.removesuffix(b'\n').removesuffix(b'\r').decode('utf-8', errors='replace')
                    results.append({"path": rel_path, "line": line_no, "text": text})
                    if len(results) >= max_results:
                        break
                return results
        except PermissionError:
            raise
        except Exception as e:
            logger.error("search_text error: %s", e)
            return []

    def read_file(
        workspace_id: str,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> dict:
        """Read bounded text; original bytes determine hash/size, Unicode splitlines determine lines."""
        ws = registry.get(workspace_id)
        validate_workspace_path(ws.path, path)
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
        if start < 1 or end < 1:raise ValueError("Line bounds must be positive integers")
        if end < start:
            raise ValueError("end_line must be >= start_line")
        if end - start + 1 > MAX_RANGE_LINES:
            raise ValueError(f"Line ranges are limited to {MAX_RANGE_LINES} lines")

        selected = []
        total_lines = 0
        for number, line in enumerate(text.splitlines(keepends=True), start=1):
                total_lines = number
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

        atomic_write(ws.path, path, content_bytes, expected_sha256, publication_state=mutation_state_dir)

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
        proc = apply_workspace_patch(ws.path, patch, MAX_WRITE_BYTES, publication_state=mutation_state_dir)
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
        workspace_mkdir(ws.path, path, publication_state=mutation_state_dir)
        return {"path": path, "status": "created"}

    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        workspace_move(ws.path, source, destination, publication_state=mutation_state_dir)
        return {"source": source, "destination": destination, "status": "moved"}

    def trash_path(workspace_id: str, path: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        validate_workspace_path(ws.path, path)
        base = os.path.basename(os.path.normpath(path))
        timestamp = int(time.time())
        destination = os.path.join('.trash', f"{timestamp}_{base}")
        workspace_move(ws.path, path, destination, publication_state=mutation_state_dir, trash=True)
        return {
            "path": path,
            "status": "trashed",
            "trash_location": destination,
        }

    from agentporter.workspaces.leases import serialized_mutation
    write_file = serialized_mutation(registry, mutation_state_dir, write_file)
    apply_patch = serialized_mutation(registry, mutation_state_dir, apply_patch)
    mkdir = serialized_mutation(registry, mutation_state_dir, mkdir)
    move_path = serialized_mutation(registry, mutation_state_dir, move_path)
    trash_path = serialized_mutation(registry, mutation_state_dir, trash_path)

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
