"""File and search operations scoped to workspaces."""

import os
import time
import shutil
import hashlib
import subprocess
import logging
from typing import Optional
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.bounded import read_regular, walk_files, capture_bounded
from agentporter.workspaces.shared_access import atomic_write

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
        """Read a bounded full file or line range and return SHA-256."""
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
            total_lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
            return {
                "path": path,
                "content": content,
                "sha256": full_sha256,
                "size_bytes": size,
                "total_lines": total_lines,
                "range": {"start_line": 1, "end_line": total_lines},
            }

        start = max(1, int(start_line or 1))
        end = int(end_line or (start + MAX_RANGE_LINES - 1))
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
        actual_end = min(end, total_lines)
        return {
            "path": path,
            "content": "".join(selected),
            "sha256": full_sha256,
            "size_bytes": size,
            "total_lines": total_lines,
            "range": {"start_line": start, "end_line": actual_end},
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
        full_path = validate_workspace_path(ws.path, path)
        os.makedirs(full_path, exist_ok=True)
        return {"path": path, "status": "created"}

    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        full_src = validate_workspace_path(ws.path, source)
        full_dst = validate_workspace_path(ws.path, destination)
        if not os.path.exists(full_src):
            raise FileNotFoundError(f"Source not found: '{source}'")
        os.makedirs(os.path.dirname(full_dst), exist_ok=True)
        shutil.move(full_src, full_dst)
        return {"source": source, "destination": destination, "status": "moved"}

    def trash_path(workspace_id: str, path: str) -> dict:
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")
        full_path = validate_workspace_path(ws.path, path)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Target not found: '{path}'")

        trash_dir = os.path.join(ws.path, ".trash")
        os.makedirs(trash_dir, exist_ok=True)
        base = os.path.basename(full_path.rstrip(os.sep))
        timestamp = int(time.time())
        dest = os.path.join(trash_dir, f"{timestamp}_{base}")
        shutil.move(full_path, dest)
        return {
            "path": path,
            "status": "trashed",
            "trash_location": os.path.relpath(dest, ws.path),
        }

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
