"""File and search operations scoped to workspaces."""

import os
import re
import time
import shutil
import hashlib
import tempfile
import subprocess
import logging
from typing import Optional
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.workspaces.paths import validate_workspace_path

logger = logging.getLogger("agentporter.tools.files")

MAX_FULL_READ_BYTES = 1024 * 1024
MAX_WRITE_BYTES = 5 * 1024 * 1024
MAX_PATCH_BYTES = 2 * 1024 * 1024
MAX_RANGE_LINES = 5000
MAX_SEARCH_RESULTS = 200

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
    def list_files(workspace_id: str, path: str = "", depth: Optional[int] = None) -> list[str]:
        """List non-hidden files in the workspace."""
        ws = registry.get(workspace_id)
        root = validate_workspace_path(ws.path, path, allow_root=True)

        rel_files = []
        root_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and d not in ["__pycache__", "node_modules", "venv", ".venv"]
            ]

            cur_depth = dirpath.count(os.sep) - root_depth
            if depth is not None and cur_depth >= max(0, depth):
                dirnames[:] = []

            for fn in filenames:
                if fn.startswith("."):
                    continue
                full_p = os.path.join(dirpath, fn)
                rel_p = os.path.relpath(full_p, ws.path)
                try:
                    validate_workspace_path(ws.path, rel_p)
                except ValueError:
                    continue
                rel_files.append(rel_p)

        rel_files.sort()
        return rel_files

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
        ]
        for excluded in RG_SENSITIVE_EXCLUDES:
            cmd.extend(["--glob", excluded])
        if glob and glob != "*":
            cmd.extend(["--glob", glob])
        cmd.extend(["--", query, ws_root])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode not in (0, 1):
                raise RuntimeError(res.stderr.strip() or f"ripgrep failed with exit {res.returncode}")

            results = []
            for line in res.stdout.splitlines():
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

<<<<<<< HEAD
        size = os.path.getsize(full_path)
        digest = hashlib.sha256()
=======
        file_size = os.path.getsize(full_path)
        max_size = 10 * 1024 * 1024  # 10 MB ceiling
        if file_size > max_size:
            raise ValueError(f"File '{path}' exceeds maximum readable size of 10 MB ({file_size} bytes)")

>>>>>>> origin/main
        with open(full_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        full_sha256 = digest.hexdigest()

        if start_line is None and end_line is None:
            if size > MAX_FULL_READ_BYTES:
                raise ValueError(
                    f"File is {size} bytes; full reads are limited to {MAX_FULL_READ_BYTES}. "
                    "Use start_line/end_line."
                )
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(MAX_FULL_READ_BYTES + 1)
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
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            for number, line in enumerate(f, start=1):
                total_lines = number
                if start <= number <= end:
                    selected.append(line)
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

        full_path = validate_workspace_path(ws.path, path)
        parent_dir = os.path.dirname(full_path)
        os.makedirs(parent_dir, exist_ok=True)

        if os.path.exists(full_path):
            with open(full_path, "rb") as f:
                existing_sha256 = hashlib.sha256(f.read()).hexdigest()
            if expected_sha256 and existing_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f"Stale file protection: current sha256 ({existing_sha256}) "
                    f"does not match expected ({expected_sha256})"
                )

        with tempfile.NamedTemporaryFile("wb", dir=parent_dir, delete=False) as tmp:
            tmp.write(content_bytes)
            tmp_name = tmp.name
        os.replace(tmp_name, full_path)

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

        has_ab_prefix = False
        for line in patch.splitlines():
            if line.startswith(("--- ", "+++ ")):
                target_token = re.split(r'[\t\s]{2,}|\t', line[4:].strip())[0].strip()
                if target_token.startswith(("a/", "b/")):
                    clean_target = target_token[2:]
                    has_ab_prefix = True
                else:
                    clean_target = target_token
                if clean_target and clean_target != "/dev/null":
                    validate_workspace_path(ws.path, clean_target)

        patch_flag = "-p1" if has_ab_prefix else "-p0"
        proc = subprocess.run(
            ["patch", patch_flag],
            input=patch,
            cwd=ws.path,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            return {
                "status": "failed",
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:100000],
                "stderr": proc.stderr[:100000],
            }
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
