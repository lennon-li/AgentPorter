"""File and search operations scoped to workspaces."""

import os
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


def create_file_tools(registry: WorkspaceRegistry):
    def list_files(workspace_id: str, path: str = "", depth: Optional[int] = None) -> list[str]:
        """List files in the workspace, skipping .git and internal cache directories."""
        ws = registry.get(workspace_id)
        root = validate_workspace_path(ws.path, path, allow_root=True)

        rel_files = []
        root_depth = root.rstrip(os.sep).count(os.sep)

        for dirpath, dirnames, filenames in os.walk(root):
            # Skip hidden and cache directories
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ["__pycache__", "node_modules", "venv", ".venv"]]

            cur_depth = dirpath.count(os.sep) - root_depth
            if depth is not None and cur_depth >= depth:
                dirnames[:] = []

            for fn in filenames:
                if fn.startswith("."):
                    continue
                full_p = os.path.join(dirpath, fn)
                rel_files.append(os.path.relpath(full_p, ws.path))

        rel_files.sort()
        return rel_files

    def search_text(workspace_id: str, query: str, glob: str = "*", max_results: int = 50) -> list[dict]:
        """Search for text across workspace files using ripgrep."""
        ws = registry.get(workspace_id)
        ws_root = ws.path

        cmd = ["rg", "--line-number", "--color", "never", "--max-count", str(max_results)]
        if glob and glob != "*":
            cmd.extend(["--glob", glob])
        cmd.extend(["--", query, ws_root])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = res.stdout.splitlines()
            results = []
            for line in lines[:max_results]:
                parts = line.split(":", 2)
                if len(parts) == 3:
                    filepath, line_no, text = parts
                    rel_path = os.path.relpath(filepath, ws_root)
                    results.append({
                        "path": rel_path,
                        "line": int(line_no) if line_no.isdigit() else line_no,
                        "text": text
                    })
            return results
        except Exception as e:
            logger.error("search_text error: %s", e)
            return []

    def read_file(workspace_id: str, path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> dict:
        """Read full or ranged content of a file, returning SHA-256 and total lines."""
        ws = registry.get(workspace_id)
        full_path = validate_workspace_path(ws.path, path)
        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"File not found: '{path}'")

        with open(full_path, "rb") as f:
            data = f.read()

        full_sha256 = hashlib.sha256(data).hexdigest()
        text = data.decode("utf-8", errors="replace")
        all_lines = text.splitlines(keepends=True)
        total_lines = len(all_lines)

        if start_line is not None or end_line is not None:
            s = max(1, start_line or 1)
            e = min(total_lines, end_line or total_lines)
            if s > total_lines or s > e:
                content = ""
            else:
                content = "".join(all_lines[s-1:e])
            returned_range = {"start_line": s, "end_line": e}
        else:
            content = text
            returned_range = {"start_line": 1, "end_line": total_lines}

        return {
            "path": path,
            "content": content,
            "sha256": full_sha256,
            "total_lines": total_lines,
            "range": returned_range
        }

    def write_file(workspace_id: str, path: str, content: str, expected_sha256: Optional[str] = None) -> dict:
        """Atomically write content to a file with stale-file protection."""
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")

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

        content_bytes = content.encode("utf-8")
        with tempfile.NamedTemporaryFile("wb", dir=parent_dir, delete=False) as tmp:
            tmp.write(content_bytes)
            tmp_name = tmp.name

        os.replace(tmp_name, full_path)
        new_sha256 = hashlib.sha256(content_bytes).hexdigest()

        return {
            "path": path,
            "status": "written",
            "bytes": len(content_bytes),
            "sha256": new_sha256
        }

    def apply_patch(workspace_id: str, patch: str) -> dict:
        """Apply a unified diff patch to the workspace with target path validation."""
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")

        # Validate all file targets in the patch before running patch binary
        has_ab_prefix = False
        for line in patch.splitlines():
            if line.startswith(("--- ", "+++ ")):
                target_token = line[4:].strip().split("\t", 1)[0]
                if target_token.startswith(("a/", "b/")):
                    clean_target = target_token[2:]
                    has_ab_prefix = True
                else:
                    clean_target = target_token
                if clean_target and clean_target != "/dev/null":
                    # Raises ValueError if target is invalid, traverses, or is sensitive
                    validate_workspace_path(ws.path, clean_target)

        patch_flag = "-p1" if has_ab_prefix else "-p0"
        try:
            proc = subprocess.run(
                ["patch", patch_flag],
                input=patch,
                cwd=ws.path,
                capture_output=True,
                text=True,
                timeout=15
            )
            if proc.returncode != 0:
                return {
                    "status": "failed",
                    "exit_code": proc.returncode,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr
                }
            return {
                "status": "applied",
                "exit_code": 0,
                "stdout": proc.stdout
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def mkdir(workspace_id: str, path: str) -> dict:
        """Create a directory in the workspace."""
        ws = registry.get(workspace_id)
        if not ws.writable:
            raise PermissionError(f"Workspace '{workspace_id}' is configured read-only")

        full_path = validate_workspace_path(ws.path, path)
        os.makedirs(full_path, exist_ok=True)
        return {"path": path, "status": "created"}

    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        """Move or rename a file or directory within the workspace."""
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
        """Move a file to the recoverable .trash folder rather than permanently deleting it."""
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
            "trash_location": os.path.relpath(dest, ws.path)
        }

    return (
        list_files, search_text, read_file, write_file,
        apply_patch, mkdir, move_path, trash_path
    )
