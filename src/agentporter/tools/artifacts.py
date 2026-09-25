"""Artifact discovery and bounded retrieval tools."""

import os
import base64
import mimetypes
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.workspaces.paths import validate_workspace_path

IMAGE_EXTENSIONS = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}
MAX_TEXT_ARTIFACT_BYTES = 200_000
MAX_IMAGE_ARTIFACT_BYTES = 5 * 1024 * 1024
MAX_ARTIFACT_LIST = 1000


def create_artifact_tools(registry: WorkspaceRegistry):
    def _workspace(workspace_id: str):
        ws = registry.get(workspace_id)
        if not ws.allow_artifacts:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow artifact access")
        return ws

    def list_artifacts(workspace_id: str, path: str = "artifacts") -> list[dict]:
        ws = _workspace(workspace_id)
        try:
            artifact_dir = validate_workspace_path(ws.path, path)
        except Exception:
            return []
        if not os.path.exists(artifact_dir):
            return []

        results = []
        for root, _, files in os.walk(artifact_dir):
            for fn in files:
                full_p = os.path.join(root, fn)
                rel_p = os.path.relpath(full_p, ws.path)
                try:
                    validate_workspace_path(ws.path, rel_p)
                except ValueError:
                    continue
                size = os.path.getsize(full_p)
                ext = os.path.splitext(fn)[1].lower()
                results.append({
                    "path": rel_p,
                    "name": fn,
                    "size_bytes": size,
                    "type": "image" if ext in IMAGE_EXTENSIONS else "text",
                })
                if len(results) >= MAX_ARTIFACT_LIST:
                    break
            if len(results) >= MAX_ARTIFACT_LIST:
                break
        results.sort(key=lambda x: x["path"])
        return results

    def read_artifact(workspace_id: str, path: str) -> dict:
        ws = _workspace(workspace_id)
        full_path = validate_workspace_path(ws.path, path)
        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"Artifact not found: '{path}'")

        size = os.path.getsize(full_path)
        ext = os.path.splitext(full_path)[1].lower()

        if ext in IMAGE_EXTENSIONS:
            if size > MAX_IMAGE_ARTIFACT_BYTES:
                raise ValueError(
                    f"Image artifact is {size} bytes; limit is {MAX_IMAGE_ARTIFACT_BYTES}"
                )
            mime = IMAGE_EXTENSIONS[ext]
            with open(full_path, "rb") as f:
                data = f.read(MAX_IMAGE_ARTIFACT_BYTES + 1)
            return {
                "path": path,
                "type": "image",
                "mime_type": mime,
                "size_bytes": size,
                "base64_data": base64.b64encode(data).decode("ascii"),
            }

        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(MAX_TEXT_ARTIFACT_BYTES)
        return {
            "path": path,
            "type": "text",
            "mime_type": mimetypes.guess_type(full_path)[0] or "text/plain",
            "size_bytes": size,
            "content": content,
            "truncated": size > MAX_TEXT_ARTIFACT_BYTES,
        }

    return list_artifacts, read_artifact
