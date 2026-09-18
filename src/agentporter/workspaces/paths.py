"""Path validation and traversal protection for workspaces."""

import os
import logging

logger = logging.getLogger("agentporter.workspaces.paths")

SENSITIVE_NAMES_LOWER = {
    ".git",
    ".ssh",
    ".env",
    "id_rsa",
    "id_ed25519",
    "secrets.env",
}


def _check_sensitive_components(path_str: str, original_ref: str) -> None:
    """Check every path component case-insensitively for sensitive names."""
    parts = path_str.replace("\\", "/").split("/")
    for p in parts:
        p_lower = p.lower()
        if (
            p_lower in SENSITIVE_NAMES_LOWER
            or p_lower.startswith(".env")
            or p_lower.endswith((".pem", ".key"))
        ):
            raise ValueError(f"Access to sensitive or internal path blocked: '{original_ref}'")


def validate_workspace_path(ws_root: str, rel_path: str, allow_root: bool = False) -> str:
    """Validate that rel_path is strictly project-relative and resolves within ws_root."""
    real_root = os.path.realpath(ws_root)

    if not rel_path or rel_path == ".":
        if allow_root:
            return real_root
        raise ValueError("Root directory not allowed for this operation")

    # Explicitly reject absolute paths
    if os.path.isabs(rel_path) or rel_path.startswith("/"):
        raise ValueError(f"Absolute paths not permitted: '{rel_path}'. Paths must be project-relative.")

    clean_rel = os.path.normpath(rel_path)
    if clean_rel.startswith("..") or clean_rel == "..":
        raise ValueError(f"Path traversal detected: '{rel_path}'")

    # Check unresolved input path components
    _check_sensitive_components(clean_rel, rel_path)

    target = os.path.realpath(os.path.join(real_root, clean_rel))
    if not (target == real_root or target.startswith(real_root + os.sep)):
        raise ValueError(f"Path escape attempt blocked: '{rel_path}' -> '{target}'")

    # Check resolved real path relative to workspace root (protects against symlink bypass)
    resolved_rel = os.path.relpath(target, real_root)
    _check_sensitive_components(resolved_rel, rel_path)

    return target
