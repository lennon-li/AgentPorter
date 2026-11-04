"""Unit tests for path traversal prevention, symlink escapes, and sensitive path blocking."""

import os
import pytest
from pathlib import Path
from agentporter.workspaces.paths import validate_workspace_path


def test_valid_project_relative_paths(tmp_path: Path):
    target = validate_workspace_path(str(tmp_path), "src/main.py")
    assert target == str(tmp_path / "src" / "main.py")


def test_absolute_path_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="Absolute paths not permitted"):
        validate_workspace_path(str(tmp_path), "/etc/passwd")

    with pytest.raises(ValueError, match="Absolute paths not permitted"):
        validate_workspace_path(str(tmp_path), "/mnt/c/Windows")


def test_traversal_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="Path traversal detected|Path escape attempt blocked"):
        validate_workspace_path(str(tmp_path), "../secret.txt")

    with pytest.raises(ValueError, match="Path traversal detected|Path escape attempt blocked"):
        validate_workspace_path(str(tmp_path), "foo/../../secret.txt")


def test_sensitive_files_blocked(tmp_path: Path):
    for sensitive in [
        ".git/config", ".Git/config", ".ssh/id_rsa", ".SSH/id_rsa",
        ".env", ".ENV", ".env.local", "secrets.env", "SECRETS.ENV",
        "server.key", "cert.pem",
        ".bashrc", ".bash_profile", ".profile", ".zshrc", ".gnupg"
    ]:
        with pytest.raises(ValueError, match="sensitive or internal"):
            validate_workspace_path(str(tmp_path), sensitive)


def test_symlink_bypass_blocked(tmp_path: Path):
    # Create actual sensitive file
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=123")

    # Create symlink pointing to sensitive file
    symlink_file = tmp_path / "innocent_symlink.txt"
    os.symlink(env_file, symlink_file)

    with pytest.raises(ValueError, match="sensitive or internal"):
        validate_workspace_path(str(tmp_path), "innocent_symlink.txt")
