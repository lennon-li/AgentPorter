"""Unit tests for config resolution."""

import os
from pathlib import Path
from agentporter.config import Config


def test_config_generates_api_key(tmp_path: Path):
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "st")
    assert cfg.api_key
    assert len(cfg.api_key) >= 32
    secrets_file = tmp_path / "cfg" / "secrets.env"
    assert secrets_file.exists()
    assert oct(secrets_file.stat().st_mode & 0o777) == "0o600"


def test_config_custom_workspaces(tmp_path: Path):
    ws_file = tmp_path / "cfg" / "workspaces.yaml"
    ws_file.parent.mkdir(parents=True, exist_ok=True)
    ws_file.write_text("workspaces:\n  demo:\n    path: /tmp/demo\n    writable: false\n")

    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "st")
    assert "demo" in cfg.workspaces
    assert cfg.workspaces["demo"]["writable"] is False
