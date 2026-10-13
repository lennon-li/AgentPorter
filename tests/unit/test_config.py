"""Unit tests for config resolution and local permission hardening."""

import os
import pytest
from pathlib import Path
from agentporter.config import Config


def test_config_generates_api_key_and_private_paths(tmp_path: Path):
    cfg = Config(
        config_dir=tmp_path / "cfg",
        state_dir=tmp_path / "st",
        cache_dir=tmp_path / "cache",
    )
    assert cfg.api_key
    assert len(cfg.api_key) >= 32
    secrets_file = tmp_path / "cfg" / "secrets.env"
    assert secrets_file.exists()
    assert oct(secrets_file.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "cfg").stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "st").stat().st_mode & 0o777) == "0o700"
    assert cfg.security.legacy_header_name == ""
    assert not any("trycloudflare" in host for host in cfg.security.allowed_hosts)


def test_config_custom_workspaces(tmp_path: Path):
    ws_file = tmp_path / "cfg" / "workspaces.yaml"
    ws_file.parent.mkdir(parents=True, exist_ok=True)
    ws_file.write_text(
        "workspaces:\n"
        "  demo:\n"
        "    path: /tmp/demo\n"
        "    writable: false\n"
        "    allow_agent_dispatch: false\n"
    )
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "st")
    assert "demo" in cfg.workspaces
    assert cfg.workspaces["demo"]["writable"] is False
    assert cfg.workspaces["demo"]["allow_agent_dispatch"] is False


def test_networked_sandbox_config_fails_closed(tmp_path: Path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text("sandbox:\n  network: true\n")
    with pytest.raises(ValueError, match="network access is not supported"):
        Config(config_dir=cfg_dir, state_dir=tmp_path / "st")


def test_private_scinet_endpoint_is_loaded_from_config(tmp_path: Path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text(
        "scinet:\n"
        "  host: approved.example\n"
        "  user: yeli\n"
        "  control_socket: ~/.ssh/cm-approved\n"
        "  machine: asgard\n"
    )
    cfg = Config(config_dir=cfg_dir, state_dir=tmp_path / "st")
    assert cfg.scinet.host == "approved.example"
    assert cfg.scinet.user == "yeli"
    assert cfg.scinet.control_socket == "~/.ssh/cm-approved"
    assert cfg.scinet.machine == "asgard"


def test_private_scinet_training_settings_are_loaded(tmp_path: Path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text(
        "scinet:\n"
        "  training_remote_root: /scratch/project/cranary-laya\n"
        "  training_account: def-cranary\n"
        "  training_partition: gpu\n"
        "  training_python: /scratch/project/laya/bin/python\n"
        "  training_cpus_per_task: 8\n"
        "  training_max_stage_bytes: 123456\n",
        encoding="utf-8",
    )
    cfg = Config(config_dir=cfg_dir, state_dir=tmp_path / "st", cache_dir=tmp_path / "cache")
    assert cfg.scinet.training_remote_root == "/scratch/project/cranary-laya"
    assert cfg.scinet.training_account == "def-cranary"
    assert cfg.scinet.training_partition == "gpu"
    assert cfg.scinet.training_python == "/scratch/project/laya/bin/python"
    assert cfg.scinet.training_cpus_per_task == 8
    assert cfg.scinet.training_max_stage_bytes == 123456
