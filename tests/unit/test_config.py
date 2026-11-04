"""Unit tests for config resolution and local permission hardening."""

import os
import pytest
from pathlib import Path
from agentporter.config import Config


@pytest.mark.parametrize("setting, expected", [
    ("", False),
    ("parallel_search: {enabled: true}\n", True),
    ("parallel_search: {enabled: false}\n", False),
])
def test_parallel_search_opt_in_preserves_other_settings(tmp_path, setting, expected):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text(setting + "server: {port: 9876}\n")
    cfg = Config(config_dir=cfg_dir, state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")
    assert cfg.parallel_search.enabled is expected
    assert cfg.server.port == 9876


@pytest.mark.parametrize("setting", ["{enabled: 'true'}", "{enabled: 1}", "[]", "{api_key: secret}"])
def test_parallel_search_rejects_invalid_settings(tmp_path, setting):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text("parallel_search: " + setting + "\n")
    with pytest.raises(ValueError, match="parallel_search"):
        Config(config_dir=cfg_dir, state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")


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


@pytest.mark.parametrize('setting, expected', [('', False), ('workspace_transactions: true', True), ('workspace_transactions: false', False)])
def test_workspace_transactions_explicit_config(tmp_path, setting, expected):
    cfg_dir = tmp_path / 'cfg'
    cfg_dir.mkdir()
    (cfg_dir / 'config.yaml').write_text('sandbox: {' + setting + '}\n')
    cfg = Config(config_dir=cfg_dir, state_dir=tmp_path / 'state', cache_dir=tmp_path / 'cache')
    assert cfg.sandbox.workspace_transactions is expected


@pytest.mark.parametrize('setting', ["'true'", '1', '[]', '{}', 'null'])
def test_workspace_transactions_rejects_non_boolean(tmp_path, setting):
    cfg_dir = tmp_path / 'cfg'
    cfg_dir.mkdir()
    (cfg_dir / 'config.yaml').write_text('sandbox: {workspace_transactions: ' + setting + '}\n')
    with pytest.raises(ValueError, match='workspace_transactions'):
        Config(config_dir=cfg_dir, state_dir=tmp_path / 'state', cache_dir=tmp_path / 'cache')
