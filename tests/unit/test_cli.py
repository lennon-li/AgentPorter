"""Unit tests for the AgentPorter Click CLI."""

import sys
from pathlib import Path
from click.testing import CliRunner
import pytest

from agentporter import __version__
from agentporter.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "AgentPorter: Secure local MCP gateway" in result.output
    assert "doctor" in result.output
    assert "serve" in result.output
    assert "workspaces" in result.output
    assert "agents" in result.output


def test_cli_doctor(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--config-dir", str(config_dir)])
    assert result.exit_code == 0
    assert "AgentPorter Doctor Diagnostic" in result.output
    assert "Python Version:" in result.output
    assert "Config Directory:" in result.output
    assert "Security Invariants:" in result.output


def test_cli_init(tmp_path: Path):
    config_dir = tmp_path / "config"
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--config-dir", str(config_dir), "--workspace", str(tmp_path), "--name", "init-test"])
    assert result.exit_code == 0
    assert "AgentPorter initialized successfully:" in result.output
    assert (config_dir / "secrets.env").exists()
    assert (config_dir / "workspaces.yaml").exists()
    assert "init-test" in (config_dir / "workspaces.yaml").read_text()


def test_cli_workspaces(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    ws_yaml = config_dir / "workspaces.yaml"
    ws_yaml.write_text(
        "workspaces:\n"
        "  my-app:\n"
        f"    path: {tmp_path}\n"
        "    writable: true\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["workspaces", "--config-dir", str(config_dir)])
    assert result.exit_code == 0
    assert "Registered Workspaces (1):" in result.output
    assert "my-app" in result.output


def test_cli_workspaces_add_and_remove(tmp_path: Path):
    config_dir = tmp_path / "config"
    runner = CliRunner()

    # Add workspace
    add_res = runner.invoke(main, ["workspaces", "add", "dynamic-ws", str(tmp_path), "--config-dir", str(config_dir)])
    assert add_res.exit_code == 0
    assert "Added workspace 'dynamic-ws'" in add_res.output

    # List workspaces
    list_res = runner.invoke(main, ["workspaces", "list", "--config-dir", str(config_dir)])
    assert list_res.exit_code == 0
    assert "dynamic-ws" in list_res.output

    # Remove workspace
    rem_res = runner.invoke(main, ["workspaces", "remove", "dynamic-ws", "--config-dir", str(config_dir)])
    assert rem_res.exit_code == 0
    assert "Removed workspace 'dynamic-ws'" in rem_res.output

    # Verify removal
    list_after = runner.invoke(main, ["workspaces", "list", "--config-dir", str(config_dir)])
    assert "dynamic-ws" not in list_after.output



def test_cli_agents(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    runner = CliRunner()
    result = runner.invoke(main, ["agents", "--config-dir", str(config_dir)])
    assert result.exit_code == 0
    assert "Agent:" in result.output
    assert "Provider:" in result.output


def test_cli_serve_help():
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--help"])
    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output
    assert "--config-dir" in result.output


def test_cli_key_show(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    secrets_file = config_dir / "secrets.env"
    secrets_file.write_text("AGENTPORTER_API_KEY=test-secret-key-456\n")

    runner = CliRunner()
    result = runner.invoke(main, ["key", "show", "--config-dir", str(config_dir)])
    assert result.exit_code == 0
    assert "Primary Header: X-AgentPorter-Key" in result.output
    assert "API Key:        test-secret-key-456" in result.output


def test_cli_key_rotate(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    secrets_file = config_dir / "secrets.env"
    secrets_file.write_text("AGENTPORTER_API_KEY=old-key-123\n")

    runner = CliRunner()
    result = runner.invoke(main, ["key", "rotate", "--config-dir", str(config_dir), "--yes"])
    assert result.exit_code == 0
    assert "API key successfully rotated." in result.output
    assert "New Key:" in result.output

    # Verify new key is written to secrets.env
    content = secrets_file.read_text()
    assert "old-key-123" not in content
    assert "AGENTPORTER_API_KEY=" in content

