"""Regression tests: task-level read-only delegation must be enforced by CLI flags."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.broker import AgentBroker
from agentporter.rest.schemas import DispatchAgentRequest
from agentporter.tools.agents import create_agent_tools


@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    exe = tmp_path / "fake-codex"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    jobs = Mock()
    jobs.start_confined_agent_job.return_value = "job-test"
    gateway = AgentBroker(SimpleNamespace(get=lambda _: ws), jobs)
    adapter = gateway.adapters["jax"]
    adapter.executable_override = str(exe)
    monkeypatch.setattr(adapter, "detect", lambda: {
        "is_installed": True,
        "configured_model": "gpt-6.1-sol",
        "reasoning_effort": "high",
        "provider": "OpenAI",
    })
    return gateway, ws, jobs


def test_default_on_writable_workspace_is_read_only(broker):
    gateway, _, jobs = broker
    result = gateway.dispatch_agent("jax", "inspect only", "test")
    cmd = jobs.start_confined_agent_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert "Authorization: READ-ONLY" in cmd[-1]
    assert "Workspace edits: NOT allowed (read-only)" in cmd[-1]
    assert "MAY MODIFY FILES WITHIN SCOPE" not in cmd[-1]
    assert result["read_only"] is True
    assert jobs.start_confined_agent_job.call_args.kwargs["policy"].workspace_write is False
    assert result["git_clean_at_dispatch"] is None  # No host-user Git subprocess.
    assert jobs.start_confined_agent_job.call_args.kwargs["env"] is not None
    assert jobs.start_confined_agent_job.call_args.kwargs["cmd"][1:4] == ["-I", "-m", "agentporter.agents.isolated_codex"]


def test_explicit_edit_opt_in_is_writable(broker):
    gateway, _, jobs = broker
    result = gateway.dispatch_agent("jax", "authorized scoped edit", "test", read_only=False)
    cmd = jobs.start_confined_agent_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "workspace-write"
    assert "Authorization: MAY MODIFY FILES WITHIN SCOPE" in cmd[-1]
    assert result["read_only"] is False
    assert jobs.start_confined_agent_job.call_args.kwargs["policy"].workspace_write is True


@pytest.mark.parametrize("flag", ["allow_commit", "allow_push"])
def test_read_only_rejects_commit_or_push_override(broker, flag):
    gateway, _, jobs = broker
    with pytest.raises(PermissionError, match="read-only dispatch|push is disabled"):
        gateway.dispatch_agent("jax", "inspect only", "test", **{flag: True})
    jobs.start_confined_agent_job.assert_not_called()


def test_writable_workspace_rejects_unsupported_read_only_adapter(broker, monkeypatch):
    gateway, _, jobs = broker
    monkeypatch.setattr(gateway.adapters["agy"], "detect", lambda: {"is_installed": True})
    with pytest.raises(PermissionError, match="cannot enforce read-only"):
        gateway.dispatch_agent("agy", "read only", "test")
    jobs.start_confined_agent_job.assert_not_called()


def test_read_only_workspace_cannot_be_overridden(broker):
    gateway, workspace, jobs = broker
    workspace.writable = False
    result = gateway.dispatch_agent("jax", "test", "test", read_only=False)
    cmd = jobs.start_confined_agent_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert result["read_only"] is True
    assert jobs.start_confined_agent_job.call_args.kwargs["policy"].workspace_write is False
    assert result["git_clean_at_dispatch"] is None  # No host-user Git subprocess.


def test_mcp_tool_wrapper_defaults_read_only():
    gateway = Mock()
    gateway.list_agents.return_value = [
        {"agent": "jax", "worker_cli": "codex", "available": True}
    ]
    gateway.dispatch_agent.return_value = {"job_id": "job-test"}
    _, dispatch = create_agent_tools(gateway)
    dispatch(agent="jax", task="inspection", workspace_id="test")
    assert gateway.dispatch_agent.call_args.kwargs["read_only"] is True
    dispatch(agent="jax", task="edit", workspace_id="test", read_only=False)
    assert gateway.dispatch_agent.call_args.kwargs["read_only"] is False


def test_rest_request_defaults_read_only():
    default = DispatchAgentRequest(agent="jax", task="inspection")
    assert default.read_only is True
    opted_in = DispatchAgentRequest(agent="jax", task="edit", read_only=False)
    assert opted_in.read_only is False


def test_private_argie_identity_remains_configurable(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    (Path(tmp_path) / "agents.yaml").write_text(
        "agents:\n  argie:\n    runtime: claude\n    alias: Existing Argie\n"
    )
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock())
    adapters, identities = gateway._configured_workers()
    assert adapters["argie"] is gateway.adapters["claude"]
    assert identities["argie"][0] == "claude"
    # Default compatibility means an existing private alias cannot be
    # overwritten by an implicit built-in Antigravity alias.


def test_missing_private_argie_uses_builtin_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock())
    adapters, identities = gateway._configured_workers()
    assert "agy" in adapters
    assert "argie" in adapters
    assert adapters["argie"].name == "agy"
    assert "argie" not in identities


def test_legacy_named_workers_remain_compatible_with_new_builtins(tmp_path, monkeypatch):
    # Asgard configured Wei/Prof before they became built-in adapters. The
    # explicit trusted aliases must win so account/model routing is preserved.
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path / "host-should-not-win"))
    config_dir = tmp_path / "selected"
    config_dir.mkdir()
    (config_dir / "agents.yaml").write_text(
        "agents:\n"
        "  wei:\n    runtime: opencode\n    alias: Wei Go\n"
        "  prof:\n    runtime: codex\n    alias: Prof Legacy\n"
        "  argie:\n    runtime: agy\n    alias: Argie\n"
    )
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock(), config_dir=config_dir)
    adapters, identities = gateway._configured_workers()
    assert adapters["wei"] is gateway.adapters["wei"]
    assert identities["wei"][0] == "opencode"
    assert identities["wei"][1] == "Wei Go"
    assert adapters["prof"] is gateway.adapters["prof"]
    assert adapters["argie"] is gateway.adapters["agy"]
    assert gateway.adapters["wei"] is not gateway.adapters["opencode"]
    assert gateway.list_agents()  # Live identity discovery must not abort.


def test_other_builtin_redirects_still_fail_closed(tmp_path):
    (tmp_path / "agents.yaml").write_text(
        "agents:\n  codex:\n    runtime: claude\n"
    )
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock(), config_dir=tmp_path)
    with pytest.raises(ValueError, match="cannot redirect"):
        gateway._configured_workers()


def test_explicit_configuration_shields_broker_from_invalid_host_config(tmp_path, monkeypatch):
    host = tmp_path / "host"
    host.mkdir()
    (host / "agents.yaml").write_text("agents:\n  jax:\n    runtime: claude\n")
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(host))
    selected = tmp_path / "selected"
    selected.mkdir()
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock(), config_dir=selected)
    adapters, identities = gateway._configured_workers()
    assert "jax" in adapters
    assert identities == {}


def test_legacy_wei_alias_cannot_bypass_free_model_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "agents.yaml").write_text(
        "agents:\n  wei:\n    runtime: opencode\n    alias: Legacy Wei Go\n"
    )
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    jobs = Mock()
    gateway = AgentBroker(SimpleNamespace(get=lambda _: ws), jobs)
    wei = gateway.adapters["wei"]
    monkeypatch.setattr(wei, "detect", lambda: {
        "is_installed": True, "configured_model": wei.default_model,
        "provider": "opencode", "reasoning_effort": "unknown", "cli_version": "fixture",
    })
    with pytest.raises(ValueError, match="free OpenCode models"):
        gateway.dispatch_agent(
            "wei", "do not execute", "test", read_only=False,
            model="opencode-go/glm-5.3-flash",
        )
    jobs.start_confined_agent_job.assert_not_called()
