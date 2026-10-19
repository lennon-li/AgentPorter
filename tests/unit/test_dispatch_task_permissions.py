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
    jobs.start_raw_job.return_value = "job-test"
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
    cmd = jobs.start_raw_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert "Authorization: READ-ONLY" in cmd[-1]
    assert "Workspace edits: NOT allowed (read-only)" in cmd[-1]
    assert "MAY MODIFY FILES WITHIN SCOPE" not in cmd[-1]
    assert result["read_only"] is True
    assert jobs.start_raw_job.call_args.kwargs["env"] is not None
    assert jobs.start_raw_job.call_args.kwargs["cmd"][1:4] == ["-I", "-m", "agentporter.agents.isolated_codex"]


def test_explicit_edit_opt_in_is_writable(broker):
    gateway, _, jobs = broker
    result = gateway.dispatch_agent("jax", "authorized scoped edit", "test", read_only=False)
    cmd = jobs.start_raw_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "workspace-write"
    assert "Authorization: MAY MODIFY FILES WITHIN SCOPE" in cmd[-1]
    assert result["read_only"] is False


@pytest.mark.parametrize("flag", ["allow_commit", "allow_push"])
def test_read_only_rejects_commit_or_push_override(broker, flag):
    gateway, _, jobs = broker
    with pytest.raises(PermissionError, match="operator-verified approval"):
        gateway.dispatch_agent("jax", "inspect only", "test", **{flag: True})
    jobs.start_raw_job.assert_not_called()


def test_writable_workspace_rejects_unsupported_read_only_adapter(broker, monkeypatch):
    gateway, _, jobs = broker
    monkeypatch.setattr(gateway.adapters["agy"], "detect", lambda: {"is_installed": True})
    with pytest.raises(PermissionError, match="cannot enforce read-only"):
        gateway.dispatch_agent("agy", "read only", "test")
    jobs.start_raw_job.assert_not_called()


def test_read_only_workspace_cannot_be_overridden(broker):
    gateway, workspace, jobs = broker
    workspace.writable = False
    result = gateway.dispatch_agent("jax", "test", "test", read_only=False)
    cmd = jobs.start_raw_job.call_args.kwargs["cmd"]
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert result["read_only"] is True


def test_mcp_tool_wrapper_defaults_read_only():
    gateway = Mock()
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


def test_missing_private_argie_does_not_invent_an_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    gateway = AgentBroker(SimpleNamespace(get=lambda _: None), Mock())
    adapters, identities = gateway._configured_workers()
    assert "agy" in adapters
    assert "argie" not in adapters
    assert "argie" not in identities
