"""Per-launch edit permissions must not enable unrestricted CLI bypass modes."""

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.adapters.agy import AgyAdapter
from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter
from agentporter.agents.policy import ExecutionPolicy
from agentporter.agents.broker import AgentBroker


@pytest.fixture
def executable(tmp_path):
    path = tmp_path / "worker"
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return str(path)


def test_claude_explicit_edits_and_central_denials(executable):
    adapter = ClaudeAdapter(executable)
    argv = adapter.build_argv("/workspace", "task")
    assert argv[argv.index("--setting-sources") + 1] == "user"
    assert json.loads(argv[argv.index("--settings") + 1]) == {"permissions": {"ask": []}}
    allowed = argv[argv.index("--allowedTools") + 1:argv.index("--disallowedTools")]
    assert {"Read", "Edit", "Write", "Bash"} <= set(allowed)
    for command in ExecutionPolicy.for_workspace(writable=True).denied_commands():
        assert f"Bash({command}*)" in argv
    assert "--dangerously-skip-permissions" not in argv
    approved = adapter.build_argv("/workspace", "task", policy=ExecutionPolicy(git_commit=True))
    assert "Bash(git commit*)" not in approved
    assert "Bash(git push*)" in approved


@pytest.mark.parametrize("version", ["1.19.0", "2.0.0"])
def test_opencode_per_launch_profile(executable, monkeypatch, version):
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run",
                        lambda *a, **kw: SimpleNamespace(stdout=version))
    adapter = OpenCodeAdapter(executable)
    argv = adapter.build_argv("/workspace", "task", model="provider/model")
    assert argv[0] == executable
    assert argv[-3:] == ["-m", "provider/model", "task"]
    assert "--auto" not in argv
    config = json.loads(adapter.runtime_env("/workspace")["OPENCODE_CONFIG_CONTENT"])
    if version.startswith("1."):
        permissions = config["agent"]["dispatch"]["permission"]
        assert permissions["edit"] == "allow"
        assert permissions["external_directory"] == "deny"
        for command in ExecutionPolicy.for_workspace(writable=True).denied_commands():
            assert permissions["bash"][command + "*"] == "deny"
    else:
        assert "--standalone" in argv
        permissions = config["agents"]["dispatch"]["permissions"]
        assert {"action": "edit", "resource": "*", "effect": "allow"} in permissions
        assert {"action": "external_directory", "resource": "*", "effect": "deny"} in permissions
        for command in ExecutionPolicy.for_workspace(writable=True).denied_commands():
            assert {"action": "shell", "resource": command + "*", "effect": "deny"} in permissions


@pytest.mark.parametrize("version", ["", "3.0.0", "unexpected output"])
def test_opencode_unknown_version_fails_closed(executable, monkeypatch, version):
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run",
                        lambda *a, **kw: SimpleNamespace(stdout=version))
    with pytest.raises(RuntimeError, match="permission schema"):
        OpenCodeAdapter(executable).build_argv("/workspace", "task")


def test_opencode_version_timeout_fails_closed(executable, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 5)
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run", timeout)
    with pytest.raises(RuntimeError, match="permission schema"):
        OpenCodeAdapter(executable).build_argv("/workspace", "task")


@pytest.mark.parametrize("adapter", [ClaudeAdapter, OpenCodeAdapter])
def test_readonly_policy_overrides_writable_default(executable, adapter):
    with pytest.raises(RuntimeError, match="read-only"):
        adapter(executable).build_argv("/workspace", "task",
                                      policy=ExecutionPolicy(workspace_write=False))


def test_agy_edit_mode_retains_sandbox(executable):
    adapter = AgyAdapter(executable)
    assert adapter.build_argv("/workspace", "task") == [
        executable, "--mode", "accept-edits", "--sandbox", "-p", "task",
    ]
    with pytest.raises(RuntimeError, match="read-only"):
        adapter.build_argv("/workspace", "task", writable=False)


@pytest.mark.parametrize("runtime", ["codex", "jax", "liz", "phil", "claude", "opencode", "agy"])
def test_private_identity_inherits_runtime_write_controls(executable, tmp_path, monkeypatch, runtime):
    import yaml
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    # The distinct Codex identities cannot be redirected through generic aliases.
    name = runtime if runtime in {"jax", "liz"} else "local_writer"
    (tmp_path / "agents.yaml").write_text(yaml.safe_dump({
        "agents": {name: {"runtime": runtime, "alias": "Local Writer"}},
    }))
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    jobs = Mock()
    jobs.start_confined_agent_job.return_value = "test-job"
    broker = AgentBroker(registry, jobs)
    adapter = broker.adapters[runtime]
    adapter.executable_override = executable
    monkeypatch.setattr(adapter, "detect", lambda: {
        "is_installed": True, "configured_model": "unknown", "provider": "test",
    })
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run",
                        lambda *a, **kw: SimpleNamespace(stdout="1.19.0"))
    result = broker.dispatch_agent(name, "Write a scoped file", "test-workspace", read_only=False)
    assert result["job_id"] == "test-job"
    kwargs = jobs.start_confined_agent_job.call_args.kwargs
    assert kwargs["workspace_path"] == str(tmp_path)
    argv = kwargs["cmd"]
    assert any("MAY MODIFY FILES WITHIN SCOPE" in arg for arg in argv)
    if runtime in {"codex", "jax", "liz"}:
        assert "workspace-write" in argv
    elif runtime == "claude":
        assert "Write" in argv and "Bash(git push*)" in argv
    elif runtime == "opencode":
        config = json.loads(kwargs["env"]["OPENCODE_CONFIG_CONTENT"])
        assert config["agent"]["dispatch"]["permission"]["edit"] == "allow"
    elif runtime == "agy":
        assert "accept-edits" in argv and "--sandbox" in argv
    else:
        assert "--allow-all-tools" in argv
        assert "--deny-tool=write" not in argv


@pytest.mark.parametrize("runtime", ["claude", "opencode", "agy"])
def test_broker_refuses_unauthorized_workspace(runtime, monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=False)
    jobs = Mock()
    broker = AgentBroker(SimpleNamespace(get=lambda _: workspace), jobs)
    monkeypatch.setattr(broker.adapters[runtime], "detect", lambda: {"is_installed": True})
    with pytest.raises(PermissionError, match="does not allow"):
        broker.dispatch_agent(runtime, "Write a file", "test-workspace")
    jobs.start_confined_agent_job.assert_not_called()
