"""Wei must use its private credential with the hardened OpenCode launch profile."""

import json

import pytest

from agentporter.agents.adapters.opencode import WeiAdapter
from agentporter.agents.broker import AgentBroker
from agentporter.agents.policy import ExecutionPolicy


def _write_private_key(tmp_path, monkeypatch, value="test-wei-key"):
    monkeypatch.setenv("HOME", str(tmp_path))
    directory = tmp_path / ".config" / "opencode"
    directory.mkdir(parents=True)
    key = directory / "wei-key"
    key.write_text(value)
    key.chmod(0o600)
    return key


def test_wei_uses_free_default_and_private_environment(tmp_path, monkeypatch):
    _write_private_key(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "agentporter.agents.adapters.opencode.subprocess.run",
        lambda *args, **kwargs: type("Result", (), {"stdout": "1.19.0"})(),
    )
    adapter = WeiAdapter(executable_override="/bin/echo")
    argv = adapter.build_argv("/workspace", "task")
    env = adapter.runtime_env("/workspace", policy=ExecutionPolicy())
    assert argv[-3:] == ["-m", "opencode/glm-5.3-flash-free", "task"]
    assert "test-wei-key" not in argv
    profile = json.loads(env["OPENCODE_CONFIG_CONTENT"])
    assert profile["provider"]["opencode"]["options"]["apiKey"] == "test-wei-key"
    assert profile["agent"]["dispatch"]["permission"]["edit"] == "allow"


def test_wei_rejects_nonfree_and_insecure_credential(tmp_path, monkeypatch):
    key = _write_private_key(tmp_path, monkeypatch)
    adapter = WeiAdapter(executable_override="/bin/echo")
    with pytest.raises(ValueError, match="free OpenCode models"):
        adapter.build_argv("/workspace", "task", model="opencode-go/glm-5.3-flash")
    key.chmod(0o644)
    assert adapter.detect()["credential_ready"] is False


def test_wei_reports_its_opencode_runtime(monkeypatch):
    adapter = WeiAdapter(executable_override="/bin/echo")
    monkeypatch.setattr(adapter, "detect", lambda: {
        "is_installed": True,
        "provider": "opencode",
        "configured_model": adapter.default_model,
        "cli_version": "1.19.0",
    })
    broker = AgentBroker(None, None)
    broker.adapters = {"wei": adapter}
    assert broker.list_agents()[0]["worker_cli"] == "opencode"
