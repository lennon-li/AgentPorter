"""Opt-in search must preserve worker identity, permissions, and MCP isolation."""

import json
from pathlib import Path
from types import SimpleNamespace
import tomllib
from unittest.mock import Mock

import pytest

from agentporter.agents import isolated_codex as guard
from agentporter.agents.adapters.copilot import CopilotAdapter, PhilAdapter
from agentporter.agents.adapters.opencode import WeiAdapter
from agentporter.agents.broker import AgentBroker
from agentporter.agents.parallel_search import PARALLEL_MCP_NAME, PARALLEL_MCP_URL


def search_roster():
    return [{"name": PARALLEL_MCP_NAME, "enabled": True,
             "transport": {"type": "streamable_http", "url": PARALLEL_MCP_URL}}]


@pytest.mark.parametrize("enabled", [False, True])
def test_codex_profile_adds_only_search_and_preserves_provider(tmp_path, monkeypatch, enabled):
    source = tmp_path / "profile"
    source.mkdir()
    original = ('model="identity-model"\nmodel_provider="private"\n'
                '[mcp_servers.unrelated]\ncommand="unsafe"\n'
                '[model_providers.private]\nbase_url="https://example.test/v1"\n')
    (source / "config.toml").write_text(original)
    calls = []

    def launch(argv, **kwargs):
        home = Path(kwargs["env"]["CODEX_HOME"])
        config = tomllib.loads((home / "config.toml").read_text())
        assert config["model"] == "identity-model"
        assert config["model_providers"]["private"]["base_url"] == "https://example.test/v1"
        assert "mcp_servers" not in config["model_providers"]["private"]
        assert set(config.get("mcp_servers", {})) == ({PARALLEL_MCP_NAME} if enabled else set())
        if enabled:
            assert config["mcp_servers"][PARALLEL_MCP_NAME] == {
                "url": PARALLEL_MCP_URL, "enabled": True,
                "enabled_tools": ["web_search", "web_fetch"],
            }
        assert "sandbox_workspace_write.network_access=false" in argv
        calls.append(home)
        return SimpleNamespace(stdout=json.dumps(search_roster() if enabled else []), returncode=0)

    monkeypatch.setattr(guard.subprocess, "run", launch)
    assert guard.run(str(source), str(tmp_path), ["/bin/echo", "exec", "task"],
                     parallel_search_enabled=enabled) == 0
    assert len(calls) == 2
    assert not calls[0].exists()
    assert (source / "config.toml").read_text() == original


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "disabled", "url", "transport", "malformed"])
def test_codex_refuses_unexpected_search_roster(tmp_path, monkeypatch, change):
    roster = search_roster()
    if change == "missing":
        roster = []
    elif change == "extra":
        roster.append({"name": "danger", "enabled": True})
    elif change == "duplicate":
        roster += search_roster()
    elif change == "disabled":
        roster[0]["enabled"] = False
    elif change == "url":
        roster[0]["transport"]["url"] = "https://example.invalid/mcp"
    elif change == "transport":
        roster[0]["transport"]["type"] = "stdio"
    else:
        roster = [None]
    monkeypatch.setattr(guard.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(roster)))
    with pytest.raises(RuntimeError, match="MCP"):
        guard._validate_mcp_roster("/bin/echo", tmp_path, {}, parallel_search_enabled=True)


@pytest.mark.parametrize("enabled", [False, True])
def test_phil_additive_config_keeps_identity_and_denials(tmp_path, enabled):
    adapter = PhilAdapter(executable_override="/bin/echo", copilot_home=str(tmp_path))
    argv = adapter.build_argv(str(tmp_path), "task", writable=False, parallel_search_enabled=enabled)
    assert argv[:3] == ["env", f"COPILOT_HOME={tmp_path}", f"PHIL_COPILOT_HOME={tmp_path}"]
    assert "--deny-tool=write" in argv
    assert "--deny-tool=shell(git push)" in argv
    assert "--model" not in argv
    assert ("--additional-mcp-config" in argv) is enabled
    if enabled:
        config = json.loads(Path(argv[argv.index("--additional-mcp-config") + 1][1:]).read_text())
        assert config == {"mcpServers": {PARALLEL_MCP_NAME: {
            "type": "http", "url": PARALLEL_MCP_URL, "tools": ["web_search", "web_fetch"],
        }}}


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("version", ["1.19.0", "2.0.31"])
def test_wei_search_keeps_credentials_out_of_argv_and_retains_permissions(tmp_path, monkeypatch, enabled, version):
    monkeypatch.setenv("HOME", str(tmp_path))
    key = tmp_path / ".config/opencode/wei-key"
    key.parent.mkdir(parents=True)
    key.write_text("fixture-wei-key")
    key.chmod(0o600)
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run",
                        lambda *a, **k: SimpleNamespace(stdout=version))
    adapter = WeiAdapter(executable_override="/bin/echo")
    argv = adapter.build_argv(str(tmp_path), "task")
    assert argv[-3:] == ["-m", adapter.default_model, "task"]
    assert "fixture-wei-key" not in str(argv)
    env = adapter.runtime_env(str(tmp_path), parallel_search_enabled=enabled)
    config = json.loads(env["OPENCODE_CONFIG_CONTENT"])
    assert config["provider"]["opencode"]["options"]["apiKey"] == "fixture-wei-key"
    assert "git push" in json.dumps(config)
    assert (PARALLEL_MCP_NAME in config.get("mcp", {})) is enabled
    if enabled:
        assert config["mcp"][PARALLEL_MCP_NAME] == {
            "type": "remote", "url": PARALLEL_MCP_URL, "enabled": True, "oauth": False,
        }
        assert config["tools"] == {"parallel-search_*": False,
                                   "parallel-search_web_search": True, "parallel-search_web_fetch": True}


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("name", ["jax", "liz", "prof", "phil", "wei", "codex", "copilot", "opencode"])
def test_broker_gates_search_by_setting_and_identity(tmp_path, monkeypatch, name, enabled):
    jobs = Mock()
    jobs.start_confined_agent_job.return_value = "search-job"
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    broker = AgentBroker(SimpleNamespace(get=lambda _: ws), jobs, parallel_search_enabled=enabled)
    if name == "copilot":
        broker.register_adapter(CopilotAdapter())
    adapter = broker.adapters[name]
    adapter.executable_override = "/bin/echo"
    if hasattr(adapter, "codex_home"):
        adapter.codex_home = str(tmp_path)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.setattr(adapter, "detect", lambda: {
        "is_installed": True, "configured_model": "unknown", "provider": adapter.provider,
    })
    monkeypatch.setattr("agentporter.agents.adapters.opencode.subprocess.run",
                        lambda *a, **k: SimpleNamespace(stdout="2.0.31"))
    if name == "wei":
        monkeypatch.setattr(adapter, "_read_key", lambda: "fixture-wei-key")
    result = broker.dispatch_agent(name, "bounded task", "workspace", read_only=False)
    assert result["job_id"] == "search-job"
    launch = jobs.start_confined_agent_job.call_args.kwargs
    expected = enabled and name in {"jax", "liz", "prof", "phil", "wei"}
    if name in {"jax", "liz", "prof", "codex"}:
        assert ("--parallel-search" in launch["cmd"]) is expected
        assert "sandbox_workspace_write.network_access=false" in launch["cmd"]
    elif name in {"phil", "copilot"}:
        assert ("--additional-mcp-config" in launch["cmd"]) is expected
    else:
        config = json.loads(launch["env"]["OPENCODE_CONFIG_CONTENT"])
        assert (PARALLEL_MCP_NAME in config.get("mcp", {})) is expected
