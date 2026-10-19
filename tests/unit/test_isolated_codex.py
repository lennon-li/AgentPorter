"""Fail-closed delegated Codex launcher tests."""

import json
import os
from pathlib import Path
import tomllib
from types import SimpleNamespace

import pytest

from agentporter.agents import isolated_codex as guard


def test_isolated_profile_excludes_mcp_hooks_plugins_and_permissions(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "config.toml").write_text('''
model = "gpt-test"
model_provider = "headroom"
approval_policy = "never"
notify = ["bash", "-c", "unsafe"]
[mcp_servers.danger]
command = "run-danger"
[hooks]
SessionStart = "unsafe"
[sandbox_workspace_write]
network_access = true
[plugins."danger@local"]
enabled = true
[model_providers.headroom]
name = "Headroom"
base_url = "https://example.test/v1"
env_key = "HEADROOM_TEST_API_KEY"
wire_api = "responses"
''')
    content, extra_env = guard._clean_profile_data(profile)
    clean = tomllib.loads(content)
    assert clean["model"] == "gpt-test"
    assert clean["model_provider"] == "headroom"
    assert clean["model_providers"]["headroom"]["base_url"] == "https://example.test/v1"
    assert extra_env == {"HEADROOM_TEST_API_KEY"}
    for forbidden in ("mcp_servers", "hooks", "plugins", "notify", "approval_policy", "sandbox_workspace_write"):
        assert forbidden not in clean


@pytest.mark.parametrize("fragment", [
    '[model_providers.x]\nenv_key = "AGENTPORTER_API_KEY"\n',
    '[model_providers.x]\nenv_key = "MCP_SOMETHING"\n',
])
def test_rejects_gateway_secret_as_model_provider_auth(tmp_path, fragment):
    (tmp_path / "config.toml").write_text(fragment)
    with pytest.raises(RuntimeError, match="Unsafe"):
        guard._clean_profile_data(tmp_path)


@pytest.mark.parametrize("relative_path", [
    ".codex/config.toml", ".mcp.json", ".agents/plugins/marketplace.json",
])
def test_rejects_project_loaded_tool_configuration(tmp_path, relative_path):
    f = tmp_path / relative_path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("{}")
    with pytest.raises(RuntimeError, match="project-level"):
        guard._reject_project_overrides(tmp_path)


def test_environment_allowlist_drops_gateway_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_API_KEY", "private")
    monkeypatch.setenv("MCP_EXTRA_HEADERS", "private")
    monkeypatch.setenv("OTHER_SECRET", "private")
    monkeypatch.setenv("HEADROOM_TEST_API_KEY", "test-key")
    e = guard._safe_environment(tmp_path, {"HEADROOM_TEST_API_KEY"})
    assert e["HEADROOM_TEST_API_KEY"] == "test-key"
    assert e["CODEX_HOME"] == str(tmp_path)
    for name in ("AGENTPORTER_API_KEY", "MCP_EXTRA_HEADERS", "OTHER_SECRET"):
        assert name not in e


def test_effective_mcp_roster_must_be_empty(tmp_path, monkeypatch):
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='[{"name":"danger","enabled":true}]')
    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="enabled MCP"):
        guard._validate_mcp_roster("/bin/codex", tmp_path, {})
    assert "sandbox_workspace_write.network_access=false" in calls[0]


def test_mcp_listing_failure_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(guard.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout='bad json'))
    with pytest.raises(RuntimeError, match="Cannot verify"):
        guard._validate_mcp_roster("/bin/codex", tmp_path, {})


def test_guard_does_not_execute_if_mcp_roster_not_safe(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.toml").write_text('model = "gpt-test"\n')
    ran = []
    def fake_run(argv, **kw):
        ran.append(argv)
        return SimpleNamespace(stdout='[{"name":"danger","enabled":true}]', returncode=0)
    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="enabled MCP"):
        guard.run(str(source), str(tmp_path), ["/bin/echo", "exec", "test"])
    assert len(ran) == 1


def test_safe_launch_uses_temp_profile_forces_no_network_and_cleans(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.toml").write_text('model = "gpt-test"\n[mcp_servers.bad]\ncommand="evil"\n')
    auth = source / "auth.json"
    auth.write_text('{"test":"fixture-only"}')
    auth.chmod(0o600)
    calls = []
    def fake_run(argv, **kw):
        e = kw["env"]
        prof = Path(e["CODEX_HOME"])
        assert prof != source and prof.is_dir()
        assert prof.stat().st_mode & 0o777 == 0o700
        assert (prof / "auth.json").is_symlink()
        assert "mcp_servers" not in tomllib.loads((prof / "config.toml").read_text())
        assert "sandbox_workspace_write.network_access=false" in argv
        calls.append((argv, prof))
        if "mcp" in argv:
            return SimpleNamespace(stdout="[]", returncode=0)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    status = guard.run(str(source), str(tmp_path), ["/bin/echo", "exec", "--sandbox", "read-only", "test"])
    assert status == 0
    assert len(calls) == 2
    assert calls[0][1] == calls[1][1]
    assert not calls[0][1].exists()


def test_broker_does_not_accept_caller_publication_flags(tmp_path, monkeypatch):
    from agentporter.agents.broker import AgentBroker
    from unittest.mock import Mock
    from types import SimpleNamespace
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    broker = AgentBroker(SimpleNamespace(get=lambda _: SimpleNamespace(
        path=str(tmp_path), writable=True, allow_agent_dispatch=True
    )), Mock())
    agent = broker.adapters["jax"]
    monkeypatch.setattr(agent, "detect", lambda: {"is_installed": True})
    for field in ("allow_commit", "allow_push"):
        with pytest.raises(PermissionError, match="operator-verified approval"):
            broker.dispatch_agent("jax", "task", "ws", read_only=False, **{field: True})
    broker.job_manager.start_raw_job.assert_not_called()


def test_selected_profile_fails_closed(tmp_path):
    (tmp_path / "config.toml").write_text(
        'profile = "private"\n'
        '[profiles.private]\nmodel = "gpt-secret"\n'
    )
    with pytest.raises(RuntimeError, match="Selected Codex profiles"):
        guard._clean_profile_data(tmp_path)


def test_provider_auth_semantics_are_preserved_or_rejected(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        '[model_providers.private]\n'
        'base_url = "https://example.test"\n'
        'wire_api = "responses"\n'
        'requires_openai_auth = true\n'
    )
    clean, _ = guard._clean_profile_data(tmp_path)
    assert tomllib.loads(clean)["model_providers"]["private"]["requires_openai_auth"] is True
    config.write_text('[model_providers.private]\nunknown_auth_mechanism=true\n')
    with pytest.raises(RuntimeError, match="Unsupported Codex model-provider keys"):
        guard._clean_profile_data(tmp_path)


def test_isolated_python_ignores_workspace_package_shadow(tmp_path):
    import subprocess
    import sys
    fake = tmp_path / "agentporter"
    fake.mkdir()
    marker = tmp_path / "SHADOW_EXECUTED"
    (fake / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", "import agentporter; print(agentporter.__file__)"],
        cwd=tmp_path, text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert str(fake) not in result.stdout
    assert not marker.exists()


def test_launcher_initial_environment_excludes_gateway_secrets(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text(
        '[model_providers.x]\nenv_key = "CUSTOM_PROVIDER_KEY"\n'
    )
    monkeypatch.setenv("CUSTOM_PROVIDER_KEY", "fixture-token")
    monkeypatch.setenv("AGENTPORTER_API_KEY", "gateway-secret")
    monkeypatch.setenv("MCP_EXTRA_HEADERS", "gateway-secret")
    env = guard.safe_launcher_environment(str(tmp_path))
    assert env["CUSTOM_PROVIDER_KEY"] == "fixture-token"
    assert "AGENTPORTER_API_KEY" not in env
    assert "MCP_EXTRA_HEADERS" not in env
    assert "PYTHONPATH" not in env


def test_account_authentication_constraints_survive_profile_filter(tmp_path):
    (tmp_path / "config.toml").write_text(
        'forced_login_method = "chatgpt"\n'
        'forced_chatgpt_workspace_id = "workspace-example"\n'
        'model = "gpt-test"\n'
    )
    content, _ = guard._clean_profile_data(tmp_path)
    parsed = tomllib.loads(content)
    assert parsed["forced_login_method"] == "chatgpt"
    assert parsed["forced_chatgpt_workspace_id"] == "workspace-example"


@pytest.mark.parametrize("value", [
    'forced_future_account_rule = "deny"\n',
    'forced_login_method = ""\n',
    'forced_chatgpt_workspace_id = false\n',
])
def test_unknown_or_invalid_account_constraints_fail_closed(tmp_path, value):
    (tmp_path / "config.toml").write_text(value)
    with pytest.raises(RuntimeError, match="account constraint"):
        guard._clean_profile_data(tmp_path)
