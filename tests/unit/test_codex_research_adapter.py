"""codex_research is an isolated Codex identity, never an alias of another account."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.adapters import CodexResearchAdapter
from agentporter.agents.broker import AgentBroker


@pytest.fixture
def codex_research(tmp_path):
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nprintf 'codex-cli 1.2.3\\n'\n")
    executable.chmod(0o755)
    adapter = CodexResearchAdapter(str(executable))
    adapter.codex_home = str(tmp_path / ".codex-research")
    return adapter


def profile(adapter, config=""):
    from pathlib import Path

    home = Path(adapter.codex_home)
    home.mkdir()
    (home / "config.toml").write_text(config)
    (home / "auth.json").write_text("{}")
    return home


def test_codex_research_default_profile_is_distinct():
    import os

    adapter = CodexResearchAdapter()
    assert adapter.name == "codex_research"
    assert adapter.alias == "codex_research"
    assert adapter.codex_home == os.path.expanduser("~/.codex-research")
    assert adapter.codex_home not in {
        os.path.expanduser("~/.codex"), os.path.expanduser("~/.codex-impl")
    }


@pytest.mark.parametrize("missing", ["config.toml", "auth.json", "both"])
def test_missing_codex_research_profile_does_not_borrow_other_accounts(codex_research, tmp_path, missing):
    home = profile(codex_research)
    for name in (".codex", ".codex-impl"):
        other = tmp_path / name
        other.mkdir()
        (other / "config.toml").write_text('model = "another-account-model"\n')
        (other / "auth.json").write_text("{}")
    for name in ("config.toml", "auth.json"):
        if missing in {name, "both"}:
            (home / name).unlink()
    detection = codex_research.detect()
    assert detection["is_installed"] is False
    assert detection["identity_ready"] is False
    assert detection["configured_model"] != "another-account-model"


def test_codex_research_detect_preserves_unset_model(codex_research):
    profile(codex_research)
    detection = codex_research.detect()
    assert detection["is_installed"] is True
    assert detection["configured_model"] == "unknown"
    assert detection["reasoning_effort"] == "unknown"


def test_codex_research_reads_only_own_config(codex_research):
    profile(codex_research, 'model = "codex_research-model"\nmodel_reasoning_effort = "medium"\n')
    detection = codex_research.detect()
    assert detection["configured_model"] == "codex_research-model"
    assert detection["reasoning_effort"] == "medium"


@pytest.mark.parametrize("writable", [True, False])
def test_codex_research_argv_preserves_account_and_workspace_policy(codex_research, writable):
    argv = codex_research.build_argv("/workspace", "task", writable=writable)
    assert argv[0:2] == ["env", f"CODEX_HOME={codex_research.codex_home}"]
    assert argv[argv.index("--sandbox") + 1] == (
        "workspace-write" if writable else "read-only"
    )
    assert "--ephemeral" in argv
    assert "approval_policy=never" in argv
    assert "-m" not in argv
    assert not any("model_reasoning_effort=" in arg for arg in argv)
    explicit = codex_research.build_argv("/workspace", "task", model="codex_research-model", reasoning_effort="high")
    assert explicit[explicit.index("-m") + 1] == "codex_research-model"
    assert "model_reasoning_effort=high" in explicit


def test_codex_research_registration_discovery_and_authorized_dispatch(codex_research, tmp_path, monkeypatch):
    profile(codex_research)
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    jobs = Mock(approved_git_pulls=None)
    jobs.start_confined_agent_job.return_value = "codex_research-job"
    broker = AgentBroker(SimpleNamespace(get=lambda _: workspace), jobs)
    assert isinstance(broker.adapters["codex_research"], CodexResearchAdapter)
    broker.adapters = {"codex_research": codex_research}
    discovery = broker.list_agents()[0]
    assert discovery["agent"] == "codex_research"
    assert discovery["worker_cli"] == "codex"
    assert discovery["available"] is True
    assert discovery["configured_model"] == "unknown"
    result = broker.dispatch_agent("codex_research", "Write a scoped result", "research", read_only=False)
    assert result["job_id"] == "codex_research-job"
    assert result["worker_cli"] == "codex"
    assert result["requested_model"] == ""
    argv = jobs.start_confined_agent_job.call_args.kwargs["cmd"]
    assert argv[1:4] == ["-I", "-m", "agentporter.agents.isolated_codex"]
    assert argv[argv.index("--source-home") + 1] == codex_research.codex_home
    assert "-m" not in argv[argv.index("--") + 1:]
    assert "workspace-write" in argv
    jobs.start_confined_agent_job.reset_mock()
    workspace.allow_agent_dispatch = False
    with pytest.raises(PermissionError, match="does not allow"):
        broker.dispatch_agent("codex_research", "test", "research")
    jobs.start_confined_agent_job.assert_not_called()
