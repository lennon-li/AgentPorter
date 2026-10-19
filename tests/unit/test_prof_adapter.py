"""Prof is an isolated Codex identity, never an alias of another account."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.adapters import ProfAdapter
from agentporter.agents.broker import AgentBroker


@pytest.fixture
def prof(tmp_path):
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nprintf 'codex-cli 1.2.3\\n'\n")
    executable.chmod(0o755)
    adapter = ProfAdapter(str(executable))
    adapter.codex_home = str(tmp_path / ".codex-prof")
    return adapter


def profile(adapter, config=""):
    from pathlib import Path

    home = Path(adapter.codex_home)
    home.mkdir()
    (home / "config.toml").write_text(config)
    (home / "auth.json").write_text("{}")
    return home


def test_prof_default_profile_is_distinct():
    import os

    adapter = ProfAdapter()
    assert adapter.name == "prof"
    assert adapter.alias == "Prof"
    assert adapter.codex_home == os.path.expanduser("~/.codex-prof")
    assert adapter.codex_home not in {
        os.path.expanduser("~/.codex"), os.path.expanduser("~/.codex-liz")
    }


@pytest.mark.parametrize("missing", ["config.toml", "auth.json", "both"])
def test_missing_prof_profile_does_not_borrow_other_accounts(prof, tmp_path, missing):
    home = profile(prof)
    for name in (".codex", ".codex-liz"):
        other = tmp_path / name
        other.mkdir()
        (other / "config.toml").write_text('model = "another-account-model"\n')
        (other / "auth.json").write_text("{}")
    for name in ("config.toml", "auth.json"):
        if missing in {name, "both"}:
            (home / name).unlink()
    detection = prof.detect()
    assert detection["is_installed"] is False
    assert detection["identity_ready"] is False
    assert detection["configured_model"] != "another-account-model"


def test_prof_detect_preserves_unset_model(prof):
    profile(prof)
    detection = prof.detect()
    assert detection["is_installed"] is True
    assert detection["configured_model"] == "unknown"
    assert detection["reasoning_effort"] == "unknown"


def test_prof_reads_only_own_config(prof):
    profile(prof, 'model = "prof-model"\nmodel_reasoning_effort = "medium"\n')
    detection = prof.detect()
    assert detection["configured_model"] == "prof-model"
    assert detection["reasoning_effort"] == "medium"


@pytest.mark.parametrize("writable", [True, False])
def test_prof_argv_preserves_account_and_workspace_policy(prof, writable):
    argv = prof.build_argv("/workspace", "task", writable=writable)
    assert argv[0:2] == ["env", f"CODEX_HOME={prof.codex_home}"]
    assert argv[argv.index("--sandbox") + 1] == (
        "workspace-write" if writable else "read-only"
    )
    assert "--ephemeral" in argv
    assert "approval_policy=never" in argv
    assert "-m" not in argv
    assert not any("model_reasoning_effort=" in arg for arg in argv)
    explicit = prof.build_argv("/workspace", "task", model="prof-model", reasoning_effort="high")
    assert explicit[explicit.index("-m") + 1] == "prof-model"
    assert "model_reasoning_effort=high" in explicit


def test_prof_registration_discovery_and_authorized_dispatch(prof, tmp_path, monkeypatch):
    profile(prof)
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path))
    workspace = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    jobs = Mock()
    jobs.start_raw_job.return_value = "prof-job"
    broker = AgentBroker(SimpleNamespace(get=lambda _: workspace), jobs)
    assert isinstance(broker.adapters["prof"], ProfAdapter)
    broker.adapters = {"prof": prof}
    discovery = broker.list_agents()[0]
    assert discovery["agent"] == "prof"
    assert discovery["worker_cli"] == "codex"
    assert discovery["available"] is True
    assert discovery["configured_model"] == "unknown"
    result = broker.dispatch_agent("prof", "Write a scoped result", "research", read_only=False)
    assert result["job_id"] == "prof-job"
    assert result["worker_cli"] == "codex"
    assert result["requested_model"] == ""
    argv = jobs.start_raw_job.call_args.kwargs["cmd"]
    assert argv[1:4] == ["-I", "-m", "agentporter.agents.isolated_codex"]
    assert argv[argv.index("--source-home") + 1] == prof.codex_home
    assert "-m" not in argv[argv.index("--") + 1:]
    assert "workspace-write" in argv
    jobs.start_raw_job.reset_mock()
    workspace.allow_agent_dispatch = False
    with pytest.raises(PermissionError, match="does not allow"):
        broker.dispatch_agent("prof", "test", "research")
    jobs.start_raw_job.assert_not_called()
