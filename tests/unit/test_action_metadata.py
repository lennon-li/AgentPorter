"""Regressions for machine-specific Actions and named worker compatibility."""

import pytest
from agentporter.config import Config, ServerSettings
from agentporter.server import create_asgi_app
from agentporter.agents.broker import AgentBroker
from agentporter.agents.adapters.codex_identity import JaxAdapter, LizAdapter
from agentporter.workspaces.registry import WorkspaceRegistry


def test_action_metadata_uses_environment(monkeypatch):
    monkeypatch.setenv("AGENTPORTER_PUBLIC_URL", "https://bcc.example.test")
    monkeypatch.setenv("AGENTPORTER_ACTION_PREFIX", "bcc")
    settings = ServerSettings()
    assert settings.public_url == "https://bcc.example.test"
    assert settings.action_prefix == "bcc"


def test_action_metadata_config_override_and_workspace_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_API_KEY", "fixture-only-not-a-real-key")
    monkeypatch.setenv("AGENTPORTER_ACTION_PREFIX", "other")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text(
        "server:\n  public_url: https://bcc.example.test\n  action_prefix: bcc\n"
    )
    config = Config(config_dir=config_dir, state_dir=tmp_path / "state")
    config.workspaces = {"repos": {"path": str(tmp_path), "allow_agent_dispatch": True}}
    app = create_asgi_app(config).app
    schema = app.openapi()
    assert schema["info"]["title"] == "BCC AgentPorter API"
    assert schema["servers"][0]["url"] == "https://bcc.example.test"
    operation_ids = [op["operationId"] for path in schema["paths"].values()
                     for op in path.values() if isinstance(op, dict) and "operationId" in op]
    assert operation_ids and all(op.startswith("bcc_") for op in operation_ids)
    assert len(operation_ids) == len(set(operation_ids))
    # GPT Actions accepts at most 30 operations; hidden endpoints still exist.
    assert len(operation_ids) <= 30
    assert "bcc_health" not in operation_ids
    assert "bcc_git_branch" not in operation_ids
    for operation_id, request_schema in (
        ("bcc_exec_run", "ExecRunRequest"),
        ("bcc_exec_start", "ExecStartRequest"),
    ):
        assert operation_id in operation_ids
        assert "network_access" in schema["components"]["schemas"][request_schema]["properties"]
    assert app.openapi() == schema
    from agentporter.rest.schemas import WorkspaceInfoResponse
    parsed = WorkspaceInfoResponse.model_validate(app.state.tools["list_workspaces"]()[0])
    assert parsed.permissions["agent_dispatch"] is True


@pytest.mark.parametrize("adapter_cls", [JaxAdapter, LizAdapter])
@pytest.mark.parametrize("writable,allow_push", [(False, False), (True, False), (True, True)])
def test_broker_named_codex_controls(tmp_path, monkeypatch, adapter_cls, writable, allow_push):
    registry = WorkspaceRegistry({"repos": {"path": str(tmp_path), "writable": writable,
                                            "allow_agent_dispatch": True}})

    class RecordingJobs:
        def start_raw_job(self, **kwargs):
            self.command = kwargs["cmd"]
            return "recording-job"

    jobs = RecordingJobs()
    broker = AgentBroker(registry, jobs)
    adapter = adapter_cls(executable_override="/bin/echo")
    monkeypatch.setattr(adapter, "detect", lambda: {"is_installed": True,
        "configured_model": "gpt-6-luna", "reasoning_effort": "high"})
    broker.adapters = {adapter.name: adapter}
    result = broker.dispatch_agent(adapter.name, "fixture task", "repos", allow_push=allow_push)
    command = jobs.command
    assert result["job_id"] == "recording-job"
    assert command[command.index("--sandbox") + 1] == ("workspace-write" if writable else "read-only")
    assert ("sandbox_workspace_write.network_access=true" in command) is (writable and allow_push)


@pytest.mark.parametrize("adapter_cls", [JaxAdapter, LizAdapter])
def test_named_codex_without_config_reports_unknown(tmp_path, adapter_cls):
    adapter = adapter_cls(executable_override="/bin/echo")
    adapter.codex_home = str(tmp_path)
    detection = adapter.detect()
    assert detection["configured_model"] == "unknown"
    assert detection["reasoning_effort"] == "unknown"
    assert not detection["is_installed"]


def test_rest_exec_requests_default_to_network_access():
    # Agent7 REST Actions are online unless the call explicitly opts out.
    from agentporter.rest.schemas import ExecRunRequest, ExecStartRequest

    assert ExecRunRequest(argv=["true"]).network_access is True
    assert ExecStartRequest(argv=["true"]).network_access is True
    assert ExecRunRequest(argv=["true"], network_access=False).network_access is False
