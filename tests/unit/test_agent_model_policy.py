"""Regression tests for prohibited and remapped worker models."""

import pytest

from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.broker import AgentBroker, OPENAI_FALLBACK_MODEL
from agentporter.tools.jobs import JobManager


class FakeOpenAIAdapter(AgentAdapter):
    name = "fake-openai"
    alias = "Fake OpenAI"
    provider = "OpenAI"
    description = "Test adapter"
    supports_model_override = True
    supports_reasoning_override = True
    default_model = "gpt-5.6-luna"

    def detect(self):
        return {
            "executable": "/bin/echo",
            "is_installed": True,
            "cli_version": "test",
            "provider": self.provider,
            "configured_model": self.default_model,
            "reasoning_effort": "high",
        }

    def capabilities(self):
        return ["testing"]

    def build_argv(self, workspace_path, packet, model="", reasoning_effort="", writable=True):
        self.last_model = model
        return ["/bin/echo", f"model={model}"]


def _fake_broker(workspace_registry, tmp_path):
    broker = AgentBroker(workspace_registry, JobManager(tmp_path / "state"))
    adapter = FakeOpenAIAdapter()
    broker.adapters = {adapter.name: adapter}
    return broker, adapter


def test_inherited_gpt_56_routes_to_safe_openai_fallback():
    assert AgentBroker._resolve_default_model("OpenAI", "gpt-5.6-luna") == OPENAI_FALLBACK_MODEL


def test_non_openai_inherited_gpt_56_is_blocked():
    with pytest.raises(ValueError, match="cannot be remapped safely"):
        AgentBroker._resolve_default_model("Google Vertex AI", "gpt-5.6-luna")


def test_non_prohibited_models_are_preserved():
    assert AgentBroker._resolve_default_model("OpenAI", "gpt-6-luna") == "gpt-6-luna"
    assert AgentBroker._resolve_default_model("Google AI", "vertex/gemini-3.8-flash") == "vertex/gemini-3.8-flash"


@pytest.mark.parametrize("model", ["gpt-5.6", "gpt-5.6-luna", "GPT-5.6-Pro"])
def test_gpt_56_family_is_prohibited(model):
    assert AgentBroker._model_is_prohibited(model)


def test_list_agents_exposes_configured_and_effective_model(workspace_registry, tmp_path):
    broker, _ = _fake_broker(workspace_registry, tmp_path)

    agent = broker.list_agents()[0]

    assert agent["configured_model"] == "gpt-5.6-luna"
    assert agent["effective_model"] == OPENAI_FALLBACK_MODEL
    assert agent["default_model"] == OPENAI_FALLBACK_MODEL
    assert "policy override" in agent["default_routing"]
    assert agent["available"] is True


def test_dispatch_inherited_prohibited_model_uses_fallback(workspace_registry, tmp_path):
    broker, adapter = _fake_broker(workspace_registry, tmp_path)
    result = broker.dispatch_agent("fake-openai", "test", "test-ws")

    try:
        assert adapter.last_model == OPENAI_FALLBACK_MODEL
        assert result["requested_model"] == OPENAI_FALLBACK_MODEL
        assert result["configured_model"] == "gpt-5.6-luna"
    finally:
        broker.job_manager.cancel(result["job_id"])


def test_dispatch_explicit_prohibited_model_is_rejected(workspace_registry, tmp_path):
    broker, _ = _fake_broker(workspace_registry, tmp_path)

    with pytest.raises(ValueError, match="prohibited"):
        broker.dispatch_agent("fake-openai", "test", "test-ws", model="gpt-5.6-luna")


def test_dispatch_explicit_allowed_model_is_preserved(workspace_registry, tmp_path):
    broker, adapter = _fake_broker(workspace_registry, tmp_path)
    result = broker.dispatch_agent("fake-openai", "test", "test-ws", model="gpt-6-luna")

    try:
        assert adapter.last_model == "gpt-6-luna"
        assert result["requested_model"] == "gpt-6-luna"
    finally:
        broker.job_manager.cancel(result["job_id"])
