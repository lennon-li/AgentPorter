import pytest
from fastapi.testclient import TestClient
from agentporter.server import create_asgi_app
from agentporter.config import Config
import tempfile
import pathlib
import os
import yaml
import sys
import time
from agentporter.agents.adapters.codex import CodexAdapter
from tests._support import BWRAP_USABLE

@pytest.fixture
def test_config():
    with tempfile.TemporaryDirectory() as base_dir:
        base = pathlib.Path(base_dir)
        cfg_dir = base / "cfg"
        st_dir = base / "st"
        cfg_dir.mkdir()
        st_dir.mkdir()
        workspace = base / "workspace"
        workspace.mkdir()
        
        # Write workspaces.yaml
        ws_file = cfg_dir / "workspaces.yaml"
        with open(ws_file, "w") as f:
            yaml.dump({"workspaces": {"test-workspace": {"path": str(workspace), "enabled": True, "allow_agent_dispatch": True}}}, f)
            
        # Write secrets.env
        secrets_file = cfg_dir / "secrets.env"
        with open(secrets_file, "w") as f:
            f.write("API_KEY=test-secret-key\n")

        config = Config(config_dir=cfg_dir, state_dir=st_dir)
        config.security.allowed_hosts.append("testserver")
        config.server.public_url = "https://example.test"
        yield config

@pytest.fixture
def client(test_config, monkeypatch):
    # Test REST/broker contracts, not a developer's installed or billed CLI.
    # REST routing contract is tested with a neutral fake worker. Dedicated
    # isolated_codex tests cover the real Codex launcher with Python -I.
    from agentporter.agents.broker import AgentBroker

    class FakeRESTWorker:
        name = "jax"
        alias = "Codex fixture"
        provider = "OpenAI"
        description = "No-model REST contract fixture"
        supports_read_only = True
        supports_model_override = True
        supports_reasoning_override = True

        def detect(self):
            return {"is_installed": True, "cli_version": "fixture",
                    "provider": "OpenAI", "configured_model": "gpt-6-luna",
                    "reasoning_effort": "high"}

        def capabilities(self):
            return ["verification"]

        def build_argv(self, **kwargs):
            return [sys.executable, "-c", "print('fixture worker completed')"]

    monkeypatch.setattr(
        AgentBroker, "_configured_workers",
        lambda self: ({"jax": FakeRESTWorker()}, {
            "jax": ("codex", "Jax", "Fixture-only REST contract worker", "")
        }),
    )
    app = create_asgi_app(test_config)
    # The SecurityMiddleware is the outermost app, TestClient wraps it.
    with TestClient(app) as client:
        yield client

def test_unauthenticated_access(client):
    # Health should work
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

    # OpenAPI should work
    response = client.get("/openapi.json")
    assert response.status_code == 200
    openapi = response.json()
    assert openapi["info"]["title"] == "AgentPorter API"
    assert openapi["info"]["version"] == "0.1.0"
    assert openapi["servers"] == [{"url": "https://example.test"}]
    
    # Check operationId format
    paths = openapi.get("paths", {})
    assert "/api/v1/workspaces/" in paths
    assert paths["/api/v1/workspaces/"]["get"]["operationId"] == "list_workspaces"

    # Docs should work
    response = client.get("/docs")
    assert response.status_code == 200

    # Protected endpoint should fail
    response = client.get("/api/v1/workspaces/")
    assert response.status_code == 401

def test_authenticated_access_custom_header(client, test_config):
    headers = {"X-AgentPorter-Key": test_config.api_key}
    response = client.get("/api/v1/workspaces/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_authenticated_access_bearer_token(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    response = client.get("/api/v1/workspaces/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(ws.get("workspace_id") == "test-workspace" for ws in data)

    response = client.get("/api/v1/workspaces/test-workspace", headers=headers)
    assert response.status_code == 200
    assert response.json()["workspace_id"] == "test-workspace"

def test_file_operations_rest(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    
    # Write file
    write_req = {
        "path": "rest_test.txt",
        "content": "hello rest API"
    }
    response = client.post("/api/v1/workspaces/test-workspace/files/write", json=write_req, headers=headers)
    assert response.status_code == 200
    
    # Read file
    read_req = {"path": "rest_test.txt"}
    response = client.post("/api/v1/workspaces/test-workspace/files/read", json=read_req, headers=headers)
    assert response.status_code == 200
    assert response.json()["content"] == "hello rest API"
    
    # Trash file
    trash_req = {"path": "rest_test.txt"}
    response = client.post("/api/v1/workspaces/test-workspace/files/trash", json=trash_req, headers=headers)
    assert response.status_code == 200

@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap user namespaces unavailable")
def test_exec_run_rest(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    
    exec_req = {
        "argv": ["echo", "rest_exec"],
        "cwd": "",
        "timeout_seconds": 5
    }
    response = client.post("/api/v1/workspaces/test-workspace/exec/run", json=exec_req, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "rest_exec" in data["stdout"]

def test_public_rest_agent_list_is_named_only(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    response = client.get("/api/v1/workspaces/test-workspace/agents/list", headers=headers)
    assert response.status_code == 200
    entries = response.json()
    assert [x["agent"] for x in entries] == [
        "jax", "liz", "prof", "phil", "wei", "ming", "argie"
    ]
    assert all(x["registered"] is False for x in entries if x["agent"] != "jax")


@pytest.mark.parametrize("action,payload", [
    ("commit", {"message": "no unverified commit", "all_files": False}),
    ("push", {"remote": "origin", "branch": "main", "set_upstream": False}),
])
def test_direct_git_publication_requires_verified_approval(client, test_config, action, payload):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    response = client.post(
        f"/api/v1/workspaces/test-workspace/git/{action}",
        json=payload, headers=headers,
    )
    assert response.status_code == 403
    assert "approval" in response.json()["detail"].lower()


def test_public_rest_rejects_generic_runtime(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    response = client.post(
        "/api/v1/workspaces/test-workspace/agents/dispatch",
        json={"agent": "codex", "task": "Do not launch"},
        headers=headers,
    )
    assert response.status_code == 403
    assert "unapproved" in response.json()["detail"].lower()


def test_dispatch_agent_rest(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}
    # The seven-agent catalog remains discoverable, but real launch is denied
    # pending kernel-confined backend. Neither read nor write can bypass it.
    for read_only in (True, False):
        response = client.post(
            "/api/v1/workspaces/test-workspace/agents/dispatch",
            json={"agent": "jax", "task": "do not launch", "read_only": read_only},
            headers=headers,
        )
        assert response.status_code == 403
        assert "delegation blocked" in response.json()["detail"].lower()
