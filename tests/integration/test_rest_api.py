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
    monkeypatch.setattr(CodexAdapter, "detect", lambda self: {
        "is_installed": True, "cli_version": "fixture", "provider": "OpenAI",
        "configured_model": "gpt-6-luna", "reasoning_effort": "high",
    })
    monkeypatch.setattr(CodexAdapter, "build_argv", lambda self, **kwargs: [
        sys.executable, "-c", "print('fixture worker completed')",
    ])
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

def test_dispatch_agent_rest(client, test_config):
    headers = {"Authorization": f"Bearer {test_config.api_key}"}

    prohibited_req = {
        "agent": "codex",
        "task": "echo blocked dispatch test",
        "purpose": "unit test",
        "model": "gpt-5.6-luna",
        "reasoning_effort": "high"
    }
    response = client.post("/api/v1/workspaces/test-workspace/agents/dispatch", json=prohibited_req, headers=headers)
    assert response.status_code == 400
    assert "prohibited" in response.json()["detail"].lower()

    dispatch_req = {
        "agent": "codex",
        "task": "echo rest dispatch test",
        "purpose": "unit test",
        "model": "gpt-6-luna",
        "reasoning_effort": "high"
    }
    response = client.post("/api/v1/workspaces/test-workspace/agents/dispatch", json=dispatch_req, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "dispatch_id" in data
    assert "job_id" in data
    assert data["dispatch_id"] == data["job_id"]
    assert data["status"] == "running"
    assert data["worker_cli"] == "codex"
    assert data["requested_model"] == "gpt-6-luna"
    # Let the monitor finish its SQLite write before the temp state is removed.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = client.get(f"/api/v1/jobs/{data['job_id']}/status", headers=headers)
        assert status.status_code == 200
        if status.json()["status"] == "completed":
            break
        time.sleep(0.05)
    else:
        pytest.fail("fixture worker did not complete before teardown")
