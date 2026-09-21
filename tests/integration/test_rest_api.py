import pytest
from fastapi.testclient import TestClient
from agentporter.server import create_asgi_app
from agentporter.config import Config
import tempfile
import pathlib
import os
import yaml

@pytest.fixture
def test_config():
    with tempfile.TemporaryDirectory() as base_dir:
        base = pathlib.Path(base_dir)
        cfg_dir = base / "cfg"
        st_dir = base / "st"
        cfg_dir.mkdir()
        st_dir.mkdir()
        
        # Write workspaces.yaml
        ws_file = cfg_dir / "workspaces.yaml"
        with open(ws_file, "w") as f:
            yaml.dump({"workspaces": {"test-workspace": {"path": "/tmp", "enabled": True}}}, f)
            
        # Write secrets.env
        secrets_file = cfg_dir / "secrets.env"
        with open(secrets_file, "w") as f:
            f.write("API_KEY=test-secret-key\n")

        config = Config(config_dir=cfg_dir, state_dir=st_dir)
        config.security.allowed_hosts.append("testserver")
        yield config

@pytest.fixture
def client(test_config):
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
