"""Security boundary and sandbox isolation tests."""

import os
import shutil
import pytest
from pathlib import Path
from agentporter.auth import verify_api_key, is_host_allowed
from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.agents.broker import AgentBroker
from agentporter.tools.jobs import JobManager
from tests._support import BWRAP_USABLE


def test_auth_rejection():
    key = "correct_api_key_12345"
    assert not verify_api_key("", key)
    assert not verify_api_key("wrong_key_12345", key)
    assert verify_api_key(key, key)


def test_host_header_validation():
    allowed = ["localhost", "127.0.0.1:8765", "*.trycloudflare.com"]
    assert is_host_allowed("localhost", allowed)
    assert is_host_allowed("127.0.0.1:8765", allowed)
    assert is_host_allowed("custom-tunnel.trycloudflare.com", allowed)
    assert not is_host_allowed("attacker.com", allowed)
    assert not is_host_allowed("malicious.org:8765", allowed)


def test_path_traversal_blocked(tmp_path: Path):
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir()
    with pytest.raises(ValueError, match="Path traversal detected|Path escape attempt blocked"):
        validate_workspace_path(str(ws_dir), "../../.ssh/id_rsa")

    with pytest.raises(ValueError, match="Absolute paths not permitted"):
        validate_workspace_path(str(ws_dir), "/mnt/c/Windows")


def test_sensitive_files_blocked(tmp_path: Path):
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir()
    with pytest.raises(ValueError, match="sensitive or internal"):
        validate_workspace_path(str(ws_dir), ".git/config")

    with pytest.raises(ValueError, match="sensitive or internal"):
        validate_workspace_path(str(ws_dir), ".ssh/id_rsa")


def test_unknown_workspace_blocked():
    reg = WorkspaceRegistry()
    with pytest.raises(KeyError, match="Unknown workspace_id"):
        reg.get("nonexistent-workspace-xyz")


def test_unknown_agent_blocked(tmp_path: Path):
    reg = WorkspaceRegistry({"ws": {"path": str(tmp_path), "writable": True}})
    jm = JobManager(tmp_path / "state")
    broker = AgentBroker(reg, jm)
    with pytest.raises(ValueError, match="Unknown agent"):
        broker.dispatch_agent("malicious-agent", "do harm", "ws")


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap not available")
def test_sandbox_python_ssh_blocked(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    code = (
        "import os\n"
        "ssh_path = os.path.expanduser('~/.ssh')\n"
        "found = os.path.exists(ssh_path) or os.path.exists('/home')\n"
        "print('SSH_EXISTS:', found)\n"
    )
    res = sandbox.run(str(tmp_path), ["python3", "-c", code])
    assert res["exit_code"] == 0
    assert "SSH_EXISTS: False" in res["stdout"]


@pytest.mark.skipif(not BWRAP_USABLE or not shutil.which("Rscript"), reason="bwrap or Rscript not available")
def test_sandbox_r_ssh_blocked(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    code = 'cat("R_SSH_EXISTS:", dir.exists(path.expand("~/.ssh")) || dir.exists("/home"))'
    res = sandbox.run(str(tmp_path), ["Rscript", "-e", code])
    assert res["exit_code"] == 0
    assert "R_SSH_EXISTS: FALSE" in res["stdout"]


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap not available")
def test_sandbox_mnt_c_blocked(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    res = sandbox.run(str(tmp_path), ["bash", "-c", "ls -d /mnt/c 2>/dev/null || echo NOT_MOUNTED"])
    assert res["exit_code"] == 0
    assert "NOT_MOUNTED" in res["stdout"]


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap not available")
def test_sandbox_docker_socket_blocked(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    res = sandbox.run(str(tmp_path), ["bash", "-c", "ls /var/run/docker.sock 2>/dev/null || echo NO_DOCKER"])
    assert res["exit_code"] == 0
    assert "NO_DOCKER" in res["stdout"]


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap not available")
def test_sandbox_network_blocked(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    code = (
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "    print('CONNECTED')\n"
        "except Exception as e:\n"
        "    print('NETWORK_BLOCKED:', type(e).__name__)\n"
    )
    res = sandbox.run(str(tmp_path), ["python3", "-c", code], timeout_seconds=5)
    assert res["exit_code"] == 0
    assert "NETWORK_BLOCKED: OSError" in res["stdout"] or "Network is unreachable" in res["stdout"] or "NETWORK_BLOCKED" in res["stdout"]


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap not available")
def test_sandbox_environment_clean(tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    os.environ["SECRET_HOST_TOKEN_TEST"] = "super_secret_12345"
    res = sandbox.run(str(tmp_path), ["bash", "-c", "env"])
    assert res["exit_code"] == 0
    assert "SECRET_HOST_TOKEN_TEST" not in res["stdout"]
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in res["stdout"]
    assert "USER=sandbox" in res["stdout"]
