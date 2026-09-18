"""Integration tests for AgentPorter tools."""

import os
import time
import shutil
import pytest
from pathlib import Path
from agentporter.tools.system import create_system_tools
from agentporter.tools.files import create_file_tools
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.git import create_git_tools
from agentporter.tools.artifacts import create_artifact_tools
from agentporter.tools.agents import create_agent_tools
from agentporter.tools.jobs import JobManager
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.agents.broker import AgentBroker


def test_capabilities_and_workspace_info(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    get_caps, list_ws, ws_info = create_system_tools(workspace_registry, sandbox)

    caps = get_caps()
    assert "supported_tools" in caps
    assert "bubblewrap_0.9.0" in caps["sandbox"]

    workspaces = list_ws()
    assert any(w["workspace_id"] == "test-ws" for w in workspaces)

    info = ws_info("test-ws")
    assert info["workspace_id"] == "test-ws"
    assert "R" in info["languages"]
    assert "Python" in info["languages"]
    assert info["git"]["is_repo"] is True


def test_file_operations(workspace_registry):
    (
        list_files, search_text, read_file, write_file,
        apply_patch, mkdir, move_path, trash_path
    ) = create_file_tools(workspace_registry)

    files = list_files("test-ws")
    assert "README.md" in files
    assert "R/stats.R" in files
    assert "python/stats.py" in files

    hits = search_text("test-ws", "compute_mean")
    assert len(hits) >= 2

    # Ranged read
    read_res = read_file("test-ws", "README.md", start_line=1, end_line=2)
    assert "AgentPorter Test Workspace" in read_res["content"]
    assert "sha256" in read_res

    # Write file
    w_res = write_file("test-ws", "scratch.txt", "Hello AgentPorter")
    assert w_res["status"] == "written"

    # Read back
    r_res = read_file("test-ws", "scratch.txt")
    assert r_res["content"] == "Hello AgentPorter"

    # Mkdir
    mk_res = mkdir("test-ws", "sub/new_dir")
    assert mk_res["status"] == "created"

    # Move file
    m_res = move_path("test-ws", "scratch.txt", "scratch_renamed.txt")
    assert m_res["status"] == "moved"

    # Trash file
    t_res = trash_path("test-ws", "scratch_renamed.txt")
    assert t_res["status"] == "trashed"

    # Apply patch
    valid_patch = (
        "--- README.md\n"
        "+++ README.md\n"
        "@@ -1,2 +1,3 @@\n"
        " # AgentPorter Test Workspace\n"
        "+Patched line here\n"
        " Line 2 content\n"
    )
    p_res = apply_patch("test-ws", valid_patch)
    assert p_res["status"] == "applied"
    read_patched = read_file("test-ws", "README.md")
    assert "Patched line here" in read_patched["content"]

    # Reject patch targeting sensitive paths
    malicious_patch = (
        "--- .env\n"
        "+++ .env\n"
        "@@ -0,0 +1 @@\n"
        "+PWNED=1\n"
    )
    with pytest.raises(ValueError, match="sensitive or internal"):
        apply_patch("test-ws", malicious_patch)


@pytest.mark.skipif(not shutil.which("bwrap") or not shutil.which("Rscript"), reason="bwrap or Rscript not available")
def test_r_execution_and_tests(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    job_mgr = JobManager(tmp_path / "state")
    exec_run, _ = create_execution_tools(workspace_registry, sandbox, job_mgr)

    # 100/pi in R
    r_calc = exec_run("test-ws", ["Rscript", "-e", "cat(100/pi)"])
    assert r_calc["exit_code"] == 0
    val = float(r_calc["stdout"].strip())
    assert 31.83 <= val <= 31.84


@pytest.mark.skipif(not shutil.which("bwrap"), reason="Bubblewrap not available")
def test_python_execution_and_tests(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    job_mgr = JobManager(tmp_path / "state")
    exec_run, _ = create_execution_tools(workspace_registry, sandbox, job_mgr)

    # 100/pi in Python
    py_calc = exec_run("test-ws", ["python3", "-c", "import math; print(100/math.pi)"])
    assert py_calc["exit_code"] == 0
    val = float(py_calc["stdout"].strip())
    assert 31.83 <= val <= 31.84


@pytest.mark.skipif(not shutil.which("bwrap"), reason="Bubblewrap not available")
def test_bash_sandbox_execution(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    job_mgr = JobManager(tmp_path / "state")
    exec_run, _ = create_execution_tools(workspace_registry, sandbox, job_mgr)

    res = exec_run("test-ws", ["bash", "-c", "echo 'phase 1'; sleep 0.05; echo 'phase 2'"])
    assert res["exit_code"] == 0
    assert "phase 1" in res["stdout"]
    assert "phase 2" in res["stdout"]


def test_git_inspection(workspace_registry):
    git_status, git_diff, git_log, git_show = create_git_tools(workspace_registry)

    st = git_status("test-ws")
    assert "Clean working tree" in st or "master" in st or "main" in st

    diff = git_diff("test-ws")
    assert "No diff" in diff or isinstance(diff, str)

    log = git_log("test-ws", limit=5)
    assert "Initial commit" in log

    show = git_show("test-ws", ref="HEAD")
    assert "commit" in show or "Initial commit" in show


def test_local_http_tool(workspace_registry):
    from agentporter.tools.local_http import create_local_http_tool
    local_http = create_local_http_tool(workspace_registry)

    with pytest.raises(ValueError, match="Invalid port number"):
        local_http("test-ws", port=99999)

    # Valid port but no listener running
    res = local_http("test-ws", port=54321)
    assert "error" in res


def test_artifact_tools(workspace_registry):
    list_artifacts, read_artifact = create_artifact_tools(workspace_registry)

    arts = list_artifacts("test-ws")
    names = [a["name"] for a in arts]
    assert "report.txt" in names
    assert "plot.png" in names

    # Read text artifact
    txt_art = read_artifact("test-ws", "artifacts/report.txt")
    assert txt_art["type"] == "text"
    assert "Test run report artifact content" in txt_art["content"]

    # Read image artifact
    img_art = read_artifact("test-ws", "artifacts/plot.png")
    assert img_art["type"] == "image"
    assert "base64_data" in img_art
    assert img_art["mime_type"] == "image/png"


@pytest.mark.skipif(not shutil.which("bwrap"), reason="Bubblewrap not available")
def test_async_job_lifecycle(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    job_mgr = JobManager(tmp_path / "state")
    _, exec_start = create_execution_tools(workspace_registry, sandbox, job_mgr)

    start_res = exec_start("test-ws", ["bash", "-c", "echo 'async job started'; sleep 0.1; echo 'async job finished'"])
    job_id = start_res["job_id"]

    # Wait for job completion
    for _ in range(50):
        st = job_mgr.get_status(job_id)
        if st["status"] in ("completed", "failed", "timed_out"):
            break
        time.sleep(0.05)

    assert st["status"] == "completed"
    res = job_mgr.get_result(job_id)
    assert "async job started" in res["stdout"]
    assert "async job finished" in res["stdout"]


@pytest.mark.skipif(not shutil.which("bwrap"), reason="Bubblewrap not available")
def test_async_job_cancel(workspace_registry, tmp_path: Path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    job_mgr = JobManager(tmp_path / "state")
    _, exec_start = create_execution_tools(workspace_registry, sandbox, job_mgr)

    start_res = exec_start("test-ws", ["sleep", "30"])
    job_id = start_res["job_id"]

    cancel_res = job_mgr.cancel(job_id)
    assert cancel_res["status"] == "cancelled"

    st = job_mgr.get_status(job_id)
    assert st["status"] == "cancelled"


def test_agent_broker_listing(workspace_registry, tmp_path: Path):
    job_mgr = JobManager(tmp_path / "state")
    broker = AgentBroker(workspace_registry, job_mgr)
    agents = broker.list_agents()
    agent_names = [a["agent"] for a in agents]

    assert "codex" in agent_names
    assert "claude" in agent_names
    assert "opencode" in agent_names
    assert "agy" in agent_names

    for ag in agents:
        assert "configured_model" in ag
        assert "actual_model_used" in ag
        assert "cli_version" in ag
        assert ag["actual_model_used"] == "unknown (resolved at runtime per dispatch)"


def test_dispatch_agent_telemetry(workspace_registry, tmp_path: Path):
    job_mgr = JobManager(tmp_path / "state")
    broker = AgentBroker(workspace_registry, job_mgr)
    list_ag, dispatch_ag = create_agent_tools(broker)

    res = dispatch_ag(
        agent="codex",
        task="echo test",
        workspace_id="test-ws",
        purpose="unit test"
    )

    assert res["worker_cli"] == "codex"
    assert res["provider"] == "OpenAI"
    assert res["requested_model"]
    assert res["actual_model"] == "unknown"
    assert res["reasoning_level"]
    assert res["cli_version"] != "unknown"
    assert res["job_id"].startswith("job_")
    assert res["exit_status"] is None
    assert res["duration"] == 0.0

    job_mgr.cancel(res["job_id"])
