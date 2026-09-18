"""Shared pytest fixtures for AgentPorter."""

import os
import shutil
import subprocess
import pytest
from pathlib import Path
from agentporter.config import Config
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager
from agentporter.agents.broker import AgentBroker


@pytest.fixture
def temp_config(tmp_path: Path) -> Config:
    """Provide an isolated Config instance with temporary directories."""
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    cache_dir = tmp_path / "cache"
    return Config(config_dir=config_dir, state_dir=state_dir, cache_dir=cache_dir)


@pytest.fixture
def sample_workspace(tmp_path: Path) -> Path:
    """Create a temporary git-initialized workspace with sample files."""
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=ws, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "AgentPorter Test"], cwd=ws, check=True)
    subprocess.run(["git", "config", "user.email", "test@agentporter.local"], cwd=ws, check=True)

    # README.md
    readme = ws / "README.md"
    readme.write_text("# AgentPorter Test Workspace\nLine 2 content\nLine 3 content\n")

    # Python sample
    py_dir = ws / "python"
    py_dir.mkdir()
    py_file = py_dir / "stats.py"
    py_file.write_text(
        "def compute_mean(numbers):\n"
        "    if not numbers:\n"
        "        return 0.0\n"
        "    return sum(numbers) / len(numbers)\n"
    )

    # R sample
    r_dir = ws / "R"
    r_dir.mkdir()
    r_file = r_dir / "stats.R"
    r_file.write_text(
        "compute_mean <- function(x) {\n"
        "  if (length(x) == 0) return(NA_real_)\n"
        "  sum(x) / length(x)\n"
        "}\n"
    )

    # Artifacts sample
    art_dir = ws / "artifacts"
    art_dir.mkdir()
    (art_dir / "report.txt").write_text("Test run report artifact content.")
    # Minimal 1x1 png image
    tiny_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc`\x00\x00"
        b"\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    (art_dir / "plot.png").write_bytes(tiny_png)

    # Initial commit
    subprocess.run(["git", "add", "."], cwd=ws, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=ws, capture_output=True, check=True)

    return ws


@pytest.fixture
def workspace_registry(sample_workspace: Path) -> WorkspaceRegistry:
    reg = WorkspaceRegistry()
    reg.register(
        ws_id="test-ws",
        path=str(sample_workspace),
        writable=True,
        description="Sample test workspace"
    )
    return reg
