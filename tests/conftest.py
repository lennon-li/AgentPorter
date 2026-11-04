"""Shared pytest fixtures for AgentPorter."""

import os
import subprocess
import pytest
from pathlib import Path
from agentporter.config import Config
from agentporter.workspaces.registry import WorkspaceRegistry
from tests._support import BWRAP_USABLE


def pytest_collection_modifyitems(config, items):
    """Skip native sandbox integration tests when namespaces are unavailable."""
    if BWRAP_USABLE:
        return

    native_bwrap_modules = {
        "test_git_raw.py",
        "test_native_ref_recovery.py",
        "test_repository_birth.py",
        "test_tracking_metadata.py",
        "test_clone_job_control.py",
        "test_clone_preparation.py",
        "test_clone_service.py",
        "test_foreign_git_fd_scope.py",
        "test_git_snapshot_budget.py",
        "test_git_workspace_ownership.py",
        "test_nested_repository_scope.py",
        "test_owner_clone_protocol.py",
        "test_readonly_projection_runtime.py",
        "test_relay_owned_cancellation.py",
        "test_worker_git_runtime.py",
        "test_workspace_git_authorization.py",
        "test_workspace_git_commits.py",
        "test_workspace_git_rpc.py",
    }
    security_dir = Path(__file__).parent / "security"
    skip = pytest.mark.skip(reason="Bubblewrap namespaces unavailable on this runner")
    for item in items:
        if not item.path.is_relative_to(security_dir):
            continue
        test_name = item.name.split("[", 1)[0]
        if item.path.name in native_bwrap_modules or (
            item.path.name == "test_development_runtime.py"
            and (
                test_name.startswith("test_real_")
                or test_name == "test_full_job_launch_uses_the_operator_selected_sandbox"
            )
        ):
            item.add_marker(skip)


@pytest.fixture(scope='session', autouse=True)
def select_native_test_sandbox():
    """Select the trusted binary before module-scoped native fixtures run."""
    with pytest.MonkeyPatch.context() as patch:
        if sandbox := os.environ.get('AGENTPORTER_TEST_BWRAP'):
            patch.setenv('AGENTPORTER_SANDBOX_EXECUTABLE', sandbox)
        yield


@pytest.fixture(autouse=True)
def isolate_agent_identities(tmp_path, monkeypatch):
    """Source tests must never consume the host's private identity registry."""
    monkeypatch.setenv("AGENTPORTER_CONFIG_DIR", str(tmp_path / "agent-config"))
    monkeypatch.setenv("AGENTPORTER_STATE_DIR", str(tmp_path / "agent-state"))
    monkeypatch.setenv("AGENTPORTER_CACHE_DIR", str(tmp_path / "agent-cache"))


@pytest.fixture
def temp_config(tmp_path: Path) -> Config:
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    cache_dir = tmp_path / "cache"
    return Config(config_dir=config_dir, state_dir=state_dir, cache_dir=cache_dir)


@pytest.fixture
def sample_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init"], cwd=ws, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "AgentPorter Test"], cwd=ws, check=True)
    subprocess.run(["git", "config", "user.email", "test@agentporter.local"], cwd=ws, check=True)

    (ws / "README.md").write_text(
        "# AgentPorter Test Workspace\nLine 2 content\nLine 3 content\n"
    )

    py_dir = ws / "python"
    py_dir.mkdir()
    (py_dir / "stats.py").write_text(
        "def compute_mean(numbers):\n"
        "    if not numbers:\n"
        "        return 0.0\n"
        "    return sum(numbers) / len(numbers)\n"
    )

    r_dir = ws / "R"
    r_dir.mkdir()
    (r_dir / "stats.R").write_text(
        "compute_mean <- function(x) {\n"
        "  if (length(x) == 0) return(NA_real_)\n"
        "  sum(x) / length(x)\n"
        "}\n"
    )

    art_dir = ws / "artifacts"
    art_dir.mkdir()
    (art_dir / "report.txt").write_text("Test run report artifact content.")
    tiny_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc`\x00\x00"
        b"\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    (art_dir / "plot.png").write_bytes(tiny_png)

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
        description="Sample test workspace",
        allow_execute=True,
        allow_git=True,
        allow_artifacts=True,
        allow_agent_dispatch=True,
        local_http_ports=[54321],
    )
    return reg
