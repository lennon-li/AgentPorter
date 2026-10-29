"""Negative tests for forbidden host-user launches and generic execution."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.broker import AgentBroker
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.jobs import JobManager
from tests._support import BWRAP_USABLE


def test_raw_job_refuses_agent_before_popen(tmp_path):
    mgr = JobManager(tmp_path / "state")
    with pytest.raises(PermissionError, match="unconfined"):
        mgr.start_raw_job(
            "demo", str(tmp_path), ["python3", "-c", "print('bad')"],
            agent="jax",
        )
    assert not list(mgr.jobs_dir.glob("*.stdout.log"))


@pytest.mark.parametrize("read_only", [True, False])
def test_broker_refuses_host_worker_without_kernel_confinement(tmp_path, read_only):
    job_manager = JobManager(tmp_path / "state")
    workspace = SimpleNamespace(
        path=str(tmp_path), writable=True, allow_agent_dispatch=True
    )
    broker = AgentBroker(
        SimpleNamespace(get=lambda _: workspace), job_manager,
        config_dir=tmp_path,
    )
    adapter = broker.adapters["jax"]
    adapter.detect = lambda: {"is_installed": True, "provider": "OpenAI", "configured_model": "gpt-6.1-sol"}
    with pytest.raises(PermissionError, match="OS-confined agent launcher"):
        broker.dispatch_agent("jax", "No host launch", "demo", read_only=read_only)


def test_inventory_distinguishes_installed_from_authorized(tmp_path):
    broker = AgentBroker(SimpleNamespace(), Mock(), config_dir=tmp_path)
    rows = broker.list_agents()
    assert rows
    assert all(row["delegatable"] is False for row in rows)
    assert all(row["confinement_status"] == "blocked_pending_os_confinement" for row in rows)


def test_generic_network_execution_refused_even_if_requested(tmp_path):
    sandbox = BubblewrapSandbox(tmp_path / "state")
    with pytest.raises(PermissionError, match="Networked generic execution"):
        sandbox.build_bwrap_args(str(tmp_path), network_access=True)
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_execute=True)
    exec_run, exec_start = create_execution_tools(SimpleNamespace(get=lambda _: ws), sandbox, Mock())
    with pytest.raises(PermissionError, match="Networked generic execution"):
        exec_run("demo", ["echo", "hello"], network_access=True)
    with pytest.raises(PermissionError, match="Networked generic execution"):
        exec_start("demo", ["echo", "hello"], network_access=True)


def test_generic_bwrap_does_not_expose_ssh_gh_or_gitconfig(tmp_path):
    sb = BubblewrapSandbox(tmp_path / "state")
    argv = sb.build_bwrap_args(str(tmp_path), network_access=False)
    for forbidden in ("/tmp/.ssh", "/tmp/.config/gh", "SSH_AUTH_SOCK", "/tmp/.gitconfig", "--share-net"):
        assert forbidden not in argv
    assert "--unshare-net" in argv


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap namespaces unavailable")
def test_generic_writable_workspace_cannot_change_git_control(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / ".git").mkdir()
    (ws / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    sb = BubblewrapSandbox(tmp_path / "state")
    result = sb.run(
        str(ws),
        ["python3", "-c",
         "from pathlib import Path; "
         "Path('/workspace/edited.txt').write_text('ok'); "
         "Path('/workspace/.git/HEAD').write_text('tampered')"],
        writable=True,
    )
    assert result["exit_code"] != 0
    assert not (ws / "edited.txt").exists()
    assert (ws / ".git" / "HEAD").read_text() == "ref: refs/heads/main\n"

def test_broker_must_use_confined_launcher_not_raw_job(tmp_path):
    """Even a mock 'confined' backend must never hit the raw worker path."""
    jobs = Mock()
    jobs.start_confined_agent_job.return_value = "confined-fixture"
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    broker = AgentBroker(SimpleNamespace(get=lambda _: ws), jobs, config_dir=tmp_path)
    adapter = broker.adapters["jax"]
    adapter.detect = lambda: {
        "is_installed": True, "provider": "OpenAI", "configured_model": "gpt-6.1-sol"
    }
    adapter.executable_override = "/bin/true"
    # A fixture-only backend tests routing, NOT actual containment.
    result = broker.dispatch_agent("jax", "fixture", "repo", read_only=True)
    assert result["job_id"] == "confined-fixture"
    jobs.start_confined_agent_job.assert_called_once()
    assert jobs.start_confined_agent_job.call_args.kwargs["policy"].workspace_write is False
    jobs.start_raw_job.assert_not_called()

def test_unlabeled_host_raw_process_is_also_rejected(tmp_path):
    """No metadata-free path to launch a host Python interpreter."""
    mgr = JobManager(tmp_path / "state")
    with pytest.raises(PermissionError, match="Raw host process execution"):
        mgr.start_raw_job(
            "demo", str(tmp_path), ["python3", "-c", "print('not run')"],
        )
    assert not list(mgr.jobs_dir.glob("*.stdout.log"))


def test_raw_job_rejects_fake_bwrap_with_network_share(tmp_path):
    mgr = JobManager(tmp_path / "state")
    cmd = ["bwrap", "--die-with-parent", "--unshare-all", "--share-net",
           "--clearenv", "--bind", str(tmp_path.resolve()),
           "/workspace", "--", "python3", "-c", "print('not run')"]
    with pytest.raises(PermissionError, match="network permissions"):
        mgr.start_raw_job("demo", str(tmp_path), cmd)
    assert not list(mgr.jobs_dir.glob("*.stdout.log"))


def test_async_launcher_uses_trusted_absolute_bwrap_before_scrubbing_path(tmp_path, monkeypatch):
    """A host-resolved bwrap outside /usr/bin must still launch under a safe PATH."""
    from agentporter.tools import jobs as job_module

    location = "/opt/test-profile/bin/bwrap"
    monkeypatch.setattr(job_module.shutil, "which", lambda name: location if name == "bwrap" else None)
    calls = []

    def capture_launch(cmd, **kwargs):
        calls.append((cmd, kwargs))
        raise RuntimeError("intentionally intercepted before host execution")

    monkeypatch.setattr(job_module.subprocess, "Popen", capture_launch)
    manager = JobManager(tmp_path / "state")
    command = ["bwrap", "--die-with-parent", "--unshare-all", "--unshare-net",
               "--clearenv", "--bind", str(tmp_path.resolve()), "/workspace",
               "--", "echo", "safe"]
    with pytest.raises(RuntimeError, match="intentionally intercepted"):
        manager.start_raw_job("demo", str(tmp_path), command)
    assert len(calls) == 1
    assert calls[0][0][0] == location
    assert calls[0][0][1:] == command[1:]
    assert calls[0][1]["env"]["PATH"] == "/usr/bin:/bin"


def test_async_launcher_does_not_accept_arbitrary_host_binary(tmp_path, monkeypatch):
    from agentporter.tools import jobs as job_module
    monkeypatch.setattr(job_module.shutil, "which", lambda name: "/opt/test-profile/bin/bwrap")
    manager = JobManager(tmp_path / "state")
    with pytest.raises(PermissionError, match="Bubblewrap required"):
        manager.start_raw_job("demo", str(tmp_path), ["python3", "-c", "print(1)"])
