"""Asynchronous log budgets and process groups must hold under actual child output."""

import os
import signal
import sys
import time
from pathlib import Path

import pytest

from agentporter.tools.jobs import JobManager
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from tests._support import BWRAP_USABLE

pytestmark = pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap namespaces unavailable")


def _offline_sandbox_cmd(workspace: Path, code: str) -> list[str]:
    sandbox = BubblewrapSandbox(workspace / "sandbox-state")
    return sandbox.build_bwrap_args(str(workspace), writable=True) + [
        "--", "python3", "-B", "-c", code,
    ]


def _wait(mgr: JobManager, job_id: str, seconds: float = 6.0) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = mgr.get_status(job_id)
        if status["status"] != "running":
            return status
        time.sleep(0.025)
    raise AssertionError(f"Async job did not stop within {seconds}s")


@pytest.mark.parametrize("streams", ["stdout", "stderr", "both"])
def test_async_pipes_stop_unbounded_output_without_disk_overshoot(tmp_path, streams):
    budget = 2048
    mgr = JobManager(tmp_path / "state", max_log_bytes=budget)
    descriptor = {"stdout": [1], "stderr": [2], "both": [1, 2]}[streams]
    code = (
        "import os\n"
        f"descriptors={descriptor!r}\n"
        "while True:\n"
        " for fd in descriptors: os.write(fd, b'X' * 65536)\n"
    )
    job_id = mgr.start_raw_job(
        workspace_id="test", workspace_path=str(tmp_path),
        cmd=_offline_sandbox_cmd(tmp_path, code),
        timeout_seconds=5,
    )
    status = _wait(mgr, job_id)
    assert status["status"] == "output_limit_exceeded", status
    assert status["exit_code"] == 125
    assert status["duration"] < 4
    stdout_path = mgr.jobs_dir / f"{job_id}.stdout.log"
    stderr_path = mgr.jobs_dir / f"{job_id}.stderr.log"
    assert stdout_path.stat().st_size <= budget
    assert stderr_path.stat().st_size <= budget
    assert stdout_path.stat().st_size + stderr_path.stat().st_size > 0


def test_async_monitor_stops_descendant_after_leader_exits(tmp_path):
    """Reaping a PID-namespace leader cannot leave output pipes open indefinitely.

    When the sandbox's PID 1 exits, the kernel may immediately kill the
    descendant and close its inherited pipes: completed is then correct.
    On hosts that retain the pipes until the deadline, timed_out is correct.
    Either behavior must settle within the bounded deadline.
    """
    mgr = JobManager(tmp_path / "state", max_log_bytes=2048)
    code = (
        "import subprocess,sys\n"
        "p=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'])\n"
        "print(p.pid,flush=True)\n"
    )
    job_id = mgr.start_raw_job(
        workspace_id="test", workspace_path=str(tmp_path),
        cmd=_offline_sandbox_cmd(tmp_path, code),
        timeout_seconds=1,
    )
    status = _wait(mgr, job_id, seconds=5)
    assert status["status"] in {"completed", "timed_out"}, status
    assert status["exit_code"] == (0 if status["status"] == "completed" else 124)
    assert status["duration"] < 5, status
    output = (mgr.jobs_dir / f"{job_id}.stdout.log").read_text().strip()
    assert output.isdigit(), output
    # The child PID is in Bubblewrap's namespace. Never signal a host PID.


def test_async_descendant_held_by_live_leader_must_timeout(tmp_path):
    """Verify actual deadline/group-kill handling independently of PID 1 reaping."""
    mgr = JobManager(tmp_path / "state", max_log_bytes=2048)
    code = (
        "import subprocess,sys\n"
        "p=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'])\n"
        "print(p.pid,flush=True)\n"
        "p.wait()\n"
    )
    job_id = mgr.start_raw_job(
        workspace_id="test", workspace_path=str(tmp_path),
        cmd=_offline_sandbox_cmd(tmp_path, code),
        timeout_seconds=1,
    )
    status = _wait(mgr, job_id, seconds=5)
    assert status["status"] == "timed_out", status
    assert status["exit_code"] == 124, status
    assert status["duration"] < 5, status
    output = (mgr.jobs_dir / f"{job_id}.stdout.log").read_text().strip()
    assert output.isdigit(), output


def test_immediately_exiting_worker_does_not_need_getpgid(tmp_path, monkeypatch):
    mgr = JobManager(tmp_path / "state", max_log_bytes=2048)

    def fail_getpgid(pid):
        raise AssertionError("Popen(process_group=0) must use PID as PGID")

    monkeypatch.setattr("agentporter.tools.jobs.os.getpgid", fail_getpgid)
    job_id = mgr.start_raw_job(
        workspace_id="test", workspace_path=str(tmp_path),
        cmd=_offline_sandbox_cmd(tmp_path, "pass"),
        timeout_seconds=3,
    )
    status = _wait(mgr, job_id)
    assert status["status"] == "completed"
    assert status["exit_code"] == 0
