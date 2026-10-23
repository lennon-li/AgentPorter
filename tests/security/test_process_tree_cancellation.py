"""Cancellation must end descendants before terminal state or admission reuse."""
import os
from pathlib import Path
import signal
import threading
import time

import pytest

from agentporter.admission import synchronous_slot
from agentporter.resources import JobCapacityError, ResourceCleanupError, ResourceLease
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager


def wait_for(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('Expected bounded lifecycle transition did not occur')


def assert_heartbeat_stopped(path):
    # These native fixtures deliberately have no delegated cgroup. Reaping
    # bwrap can precede the kernel's last namespace teardown write. Bound that
    # drain, then check a stable interval longer than the child's write period.
    deadline = time.monotonic() + 1
    value = path.read_text()
    unchanged_since = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(.02)
        current = path.read_text()
        if current != value:
            value, unchanged_since = current, time.monotonic()
        if time.monotonic() - unchanged_since >= .1:
            time.sleep(.12)
            assert path.read_text() == value
            return
    raise AssertionError('Namespace descendant heartbeat did not stop within one second')


@pytest.mark.parametrize('leader_exits,close_pipes', [(False, False), (True, False), (False, True)])
def test_native_cancellation_stops_setsid_descendant_with_inherited_pipes(tmp_path, leader_exits, close_pipes, monkeypatch):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:
        pytest.skip('Native Bubblewrap unavailable')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    manager = JobManager(tmp_path / 'state', max_active_jobs=1)
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox')
    # setsid escapes a process group, not the sandbox PID namespace. The child
    # retains both pipes and writes a heartbeat so leader-only exit is not proof.
    code = '''import os,time,pathlib
if CLOSE_PIPES:
 os.close(1);os.close(2)
pid=os.fork()
if pid==0:
 os.setsid()
 p=pathlib.Path('/workspace/heartbeat')
 while True:
  p.write_text(str(time.monotonic_ns()))
  time.sleep(.02)
while not pathlib.Path('/workspace/heartbeat').exists():time.sleep(.005)
if LEADER_EXITS:os._exit(0)
time.sleep(30)
'''.replace('LEADER_EXITS', repr(leader_exits)).replace('CLOSE_PIPES', repr(close_pipes))
    command = sandbox.build_bwrap_args(str(workspace)) + ['--', 'python3', '-I', '-c', code]
    job = manager.start_raw_job('test', str(workspace), command, timeout_seconds=20)
    try:
        wait_for(lambda: (workspace / 'heartbeat').exists())
        if leader_exits:
            # Bubblewrap tears down its PID namespace when the main worker
            # exits. Observe that natural completion before requesting cancel;
            # cancellation of an already completed job must stay completed.
            wait_for(lambda: manager.get_status(job)['status'] == 'completed')
        monkeypatch.setattr('agentporter.tools.jobs.os.killpg', lambda *a: pytest.fail('Numeric PGID used'))
        started = time.monotonic()
        assert manager.cancel(job)['status'] == ('completed' if leader_exits else 'cancelled')
        assert time.monotonic() - started < 3
        assert_heartbeat_stopped(workspace / 'heartbeat')
        status = manager.get_status(job)
        assert status['exit_code'] == (0 if leader_exits else 130) and status['finished_at'] is not None
        def capacity_released():
            db = manager._get_db()
            try:return db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0
            finally:db.close()
        wait_for(capacity_released)
        with synchronous_slot(manager):
            pass
    finally:
        with manager.lock:
            proc = manager.active_processes.get(job)
        if proc is not None:
            manager._terminate_process_tree(proc)


def test_cancel_requests_tree_termination_before_waiting_for_monitor(tmp_path, monkeypatch):
    """A paused monitor cannot defer the envelope kill until pipe EOF."""
    import subprocess
    from agentporter.process_handles import open_handle, signal_handle
    manager = JobManager(tmp_path)
    proc = subprocess.Popen(['/bin/sleep', '20'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc._agentporter_pidfd = open_handle(proc.pid)
    proc._agentporter_stop = threading.Event()
    calls = []
    class Envelope:
        def terminate(self):
            calls.append('tree')
            assert manager.get_status('synthetic')['status'] == 'cancelling'
            assert proc._agentporter_stop.is_set()
        def close(self):
            calls.append('close')
    with manager.lock:
        manager.active_processes['synthetic'] = proc
        manager._resource_leases[proc] = Envelope()
    db = manager._get_db()
    with db:
        db.execute("INSERT INTO jobs (job_id,pid,status) VALUES ('synthetic',?,'running')", (proc.pid,))
    db.close()
    original_signal = signal_handle
    def signal_and_finish(fd, sig):
        assert calls == ['tree']
        original_signal(fd, sig)
        db = manager._get_db()
        with db:
            db.execute("UPDATE jobs SET status='cancelled' WHERE job_id='synthetic'")
        db.close()
    monkeypatch.setattr('agentporter.tools.jobs.signal_handle', signal_and_finish)
    try:
        assert manager.cancel('synthetic')['status'] == 'cancelled'
        assert calls == ['tree']
    finally:
        try:
            original_signal(proc._agentporter_pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)
        manager._close_pidfd(proc)
        proc.stdout.close()
        proc.stderr.close()


def test_termination_and_cleanup_are_serialized_and_idempotent(tmp_path, monkeypatch):
    (tmp_path / 'cgroup.events').write_text('populated 0\n')
    lease = ResourceLease(tmp_path)
    calls = []
    original_write = Path.write_text
    def write(path, text, *a, **kw):
        if path.name == 'cgroup.kill':
            calls.append(text)
        return original_write(path, text, *a, **kw)
    monkeypatch.setattr(Path, 'write_text', write)
    monkeypatch.setattr(Path, 'rmdir', lambda path: calls.append('removed'))
    lease.terminate()
    lease.close()
    lease.terminate()
    lease.close()
    assert calls == ['1', '1', 'removed']


def test_missing_envelope_is_not_cleanup_proof(tmp_path):
    with pytest.raises(ResourceCleanupError, match='disappeared'):
        ResourceLease(tmp_path / 'missing').close()


@pytest.mark.parametrize('limit', ['timeout', 'output'])
def test_native_synchronous_tree_stops_without_numeric_pgid(tmp_path, monkeypatch, limit):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:
        pytest.skip('Native Bubblewrap unavailable')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox', max_output_bytes=1024)
    monkeypatch.setattr('agentporter.sandbox.bubblewrap.os.killpg', lambda *a: pytest.fail('Numeric PGID used'))
    code = '''import os,time,pathlib
if os.fork()==0:
 os.setsid()
 while True:
  pathlib.Path('/workspace/heartbeat').write_text(str(time.monotonic_ns()))
  time.sleep(.01)
while not pathlib.Path('/workspace/heartbeat').exists():time.sleep(.005)
if OUTPUT:
 while True:os.write(1,b'x'*4096)
time.sleep(30)
'''.replace('OUTPUT', repr(limit == 'output'))
    started = time.monotonic()
    result = sandbox.run(str(workspace), ['python3', '-I', '-c', code], timeout_seconds=1)
    assert result['exit_code'] == (124 if limit == 'timeout' else 125)
    assert time.monotonic() - started < 4
    assert_heartbeat_stopped(workspace / 'heartbeat')


def test_kernel_control_io_failure_keeps_cleanup_unknown(tmp_path, monkeypatch):
    lease = ResourceLease(tmp_path)
    monkeypatch.setattr(Path, 'write_text', lambda *a, **kw: (_ for _ in ()).throw(OSError('synthetic EIO')))
    with pytest.raises(ResourceCleanupError):
        lease.terminate()
    with pytest.raises(ResourceCleanupError):
        lease.close()


def test_exited_launcher_does_not_skip_tree_termination(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    calls = []
    class Process:
        pid = 123
        _agentporter_pidfd = os.open('/dev/null', os.O_RDONLY)
    class Lease:
        def terminate(self):
            calls.append('tree')
    proc = Process()
    manager._resource_leases[proc] = Lease()
    def exited(fd, sig):
        calls.append('exited_launcher')
        raise ProcessLookupError('leader already exited')
    monkeypatch.setattr('agentporter.tools.jobs.signal_handle', exited)
    try:
        manager._terminate_process_tree(proc)
        assert calls == ['tree', 'exited_launcher']
    finally:
        manager._close_pidfd(proc)


def test_reused_numeric_pid_cannot_select_another_process_lease(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    seen = []
    class Process:
        pid = 123  # Simulate reuse while the old object still awaits cleanup.
        def __init__(self):
            self._agentporter_pidfd = os.open('/dev/null', os.O_RDONLY)
    class Lease:
        def __init__(self, name):self.name = name
        def terminate(self):seen.append(('terminate', self.name))
        def close(self):seen.append(('close', self.name))
    first, second = Process(), Process()
    manager._resource_leases[first] = Lease('first')
    manager._resource_leases[second] = Lease('second')
    monkeypatch.setattr('agentporter.tools.jobs.signal_handle', lambda *a: None)
    try:
        manager._terminate_process_tree(first)
        manager._drop_lease(first)
        assert manager._resource_leases[second].name == 'second'
        assert seen == [('terminate', 'first'), ('close', 'first')]
        manager._terminate_process_tree(second)
        manager._drop_lease(second)
        assert seen[-2:] == [('terminate', 'second'), ('close', 'second')]
    finally:
        manager._close_pidfd(first)
        manager._close_pidfd(second)


def test_failed_tree_kill_still_signals_owned_leader(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    seen = []
    class Process:
        pid = 123
        _agentporter_pidfd = os.open('/dev/null', os.O_RDONLY)
    class Lease:
        def terminate(self):
            seen.append('tree_failed')
            raise ResourceCleanupError('synthetic kill failure')
    proc = Process()
    manager._resource_leases[proc] = Lease()
    monkeypatch.setattr('agentporter.tools.jobs.signal_handle', lambda *a: seen.append('leader'))
    try:
        with pytest.raises(ResourceCleanupError):
            manager._terminate_process_tree(proc)
        assert seen == ['tree_failed', 'leader']
    finally:
        manager._close_pidfd(proc)
