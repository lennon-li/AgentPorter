import os
from pathlib import Path
import threading
import time

import pytest
from agentporter.tools.jobs import JobManager
from agentporter.admission import execution_slot, synchronous_slot, release
from agentporter.resources import JobCapacityError, JobResources, ResourceCleanupError, ResourceLease
from agentporter.sandbox.bubblewrap import BubblewrapSandbox


def test_global_slots_are_shared_across_managers_and_released(tmp_path):
    first=JobManager(tmp_path,max_active_jobs=1)
    second=JobManager(tmp_path,max_active_jobs=1)
    with synchronous_slot(first):
        with pytest.raises(JobCapacityError):
            with synchronous_slot(second): pytest.fail('Overcommitted')
    with synchronous_slot(second): pass
    with pytest.raises(ValueError):
        with synchronous_slot(first): raise ValueError('synthetic failure')
    with synchronous_slot(second): pass


def test_unknown_cleanup_keeps_capacity_after_restart(tmp_path):
    manager=JobManager(tmp_path,max_active_jobs=1)
    with pytest.raises(ResourceCleanupError):
        with synchronous_slot(manager): raise ResourceCleanupError('synthetic descendants')
    restarted=JobManager(tmp_path,max_active_jobs=1)
    with pytest.raises(JobCapacityError):
        with synchronous_slot(restarted):pytest.fail('Lost durable capacity')


def test_failed_launch_does_not_consume_capacity(tmp_path):
    manager=JobManager(tmp_path,max_active_jobs=1)
    with pytest.raises(PermissionError):manager.start_raw_job('test',str(tmp_path),['false'])
    with synchronous_slot(manager):pass


def test_async_budget_and_post_terminal_reuse(tmp_path):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:pytest.skip('Native Bubblewrap unavailable')
    manager=JobManager(tmp_path/'state',max_active_jobs=1)
    sandbox=BubblewrapSandbox(tmp_path/'sandbox')
    def start(code):
        cmd=sandbox.build_bwrap_args(str(tmp_path),writable=False)+['--','python3','-I','-c',code]
        return manager.start_raw_job('test',str(tmp_path),cmd,timeout_seconds=2)
    job=start('import time;time.sleep(.3)')
    with pytest.raises(JobCapacityError):start('print(1)')
    deadline=time.monotonic()+4
    while manager.get_status(job)['status']=='running' and time.monotonic()<deadline:time.sleep(.01)
    assert manager.get_status(job)['status']=='completed'
    with synchronous_slot(manager):pass


def test_resource_envelope_rejects_absent_delegation():
    with pytest.raises(PermissionError,match='DelegateSubgroup'):
        JobResources({'memory_bytes':4*1024**3,'pids':128,'cpu_quota_us':200000,'cpu_period_us':100000})


def test_terminal_status_and_capacity_release_are_atomic(tmp_path, monkeypatch):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:
        pytest.skip('Native Bubblewrap unavailable')
    manager = JobManager(tmp_path / 'state', max_active_jobs=1)
    observer = JobManager(tmp_path / 'state', max_active_jobs=1)
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox')
    finish = threading.Event()

    def delayed_release(*args, **kwargs):
        assert finish.wait(5)
        return release(*args, **kwargs)

    # Hold any separate post-commit release open, making the old race
    # deterministic. A terminal status must already permit another manager
    # to reserve capacity without waiting for the monitor's next operation.
    monkeypatch.setattr('agentporter.tools.jobs.release', delayed_release, raising=False)
    command = sandbox.build_bwrap_args(str(tmp_path), writable=False) + [
        '--', 'python3', '-I', '-c', 'import time;time.sleep(.3)']
    try:
        job = manager.start_raw_job('test', str(tmp_path), command, timeout_seconds=5)
        deadline = time.monotonic() + 5
        while observer.get_status(job)['status'] == 'running' and time.monotonic() < deadline:
            time.sleep(.01)
        assert observer.get_status(job)['status'] == 'completed'
        with synchronous_slot(observer):
            pass
    finally:
        finish.set()


def test_cpu_memory_process_limits_are_written_before_launch(tmp_path,monkeypatch):
    resources=object.__new__(JobResources)
    resources.root=tmp_path
    resources.settings={'memory_bytes':4*1024**3,'pids':128,'cpu_quota_us':200000,'cpu_period_us':100000}
    lease=resources.create()
    assert (lease.path/'memory.max').read_text()=='4294967296'
    assert (lease.path/'memory.swap.max').read_text()=='0'
    assert (lease.path/'memory.oom.group').read_text()=='1'
    assert (lease.path/'pids.max').read_text()=='128'
    assert (lease.path/'cpu.max').read_text()=='200000 100000'
    command=lease.command(['/usr/bin/bwrap','--unshare-all'])
    assert command[-2:]==['/usr/bin/bwrap','--unshare-all']
    assert str(lease.path) in command


def test_populated_envelope_cannot_be_reported_clean(tmp_path,monkeypatch):
    (tmp_path/'cgroup.events').write_text('populated 1\n')
    clock=iter([0,3])
    monkeypatch.setattr('agentporter.resources.time.monotonic',lambda:next(clock))
    with pytest.raises(ResourceCleanupError):ResourceLease(tmp_path).close()
    assert (tmp_path/'cgroup.kill').read_text()=='1'
    assert tmp_path.exists()


def test_restart_cannot_cancel_a_persisted_pid(tmp_path,monkeypatch):
    manager=JobManager(tmp_path)
    db=manager._get_db()
    with db:
        db.execute("INSERT INTO jobs (job_id,pid,pgid,status) VALUES ('old',1234,1234,'running')")
    db.close()
    monkeypatch.setattr('agentporter.tools.jobs.os.killpg',lambda *args:pytest.fail('Signalled persisted PGID'))
    with pytest.raises(PermissionError,match='owned live process handle'):manager.cancel('old')


def test_native_job_cancel_uses_owned_handle_and_releases_slot(tmp_path,monkeypatch):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:pytest.skip('Native Bubblewrap unavailable')
    manager=JobManager(tmp_path/'state',max_active_jobs=1)
    sandbox=BubblewrapSandbox(tmp_path/'sandbox')
    command=sandbox.build_bwrap_args(str(tmp_path),writable=False)+['--','python3','-I','-c','import time;time.sleep(10)']
    job=manager.start_raw_job('test',str(tmp_path),command,timeout_seconds=15)
    monkeypatch.setattr('agentporter.tools.jobs.os.killpg',lambda *args:pytest.fail('Signalled numeric PGID'))
    assert manager.cancel(job)['status']=='cancelled'
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        db=manager._get_db();count=db.execute('SELECT count(*) FROM job_admissions').fetchone()[0];db.close()
        if not count:break
        time.sleep(.01)
    assert count==0


def test_startup_recovery_only_releases_capacity_after_envelope_cleanup(tmp_path):
    from types import SimpleNamespace
    manager=JobManager(tmp_path,max_active_jobs=1)
    db=manager._get_db()
    with db:
        db.execute("INSERT INTO jobs (job_id,status,started_at) VALUES ('old','running',?)",(time.time()-10,))
        db.execute("INSERT INTO job_admissions VALUES ('reservation','old',123,?)",(time.time()-10,))
    db.close()
    def fail_recovery():raise ResourceCleanupError('Unverified envelope')
    with pytest.raises(ResourceCleanupError):manager.configure_resources(SimpleNamespace(recover=fail_recovery))
    assert manager.get_status('old')['status']=='running'
    with pytest.raises(JobCapacityError):
        with synchronous_slot(manager):pytest.fail('Freed before cleanup')
    manager.configure_resources(SimpleNamespace(recover=lambda:None))
    status=manager.get_status('old')
    assert status['status']=='interrupted' and status['exit_code']==130
    assert 9<=status['duration']<=15
    with synchronous_slot(manager):pass


def test_cancelled_job_with_failed_cleanup_retains_failed_state_and_capacity(tmp_path):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:pytest.skip('Native Bubblewrap unavailable')
    manager=JobManager(tmp_path/'state',max_active_jobs=1)
    sandbox=BubblewrapSandbox(tmp_path/'sandbox')
    command=sandbox.build_bwrap_args(str(tmp_path),writable=False)+['--','python3','-I','-c','import time;time.sleep(10)']
    job=manager.start_raw_job('test',str(tmp_path),command,timeout_seconds=15)
    class UnverifiedEnvelope:
        def terminate(self):pass
        def close(self):raise ResourceCleanupError('Synthetic cleanup failure')
    with manager.lock:
        proc=manager.active_processes[job]
        manager._resource_leases[proc]=UnverifiedEnvelope()
    manager.cancel(job)
    deadline=time.monotonic()+3
    while manager.get_status(job)['status']=='cancelled' and time.monotonic()<deadline:time.sleep(.01)
    assert manager.get_status(job)['status']=='cleanup_failed'
    with pytest.raises(JobCapacityError):
        with synchronous_slot(manager):pytest.fail('Released unresolved cancellation')


def test_pending_cancellation_is_not_terminal_cleanup_proof(tmp_path):
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE:pytest.skip('Native Bubblewrap unavailable')
    manager=JobManager(tmp_path/'state',max_active_jobs=1)
    sandbox=BubblewrapSandbox(tmp_path/'sandbox')
    command=sandbox.build_bwrap_args(str(tmp_path),writable=False)+['--','python3','-I','-c','import time;time.sleep(10)']
    job=manager.start_raw_job('test',str(tmp_path),command,timeout_seconds=15)
    entered=threading.Event();finish=threading.Event();replies=[]
    def slow_cleanup():
        entered.set();assert finish.wait(2)
    with manager.lock:manager._job_cleanups[job]=slow_cleanup
    thread=threading.Thread(target=lambda:replies.append(manager.cancel(job)))
    thread.start()
    try:
        assert entered.wait(1)
        status=manager.get_status(job)
        assert status['status']=='cancelling' and status['finished_at'] is None and status['exit_code'] is None
        with pytest.raises(JobCapacityError):
            with synchronous_slot(manager):pytest.fail('Released before cleanup finished')
    finally:
        finish.set();thread.join(3)
    assert not thread.is_alive() and replies[0]['status']=='cancelled'
    with synchronous_slot(manager):pass
