"""Queued jobs must finalize private edits before becoming terminal."""
import time
from pathlib import Path
import pytest
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager
from tests.security.test_workspace_transactions import RecordingResources

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='BCC overlay integration requires its installed sandbox')


def setup(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('original')
    sandbox = BubblewrapSandbox(tmp_path / 'state', transactional_writes=True)
    manager = JobManager(tmp_path / 'state')
    resources = RecordingResources()
    sandbox.resources = manager.resources = resources
    return root, sandbox, manager


def wait(manager, job_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        result = manager.get_status(job_id)
        if result['status'] not in {'running', 'cancelling', 'finalizing', 'queued'}:
            return result
        time.sleep(.01)
    raise AssertionError('job did not become terminal')


def start(manager, sandbox, root, script):
    return manager.start_transaction_job(sandbox=sandbox, workspace_id='project',
        workspace_path=str(root), argv=['/bin/sh', '-c', script], timeout_seconds=10)


def test_async_success_applies_edits_before_completed_status(tmp_path):
    root, sandbox, manager = setup(tmp_path)
    def before_cleanup():
        assert (root / 'ordinary').read_text() == 'original'
    manager.resources.lease.on_close = before_cleanup
    job_id = start(manager, sandbox, root, 'printf changed > /workspace/ordinary')
    result = wait(manager, job_id)
    assert result['status'] == 'completed', result
    assert (root / 'ordinary').read_text() == 'changed'
    assert manager.resources.lease.closed


def test_async_nested_git_ref_write_is_rejected(tmp_path):
    root, sandbox, manager = setup(tmp_path)
    refs = root / 'nested/.git/refs/heads'
    refs.mkdir(parents=True)
    (refs / 'main').write_text('canonical')
    result = wait(manager, start(manager, sandbox, root, 'printf bypass > /workspace/nested/.git/refs/heads/main'))
    assert result['status'] == 'failed'
    assert (refs / 'main').read_text() == 'canonical'


def test_async_failed_command_discards_edits(tmp_path):
    root, sandbox, manager = setup(tmp_path)
    result = wait(manager, start(manager, sandbox, root, 'printf changed > /workspace/ordinary; exit 7'))
    assert result['status'] == 'failed'
    assert result['exit_code'] == 7
    assert (root / 'ordinary').read_text() == 'original'


def test_accepted_cancellation_never_applies_edits(tmp_path):
    root, sandbox, manager = setup(tmp_path)
    job_id = start(manager, sandbox, root, 'printf changed > /workspace/ordinary; sleep 10')
    response = manager.cancel(job_id)
    assert response['status'] in {'cancelled', 'cancelling'}
    result = wait(manager, job_id)
    assert result['status'] == 'cancelled'
    assert (root / 'ordinary').read_text() == 'original'


def test_finalization_wins_race_without_accepting_cancellation(tmp_path, monkeypatch):
    import threading
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root, sandbox, manager = setup(tmp_path)
    entered = threading.Event()
    proceed = threading.Event()
    original = WorkspaceTransaction.publish
    def pause_publication(self):
        entered.set()
        assert proceed.wait(5)
        return original(self)
    monkeypatch.setattr(WorkspaceTransaction, 'publish', pause_publication)
    job_id = start(manager, sandbox, root, 'printf changed > /workspace/ordinary')
    try:
        assert entered.wait(5)
        assert manager.get_status(job_id)['status'] == 'finalizing'
        reply = manager.cancel(job_id)
        assert reply['status'] == 'finalizing'
        db = manager._get_db()
        try:
            assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 1
        finally:
            db.close()
        assert (root / 'ordinary').read_text() == 'original'
    finally:
        proceed.set()
    assert wait(manager, job_id)['status'] == 'completed'
    assert (root / 'ordinary').read_text() == 'changed'


def test_restart_keeps_uncertain_finalization_admission(tmp_path):
    manager = JobManager(tmp_path / 'state')
    db = manager._get_db()
    try:
        with db:
            db.execute("INSERT INTO jobs (job_id,status,created_at) VALUES ('job_uncertain','finalizing',?)", (time.time(),))
            db.execute("INSERT INTO job_admissions VALUES ('reserved','job_uncertain',0,?)", (time.time(),))
    finally:
        db.close()
    resources = RecordingResources()
    resources.recover = lambda: None
    manager.configure_resources(resources)
    assert manager.get_status('job_uncertain')['status'] == 'cleanup_failed'
    db = manager._get_db()
    try:
        assert db.execute("SELECT count(*) FROM job_admissions WHERE job_id='job_uncertain'").fetchone()[0] == 1
    finally:
        db.close()


def test_restart_does_not_clear_failed_publication_guard(tmp_path, monkeypatch):
    import os
    from agentporter.sandbox import workspace_transactions
    root, sandbox, manager = setup(tmp_path)
    def fail_application(*args, **kwargs):
        raise OSError('synthetic disk failure')
    monkeypatch.setattr(workspace_transactions, 'publish_workspace_file', fail_application)
    job_id = start(manager, sandbox, root, 'printf changed > /workspace/ordinary')
    assert wait(manager, job_id)['status'] == 'cleanup_failed'
    transaction = manager._job_transactions[job_id]
    assert transaction._pending.is_file()
    os.close(transaction._root_fd)
    os.close(transaction._lock)
    transaction._closed = True
    restarted = JobManager(manager.state_dir)
    resources = RecordingResources()
    resources.recover = lambda: None
    restarted.configure_resources(resources)
    try:
        assert restarted.get_status(job_id)['status'] == 'cleanup_failed'
        db = restarted._get_db()
        try:
            assert db.execute('SELECT count(*) FROM job_admissions WHERE job_id=?', (job_id,)).fetchone()[0] == 1
        finally:
            db.close()
        assert transaction._pending.is_file()
    finally:
        transaction._pending.unlink()
        internal_work = transaction.work / 'work'
        if internal_work.exists():
            internal_work.chmod(0o700)


def test_exec_start_tool_uses_transactional_launcher(tmp_path):
    from agentporter.tools.execution import create_execution_tools
    from agentporter.workspaces.registry import WorkspaceRegistry
    root, sandbox, manager = setup(tmp_path)
    registry = WorkspaceRegistry({'project': {'path': str(root), 'writable': True}})
    _, exec_start = create_execution_tools(registry, sandbox, manager)
    response = exec_start('project', ['/bin/sh', '-c', 'printf changed > /workspace/ordinary'])
    assert wait(manager, response['job_id'])['status'] == 'completed'
    assert (root / 'ordinary').read_text() == 'changed'


def test_readonly_exec_start_masks_secrets_and_denies_project_writes(tmp_path):
    from agentporter.tools.execution import create_execution_tools
    from agentporter.workspaces.registry import WorkspaceRegistry
    root, sandbox, manager = setup(tmp_path)
    (root / '.envrc').write_text('synthetic-secret')
    registry = WorkspaceRegistry({'project': {'path': str(root), 'writable': False}})
    _, exec_start = create_execution_tools(registry, sandbox, manager)
    response = exec_start('project', ['/bin/sh', '-c', 'cat /workspace/.envrc; printf changed > /workspace/ordinary'])
    result = wait(manager, response['job_id'])
    assert result['status'] == 'failed'
    assert 'synthetic-secret' not in (manager.jobs_dir / (response['job_id'] + '.stdout.log')).read_text()
    assert (root / 'ordinary').read_text() == 'original'
