"""Owner recovery must finish only reviewed, quiescent publication plans."""
import os
from pathlib import Path
import pytest
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox import workspace_transactions as transactions
from agentporter.sandbox import workspace_recovery as recovery
from agentporter.tools.jobs import JobManager


def interrupted(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('original')
    manager = JobManager(tmp_path / 'state')
    transaction = transactions.WorkspaceTransaction(root, manager.state_dir / 'workspace-transactions')
    (transaction.upper / 'ordinary').write_text('changed')
    (transaction.upper / 'newdir').mkdir()
    (transaction.upper / 'newdir/newfile').write_text('new')
    def fail(*args, **kwargs):
        raise OSError('synthetic interruption')
    with monkeypatch.context() as patch:
        patch.setattr(transactions, 'publish_workspace_file', fail)
        with pytest.raises(ResourceCleanupError):
            transaction.publish()
    os.close(transaction._root_fd)
    os.close(transaction._lock)
    transaction._closed = True
    monkeypatch.setattr(recovery, '_verify_stopped_service', lambda: None)
    return root, manager, transaction


def test_owner_can_inspect_then_finish_reviewed_publication(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    plan = recovery.recover_workspace(manager.state_dir, root)
    assert {entry['state'] for entry in plan['files']} == {'pending'}
    assert (root / 'ordinary').read_text() == 'original'
    result = recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert result['status'] == 'recovered'
    assert (root / 'ordinary').read_text() == 'changed'
    assert (root / 'newdir/newfile').read_text() == 'new'
    assert not transaction._pending.exists()
    assert Path(result['receipt']).is_file()


def test_stale_review_hash_never_applies_changes(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256='0' * 64)
    assert (root / 'ordinary').read_text() == 'original'
    assert transaction._pending.exists()


def test_conflicting_owner_edit_is_preserved(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    (root / 'ordinary').write_text('owner edit')
    plan = recovery.recover_workspace(manager.state_dir, root)
    assert any(entry['state'] == 'conflict' for entry in plan['files'])
    with pytest.raises(PermissionError):
        recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert (root / 'ordinary').read_text() == 'owner edit'
    assert not (root / 'newdir/newfile').exists()
    assert transaction._pending.exists()


def test_already_applied_file_is_not_replaced_again(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    (root / 'ordinary').write_text('changed')
    before = (root / 'ordinary').stat().st_ino
    plan = recovery.recover_workspace(manager.state_dir, root)
    assert any(entry['state'] == 'applied' for entry in plan['files'])
    recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert (root / 'ordinary').stat().st_ino == before


def test_live_supervisor_lock_blocks_recovery(tmp_path, monkeypatch):
    import fcntl
    root, manager, _ = interrupted(tmp_path, monkeypatch)
    descriptor = os.open(manager.state_dir / 'job-supervisor.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(PermissionError):
            recovery.recover_workspace(manager.state_dir, root)
    finally:
        os.close(descriptor)


def test_changed_staged_contents_invalidate_owner_review(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    plan = recovery.recover_workspace(manager.state_dir, root)
    (transaction.upper / 'ordinary').write_text('changed after review')
    with pytest.raises(PermissionError):
        recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert (root / 'ordinary').read_text() == 'original'


def test_invalid_job_database_fails_before_file_application(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    plan = recovery.recover_workspace(manager.state_dir, root)
    manager.db_path.unlink()
    with pytest.raises((PermissionError, FileNotFoundError)):
        recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert (root / 'ordinary').read_text() == 'original'
    assert not (root / 'newdir/newfile').exists()
    assert transaction._pending.exists()


def test_recovery_releases_only_matching_job_admission(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    db = manager._get_db()
    try:
        with db:
            for job_id, directory in [('job_target', str(transaction.directory)), ('job_other', 'unrelated-transaction')]:
                db.execute("INSERT INTO jobs (job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES (?,'project','cleanup_failed','[]',0,?)", (job_id, directory))
                db.execute('INSERT INTO job_admissions VALUES (?,?,0,0)', (job_id + '_token', job_id))
    finally:
        db.close()
    plan = recovery.recover_workspace(manager.state_dir, root)
    recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert manager.get_status('job_target')['status'] == 'recovered'
    db = manager._get_db()
    try:
        remaining = db.execute('SELECT job_id FROM job_admissions').fetchall()
        assert [row[0] for row in remaining] == ['job_other']
    finally:
        db.close()


@pytest.mark.parametrize('suffix', ['.pending.json', '.git-pending.json'])
def test_other_pending_guard_keeps_unbound_admission_reserved(tmp_path, monkeypatch, suffix):
    root, manager, _ = interrupted(tmp_path, monkeypatch)
    (manager.state_dir / 'workspace-transactions' / ('f' * 64 + suffix)).write_text('{}')
    db = manager._get_db()
    try:
        with db:
            db.execute("INSERT INTO job_admissions VALUES ('unbound',NULL,0,0)")
    finally:
        db.close()
    plan = recovery.recover_workspace(manager.state_dir, root)
    recovery.recover_workspace(manager.state_dir, root, apply=True, expected_plan_sha256=plan['plan_sha256'])
    db = manager._get_db()
    try:
        assert db.execute("SELECT count(*) FROM job_admissions WHERE token='unbound'").fetchone()[0] == 1
    finally:
        db.close()


def test_service_must_be_stopped_before_inspection_or_application(tmp_path, monkeypatch):
    root, manager, transaction = interrupted(tmp_path, monkeypatch)
    def active():
        raise PermissionError('synthetic active worker service')
    monkeypatch.setattr(recovery, '_verify_stopped_service', active)
    with pytest.raises(PermissionError):
        recovery.recover_workspace(manager.state_dir, root)
    assert (root / 'ordinary').read_text() == 'original'
    assert transaction._pending.exists()


def test_legacy_job_database_without_git_bindings_can_recover(tmp_path, monkeypatch):
    root, manager, _ = interrupted(tmp_path, monkeypatch)
    database = manager._get_db()
    try:
        with database:
            database.execute('DROP TABLE git_admissions')
    finally:
        database.close()
    plan = recovery.recover_workspace(manager.state_dir, root)
    result = recovery.recover_workspace(manager.state_dir, root, apply=True,
                                       expected_plan_sha256=plan['plan_sha256'])
    assert result['status'] == 'recovered'
