"""Uncertain approved Git work must retain shared capacity across restart."""
import json
import os
from pathlib import Path

import pytest

from agentporter.admission import synchronous_slot
from agentporter.git_commit_recovery import recover_git
from agentporter.resources import JobCapacityError, ResourceCleanupError
from agentporter.sandbox import workspace_recovery
from agentporter.tools.jobs import JobManager
from tests.security.test_approved_git_commit import backend, approve

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(),
                               reason='Native BCC approved Git required')


def setup(tmp_path):
    root, original, sandbox, key = backend(tmp_path)
    manager = JobManager(sandbox.state_dir, max_active_jobs=1)
    manager.resources = sandbox.resources
    service = type(original)(original.registry, sandbox, original.verifier,
        author_name=original.author_name, author_email=original.author_email, job_manager=manager)
    return root, service, sandbox, key, manager


def count(manager):
    database = manager._get_db()
    try:
        return database.execute('SELECT count(*) FROM job_admissions').fetchone()[0]
    finally:
        database.close()


def fail_commit(service, sandbox, key, monkeypatch):
    timestamp, receipt = approve(service, key)
    original = sandbox._run_command
    def fail(**options):
        if options.get('workspace_transaction') is not None:
            return {'exit_code': 1, 'stdout': '', 'stderr': 'synthetic interruption'}
        return original(**options)
    with monkeypatch.context() as patch:
        patch.setattr(sandbox, '_run_command', fail)
        with pytest.raises(ResourceCleanupError):
            service.commit('repo', 'Reviewed change', timestamp, receipt)


def test_commit_and_preparation_use_shared_capacity(tmp_path, monkeypatch):
    _, service, sandbox, key, manager = setup(tmp_path)
    timestamp, receipt = approve(service, key)
    assert count(manager) == 0
    original = sandbox._run_command
    def bounded(**options):
        assert count(manager) == 1
        with pytest.raises(JobCapacityError):
            with synchronous_slot(manager):
                pytest.fail('Approved Git overcommitted shared capacity')
        return original(**options)
    monkeypatch.setattr(sandbox, '_run_command', bounded)
    service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert count(manager) == 0


def test_invalid_receipt_releases_capacity(tmp_path):
    _, service, _, _, manager = setup(tmp_path)
    with pytest.raises(PermissionError):
        service.commit('repo', 'Reviewed change', 1000, '{}')
    assert count(manager) == 0


def test_restart_retains_guarded_git_admission(tmp_path, monkeypatch):
    _, service, sandbox, key, manager = setup(tmp_path)
    fail_commit(service, sandbox, key, monkeypatch)
    assert count(manager) == 1
    restarted = JobManager(manager.state_dir, max_active_jobs=1)
    sandbox.resources.recover = lambda: None
    try:
        restarted.configure_resources(sandbox.resources)
        assert count(restarted) == 1
        with pytest.raises(JobCapacityError):
            with synchronous_slot(restarted):
                pytest.fail('Restart discarded uncertain Git admission')
    finally:
        if getattr(restarted, '_supervisor_lock', None) is not None:
            os.close(restarted._supervisor_lock)


def test_owner_recovery_releases_only_bound_git_capacity(tmp_path, monkeypatch):
    _, service, sandbox, key, manager = setup(tmp_path)
    fail_commit(service, sandbox, key, monkeypatch)
    database = manager._get_db()
    try:
        with database:
            database.execute("INSERT INTO job_admissions VALUES ('unrelated',NULL,0,0)")
    finally:
        database.close()
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_git(service, 'repo')
    assert plan['admission_status'] == 'active'
    recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    database = manager._get_db()
    try:
        assert [row[0] for row in database.execute('SELECT token FROM job_admissions')] == ['unrelated']
        assert database.execute('SELECT status FROM git_admissions').fetchone()[0] == 'resolved'
    finally:
        database.close()


def test_owner_recovery_can_retry_after_admission_release(tmp_path, monkeypatch):
    _, service, sandbox, key, manager = setup(tmp_path)
    fail_commit(service, sandbox, key, monkeypatch)
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_git(service, 'repo')
    unlink = Path.unlink
    def interrupted_unlink(path, *args, **kwargs):
        if str(path).endswith('.git-pending.json'):
            raise OSError('synthetic final guard removal failure')
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'unlink', interrupted_unlink)
        with pytest.raises(OSError):
            recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert count(manager) == 0
    retry = recover_git(service, 'repo')
    assert retry['admission_status'] == 'resolved'
    recover_git(service, 'repo', apply=True, expected_plan_sha256=retry['plan_sha256'])
    timestamp, receipt = approve(service, key, 'next')
    service.commit('repo', 'next', timestamp, receipt)
    assert count(manager) == 0


def test_changed_admission_binding_cannot_be_cleared(tmp_path, monkeypatch):
    _, service, sandbox, key, manager = setup(tmp_path)
    fail_commit(service, sandbox, key, monkeypatch)
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    database = manager._get_db()
    try:
        with database:
            database.execute("UPDATE git_admissions SET request_sha256='wrong'")
    finally:
        database.close()
    with pytest.raises(PermissionError):
        recover_git(service, 'repo')
    assert count(manager) == 1


def test_crash_between_durable_guard_and_database_binding_can_recover(tmp_path, monkeypatch):
    from agentporter import git_admission
    _, service, sandbox, key, manager = setup(tmp_path)
    timestamp, receipt = approve(service, key)
    def fail(*args):
        raise RuntimeError('synthetic binding interruption')
    with monkeypatch.context() as patch:
        patch.setattr(git_admission, 'bind', fail)
        with pytest.raises(ResourceCleanupError):
            service.commit('repo', 'Reviewed change', timestamp, receipt)
    assert count(manager) == 1
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_git(service, 'repo')
    assert plan['admission_status'] == 'unbound'
    recover_git(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert count(manager) == 0

