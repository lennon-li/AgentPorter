"""Maintenance barriers and boot configuration for the production cutover."""
import ast
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT=Path(__file__).parents[2]
BUNDLE=ROOT/'deploy/bcc/release19'
spec=importlib.util.spec_from_file_location('bcc_cutover',BUNDLE/'cutover.py')
cutover=importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


def database(tmp_path,status='completed'):
    path=tmp_path/'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE jobs(status TEXT)')
        db.execute('INSERT INTO jobs VALUES(?)',(status,))
    return path


def guard(path,action,nonce='a'*32):
    return subprocess.run([sys.executable,'-I','-c',cutover.MAIN_GUARD,str(path),action,nonce],
                          capture_output=True,text=True)


def test_legacy_database_can_be_frozen_and_released_without_schema_changes(tmp_path):
    path=database(tmp_path)
    assert guard(path,'install').returncode==0
    with sqlite3.connect(path) as db:
        try:db.execute("INSERT INTO jobs VALUES('running')")
        except sqlite3.IntegrityError:pass
        else:raise AssertionError('Maintenance must block new jobs')
    assert guard(path,'remove','b'*32).returncode!=0
    assert guard(path,'remove').returncode==0
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO jobs VALUES('running')")


def test_live_jobs_prevent_maintenance_installation(tmp_path):
    path=database(tmp_path,'running')
    assert guard(path,'install').returncode!=0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger'").fetchone()[0]==0


def test_held_new_admissions_prevent_maintenance_installation(tmp_path):
    path=database(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE job_admissions(token TEXT)')
        db.execute("INSERT INTO job_admissions VALUES('held')")
    assert guard(path,'install').returncode!=0


def test_maintenance_also_blocks_new_synchronous_admissions(tmp_path):
    path=database(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE job_admissions(token TEXT PRIMARY KEY)')
    assert guard(path,'install').returncode==0
    with sqlite3.connect(path) as db:
        try:
            db.execute("INSERT INTO job_admissions(token) VALUES('new-synchronous-slot')")
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError('Maintenance must block synchronous admissions before service cutover')


def test_boot_projection_program_has_no_shell_and_uses_only_named_paths():
    text=cutover.projection_program(['/home/yeli/repos/AgentPorter','/home/yeli/repos/Qman']).decode()
    ast.parse(text)
    assert 'shell=True' not in text
    assert "'--source',source,'--apply'" in text
    assert 'target.rmdir()' in text and 'not list(target.iterdir())' in text


def test_system_gateway_is_immutable_and_enabled_for_system_boot():
    text=(BUNDLE/'gateway.service').read_text()
    assert 'ExecStart=/opt/agentporter-bcc/releases/bcc-stage-20261029-19/venv/bin/python -I -m agentporter.resource_supervisor' in text
    assert 'WantedBy=multi-user.target' in text
    assert 'Wants=network-online.target agentporter-bcc-worker.service' in text
    assert 'Delegate=yes' in text
    assert 'AGENTPORTER_ACTION_PREFIX=bcc' in text


def test_rollback_refuses_to_stop_services_when_worker_has_active_work(monkeypatch):
    from types import SimpleNamespace
    import pytest
    calls=[]
    monkeypatch.setattr(cutover,'save',lambda journal: None)
    monkeypatch.setattr(cutover,'system',lambda *args: calls.append(args))
    def busy(*args):
        raise PermissionError('Held worker admissions')
    journal={'phase':'complete','files':{},'nonce':'a'*32,
        'worker_changed':True,'worker_guard':False,'gateway_started':True,'main_guard':False}
    with pytest.raises(PermissionError,match='Held worker admissions'):
        cutover.rollback(journal,SimpleNamespace(guard=busy))
    assert calls==[]
    assert journal['worker_guard'] is True  # Durable intent remains for inspection.
