#!/usr/bin/python3
"""One-off, service-UID-only recovery of the independently identified v12 orphan.

Requires A7Dev stopped and no other service-UID process. Never sends signals,
deletes jobs/admissions, changes configuration, or invokes application code.
Preserves a private full SQLite snapshot before changing exactly one row.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import tempfile
import time

JOB = 'job_494fce9fb61642529bcfa7d4'
PID = 2136174
CREATED = 1792524991.8932388
STATE = Path('/var/lib/agentporter-dev/state')


def verify_row(db):
    row = db.execute('SELECT * FROM jobs WHERE job_id=?', (JOB,)).fetchone()
    assert row is not None, 'Expected orphan absent'
    assert (row['workspace_id'], row['agent'], row['status'], row['pid'],
            row['pgid'], row['created_at']) == (
        'agentporter-dev', 'prof', 'running', PID, PID, CREATED), 'Job changed: stop'
    assert db.execute("SELECT count(*) FROM jobs WHERE status IN ('running','cancelling','queued','cleanup_failed')").fetchone()[0] == 1, 'Other unresolved jobs: stop'
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'job_admissions' in tables:
        assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0, 'Admissions require separate investigation'
    return row


def verify_processes(uid):
    assert not Path('/proc/' + str(PID)).exists(), 'Recorded PID is live: stop'
    assert not Path('/sys/fs/cgroup/system.slice/agentporter-development.service').exists(), 'Service cgroup still exists: stop'
    for path in Path('/proc').iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid():
            continue
        try:
            assert path.stat().st_uid != uid, 'Another service-UID process exists: stop'
            assert os.getpgid(int(path.name)) != PID, 'Recorded process group still exists: stop'
        except ProcessLookupError:
            pass
        except FileNotFoundError:
            pass


def main():
    os.umask(0o077)
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    assert os.geteuid() == uid and uid != 0, 'Run only as agentporter-dev'
    path = STATE / 'jobs.db'
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
    assert not info.st_mode & 0o077 and info.st_size <= 256 * 1024**2
    verify_processes(uid)
    db = sqlite3.connect('file:' + str(path) + '?mode=rw', uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    before = verify_row(db)
    fd, backup = tempfile.mkstemp(prefix='pre-v19-prof-orphan-', suffix='.sqlite', dir=STATE)
    os.close(fd)
    snapshot = sqlite3.connect(backup)
    try:
        db.backup(snapshot)
        assert snapshot.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    finally:
        snapshot.close()
    with open(backup, 'rb') as stream:
        os.fsync(stream.fileno())
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    try:
        db.execute('BEGIN IMMEDIATE')
        verify_row(db)
        verify_processes(uid)
        now = time.time()
        changed = db.execute("""UPDATE jobs SET status='interrupted', exit_code=130,
            finished_at=?, duration=MAX(0,?-COALESCE(started_at,created_at,?))
            WHERE job_id=? AND status='running' AND pid=? AND pgid=? AND created_at=?""",
            (now, now, now, JOB, PID, PID, CREATED))
        assert changed.rowcount == 1
        db.commit()
        assert db.execute('SELECT status,exit_code FROM jobs WHERE job_id=?', (JOB,)).fetchone()[:] == ('interrupted', 130)
        print(json.dumps({'job_id': JOB, 'previous_status': before['status'],
            'status': 'interrupted', 'exit_code': 130, 'finished_at': now,
            'backup': backup, 'backup_sha256': digest,
            'processes_signalled': 0, 'admissions_deleted': 0}))
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
