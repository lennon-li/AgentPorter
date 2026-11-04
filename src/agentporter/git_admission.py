"""Durable capacity linkage for approved Git operations and owner recovery."""
import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote


def bind(manager, token, request_digest, guard):
    database = manager._get_db()
    try:
        with database:
            database.execute('BEGIN IMMEDIATE')
            row = database.execute('SELECT job_id FROM job_admissions WHERE token=?', (token,)).fetchone()
            if row is None or row[0] is not None:
                raise PermissionError('Git operation has no owned synchronous admission')
            database.execute('INSERT INTO git_admissions VALUES (?,?,?,?)',
                             (token, request_digest, str(guard), 'active'))
    finally:
        database.close()


def resolve(manager, token):
    """Called only after verified cleanup and durable success, or before launch."""
    database = manager._get_db()
    try:
        with database:
            database.execute("UPDATE git_admissions SET status='resolved' WHERE token=?", (token,))
            database.execute('DELETE FROM job_admissions WHERE token=? AND job_id IS NULL', (token,))
    finally:
        database.close()


def _recovery_database(state, *, write=False):
    path = Path(state) / 'jobs.db'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise PermissionError('Untrusted Git admission database')
    finally:
        os.close(descriptor)
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = Path(str(path) + suffix)
        try:
            info = sidecar.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise PermissionError('Untrusted Git admission database sidecar')
    # Both modes refuse a missing database; plan inspection cannot write it.
    mode = 'rw' if write else 'ro'
    return sqlite3.connect('file:' + quote(str(path)) + '?mode=' + mode, uri=True)


def inspect_recovery(state, token, request_digest, guard):
    database = _recovery_database(state)
    try:
        row = database.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',
                               (token,)).fetchone()
        if row is None:
            admission = database.execute('SELECT job_id FROM job_admissions WHERE token=?', (token,)).fetchone()
            if admission is not None and admission[0] is not None:
                raise PermissionError('Git guard points at an asynchronous job admission')
            return 'unbound'
        if (row[0] != request_digest or row[1] != str(guard)
                or row[2] not in {'active', 'resolved'}):
            raise PermissionError('Git guard admission does not match private database state')
        return row[2]
    finally:
        database.close()


def resolve_recovery(state, token, request_digest, guard):
    database = _recovery_database(state, write=True)
    try:
        with database:
            database.execute('BEGIN IMMEDIATE')
            row = database.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',
                                   (token,)).fetchone()
            if row is None:
                admission = database.execute('SELECT job_id FROM job_admissions WHERE token=?', (token,)).fetchone()
                if admission is not None and admission[0] is not None:
                    raise PermissionError('Git guard points at an asynchronous job admission')
                database.execute('INSERT INTO git_admissions VALUES (?,?,?,?)',
                                 (token, request_digest, str(guard), 'resolved'))
            else:
                if (row[0] != request_digest or row[1] != str(guard) or row[2] not in {'active', 'resolved'}):
                    raise PermissionError('Git admission changed before owner recovery')
                database.execute("UPDATE git_admissions SET status='resolved' WHERE token=?", (token,))
            database.execute('DELETE FROM job_admissions WHERE token=? AND job_id IS NULL', (token,))
    finally:
        database.close()
