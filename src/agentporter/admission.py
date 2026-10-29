"""Cross-process, fail-closed admission for sync and async gateway jobs."""
from contextlib import contextmanager
import functools
import os
import time
import uuid

from agentporter.resources import JobCapacityError, ResourceCleanupError


@contextmanager
def execution_slot(manager):
    token = uuid.uuid4().hex
    db = manager._get_db()
    try:
        with db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] >= manager.max_active_jobs:
                raise JobCapacityError('Gateway active-job limit reached; retry after an existing job finishes')
            db.execute('INSERT INTO job_admissions VALUES (?,?,?,?)', (token, None, os.getpid(), time.time()))
        yield token
    except BaseException as error:
        if isinstance(error, ResourceCleanupError):
            raise  # Keep capacity held for unresolved descendants.
        with db:
            db.execute('DELETE FROM job_admissions WHERE token=?', (token,))
        raise
    finally:
        db.close()


def release(manager, *, token=None, job_id=None):
    db = manager._get_db()
    try:
        with db:
            if token is not None:
                db.execute('DELETE FROM job_admissions WHERE token=?', (token,))
            else:
                db.execute('DELETE FROM job_admissions WHERE job_id=?', (job_id,))
    finally:
        db.close()


def admitted_job(function):
    @functools.wraps(function)
    def wrapped(self, *args, **kwargs):
        with execution_slot(self) as token:
            job_id = function(self, *args, **kwargs)
            try:
                db = self._get_db()
                try:
                    with db:
                        db.execute('UPDATE job_admissions SET job_id=? WHERE token=?', (job_id, token))
                        row = db.execute('SELECT status FROM jobs WHERE job_id=?', (job_id,)).fetchone()
                        # The monitor can finish before this binding. Its cleanup
                        # terminal state is sufficient; unverified cleanup is not.
                        if row and row[0] not in {'running', 'cancelling', 'queued', 'finalizing', 'cleanup_failed'}:
                            db.execute('DELETE FROM job_admissions WHERE token=?', (token,))
                finally:
                    db.close()
            except BaseException as error:
                raise ResourceCleanupError('Job launched; admission binding remains uncertain') from error
            return job_id
    return wrapped


@contextmanager
def synchronous_slot(manager):
    with execution_slot(manager) as token:
        try:
            yield
        except ResourceCleanupError:
            raise
        else:
            release(manager, token=token)
