"""Owner-only offline recovery for interrupted BCC workspace publication.

This module has no MCP/REST entry point. The CLI must run as the unprivileged
worker identity after the owner stops its service, never as root.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pwd
from pathlib import Path
import sqlite3
import stat
import subprocess
import time

from agentporter.sandbox.workspace_delta import (
    _require_public_path, publish_workspace_file, validate_workspace_delta,
)
from agentporter.sandbox.workspace_transactions import _fingerprint
from agentporter.workspaces.leases import mutation_lease, workspace_key

_SERVICE = 'agentporter-bcc-worker.service'
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _verify_stopped_service():
    result = subprocess.run(['/usr/bin/systemctl', 'is-active', _SERVICE],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    if result.returncode != 3 or result.stdout.strip() not in {b'inactive', b'failed'}:
        raise PermissionError('Owner must stop the BCC worker service before recovery')
    cgroup = Path('/sys/fs/cgroup/system.slice') / _SERVICE
    if cgroup.exists():
        events = dict(line.split() for line in (cgroup / 'cgroup.events').read_text().splitlines())
        if events.get('populated') != '0':
            raise PermissionError('BCC worker process tree is not quiescent')


def _directory(path, *, private=False):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError('Recovery directories must belong to the worker identity')
    if private and info.st_mode & 0o077:
        raise PermissionError('Recovery state must be private to the worker identity')


@contextmanager
def _maintenance(state):
    _verify_stopped_service()
    _directory(state, private=True)
    descriptor = os.open(state / 'job-supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PermissionError('Gateway supervisor is still active') from error
        _verify_stopped_service()
        yield
    finally:
        os.close(descriptor)


def _read_journal(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_size > 16 * 1024 * 1024):
            raise PermissionError('Untrusted recovery journal')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise PermissionError('Recovery journal exceeds size limit')
    finally:
        os.close(descriptor)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PermissionError('Duplicate recovery journal field')
            result[key] = value
        return result
    parsed = json.loads(data, object_pairs_hook=unique)
    if not isinstance(parsed, dict) or set(parsed) != {'workspace', 'transaction', 'changes'}:
        raise PermissionError('Unsupported recovery journal schema')
    return parsed, hashlib.sha256(data).hexdigest()


def _relative(path):
    if not isinstance(path, str) or any(part in {'', '.', '..'} for part in path.split('/')):
        raise PermissionError('Invalid recovery path')
    _require_public_path(path)


def _current_hash(root_descriptor, relative):
    descriptor = os.dup(root_descriptor)
    try:
        try:
            for part in relative.split('/')[:-1]:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return _fingerprint(Path(f'/proc/self/fd/{descriptor}') / relative.split('/')[-1])
        except FileNotFoundError:
            return None
    finally:
        os.close(descriptor)


def _sync(directory):
    descriptor = os.open(directory, _DIRECTORY_FLAGS)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_receipt(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(json.dumps(data, sort_keys=True, indent=2).encode())
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def recover_workspace(state_dir, workspace, *, apply=False, expected_plan_sha256=None):
    state = Path(state_dir).resolve(strict=True)
    workspace = Path(workspace).resolve(strict=True)
    transactions = state / 'workspace-transactions'
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Recovery state must be outside the workspace')
    with _maintenance(state), mutation_lease(workspace, transactions, allow_pending=True):
        _directory(transactions, private=True)
        root = os.open(workspace, _DIRECTORY_FLAGS)
        connection = None
        publication = None
        try:
            identity = os.fstat(root)
            key = workspace_key(identity)
            journal = transactions / (key + '.pending.json')
            data, journal_hash = _read_journal(journal)
            if data['workspace'] != str(workspace) or not isinstance(data['transaction'], str):
                raise PermissionError('Recovery workspace identity does not match journal')
            directory = Path(data['transaction'])
            if directory.parent != transactions or not directory.name.startswith(key[:12] + '-'):
                raise PermissionError('Recovery transaction is outside private storage')
            _directory(directory, private=True)
            if any(directory.glob('git-*')):
                raise PermissionError('Private Git import recovery requires reconciliation of its retained Git guards')
            upper = directory / 'upper'
            _directory(upper)
            validate_workspace_delta(upper)
            if not isinstance(data['changes'], list) or len(data['changes']) > 100_000:
                raise PermissionError('Invalid recovery change list')
            expected = {}
            for entry in data['changes']:
                if not isinstance(entry, list) or len(entry) != 2:
                    raise PermissionError('Invalid recovery change entry')
                relative, before = entry
                _relative(relative)
                if relative in expected or (before is not None and
                        (not isinstance(before, str) or len(before) != 64 or any(c not in '0123456789abcdef' for c in before))):
                    raise PermissionError('Invalid recovery baseline digest')
                expected[relative] = before
            files = {}
            directories = []
            for current, dirs, names in os.walk(upper):
                for name in dirs:
                    directories.append((Path(current) / name).relative_to(upper).as_posix())
                for name in names:
                    relative = (Path(current) / name).relative_to(upper).as_posix()
                    files[relative] = _fingerprint(upper / relative)
            if set(files) != set(expected):
                raise PermissionError('Recovery delta differs from journal file list')
            entries = []
            for relative in sorted(files):
                current = _current_hash(root, relative)
                status = 'applied' if current == files[relative] else ('pending' if current == expected[relative] else 'conflict')
                entries.append({'path': relative, 'before_sha256': expected[relative],
                    'staged_sha256': files[relative], 'current_sha256': current, 'state': status})
            plan = {'status': 'planned', 'workspace': str(workspace), 'workspace_key': key,
                'transaction': str(directory), 'journal_sha256': journal_hash,
                'directories': sorted(directories), 'files': entries}
            plan_hash = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            plan['plan_sha256'] = plan_hash
            if not apply:
                return plan
            if expected_plan_sha256 != plan_hash:
                raise PermissionError('Recovery requires the exact reviewed plan SHA256')
            if any(entry['state'] == 'conflict' for entry in entries):
                raise PermissionError('Recovery conflicts with owner edits; no changes applied')
            database = state / 'jobs.db'
            info = database.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise PermissionError('Untrusted recovery job database')
            connection = sqlite3.connect(database)
            try:
                connection.execute('SELECT job_id,workspace_transaction,status FROM jobs LIMIT 0')
                connection.execute('SELECT token,job_id FROM job_admissions LIMIT 0')
            except sqlite3.DatabaseError as error:
                raise PermissionError('Recovery job database schema is invalid') from error
            if identity.st_uid != os.getuid():
                from agentporter.sandbox.workspace_projections import open_workspace_publication
                publication = open_workspace_publication(root)
            source_root = f'/proc/self/fd/{publication if publication is not None else root}/.'
            for relative in sorted(directories, key=lambda name: len(name.split('/'))):
                descriptor = os.dup(publication if publication is not None else root)
                try:
                    for part in relative.split('/'):
                        try:
                            os.mkdir(part, 0o755, dir_fd=descriptor)
                        except FileExistsError:
                            pass
                        child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                        os.fsync(descriptor)
                        os.close(descriptor)
                        descriptor = child
                finally:
                    os.close(descriptor)
            for entry in entries:
                if entry['state'] == 'pending':
                    publish_workspace_file(source_root, entry['path'], upper / entry['path'],
                                           expected_sha256=entry['before_sha256'])
            receipts = state / 'recovery-receipts'
            receipts.mkdir(mode=0o700, exist_ok=True)
            _directory(receipts, private=True)
            receipt = receipts / (key + '-' + str(time.time_ns()) + '.json')
            report = {**plan, 'status': 'recovered', 'operator_uid': os.getuid(), 'recovered_at': time.time()}
            _write_receipt(receipt, report)
            # Keep the pending guard until durable job state and the receipt exist.
            try:
                with connection:
                    job_ids = [row[0] for row in connection.execute(
                        "SELECT job_id FROM jobs WHERE workspace_transaction=? AND status IN ('cleanup_failed','finalizing')", (str(directory),))]
                    for job_id in job_ids:
                        connection.execute("UPDATE jobs SET status='recovered',exit_code=0,finished_at=? WHERE job_id=?", (time.time(), job_id))
                        connection.execute('DELETE FROM job_admissions WHERE job_id=?', (job_id,))
                journal.unlink()
                _sync(transactions)
                if (not any(transactions.glob('*.pending.json'))
                        and not any(transactions.glob('*.git-pending.json'))):
                    with connection:
                        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='git_admissions'").fetchone():
                            connection.execute("""DELETE FROM job_admissions WHERE job_id IS NULL
                                AND token NOT IN (SELECT token FROM git_admissions WHERE status='active')""")
                        else:
                            connection.execute('DELETE FROM job_admissions WHERE job_id IS NULL')
            finally:
                connection.close()
                connection = None
            return {**report, 'receipt': str(receipt)}
        finally:
            if connection is not None:
                connection.close()
            if publication is not None:
                os.close(publication)
            os.close(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expect-plan-sha256')
    arguments = parser.parse_args()
    try:
        worker_uid = pwd.getpwnam('agentporter-bcc-worker').pw_uid
    except KeyError:
        parser.error('The BCC worker account is not installed')
    if os.getuid() == 0 or os.geteuid() != os.getuid() or os.getuid() != worker_uid:
        parser.error('Run as agentporter-bcc-worker, never as root or another user')
    try:
        result = recover_workspace(arguments.state_dir, arguments.workspace, apply=arguments.apply,
                                   expected_plan_sha256=arguments.expect_plan_sha256)
    except (OSError, ValueError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
