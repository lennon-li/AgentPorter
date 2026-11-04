"""Owner-only offline recovery for interrupted Gateway workspace publication.

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
    restore_workspace_deletion, _workspace_parent, _read_deletion_file, _file_signature,
    _publish_restore_fd,
)
from agentporter.sandbox.workspace_transactions import _fingerprint
from agentporter.workspaces.leases import mutation_lease, workspace_key

_SERVICE = 'agentporter-worker.service'
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _verify_stopped_service():
    result = subprocess.run(['/usr/bin/systemctl', 'is-active', _SERVICE],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    if result.returncode != 3 or result.stdout.strip() not in {b'inactive', b'failed'}:
        raise PermissionError('Owner must stop the Gateway worker service before recovery')
    cgroup = Path('/sys/fs/cgroup/system.slice') / _SERVICE
    if cgroup.exists():
        events = dict(line.split() for line in (cgroup / 'cgroup.events').read_text().splitlines())
        if events.get('populated') != '0':
            raise PermissionError('Gateway worker process tree is not quiescent')


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


def _read_private_json(path):
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
    return parsed, hashlib.sha256(data).hexdigest()


def _read_journal(path):
    parsed, digest = _read_private_json(path)
    if not isinstance(parsed, dict):
        raise PermissionError('Unsupported recovery journal schema')
    keys = set(parsed)
    if keys == {'workspace', 'transaction', 'changes'}:
        return parsed, digest
    if keys == {'schema', 'workspace', 'transaction', 'changes'} and parsed['schema'] == 2:
        return parsed, digest
    if keys == {'schema', 'workspace', 'transaction', 'changes', 'recovery'} and parsed['schema'] in (3, 4):
        return parsed, digest
    raise PermissionError('Unsupported recovery journal schema')


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
    # A receipt is visible only after its complete bytes are durable. Crashes
    # during write/fsync leave no partial final JSON for a retry to misread.
    parent = os.open(path.parent, _DIRECTORY_FLAGS)
    descriptor = None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError('Receipt storage must be private')
        descriptor = os.open('.', os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(os.dup(descriptor), 'wb') as stream:
            stream.write(json.dumps(data, sort_keys=True, indent=2).encode())
            stream.flush()
        os.fsync(descriptor)
        _publish_restore_fd(parent, descriptor, path.name)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _restored_signature(workspace, relative, record, expected_signature, *, renamed=False):
    import base64
    if (not isinstance(expected_signature, list) or len(expected_signature) != 7
            or any(type(value) is not int or value < 0 for value in expected_signature)):
        raise PermissionError('Invalid restoration candidate identity')
    with _workspace_parent(workspace, relative) as (parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            signature = list(_file_signature(info))
            published_expected = list(expected_signature)
            if renamed and published_expected[3] == 0:
                # Anonymous O_TMPFILE receives its one canonical name via linkat.
                published_expected[3] = 1
            matches = (signature[:-1] == published_expected[:-1]
                       and signature[-1] >= published_expected[-1]) if renamed else signature == expected_signature
            if not matches:
                raise PermissionError('Restored destination no longer names the exact prepared inode')
            _read_deletion_file(descriptor, expected_signature=signature, expected_sha256=record['sha256'])
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns) != (
                    record['uid'], record['gid'], record['mode'], record['mtime_ns']):
                raise PermissionError('Restored access metadata changed')
            if {key: base64.b64encode(os.getxattr(descriptor, key)).decode('ascii')
                    for key in os.listxattr(descriptor)} != record['xattrs']:
                raise PermissionError('Restored access attributes changed')
            if list(_file_signature(os.fstat(descriptor))) != signature:
                raise PermissionError('Restored file changed during verification')
            return signature
        finally:
            os.close(descriptor)


def _restore_deletion_journal(data, journal_hash, directory, workspace, root, *, apply,
                             expected_plan_sha256, restore_deletions):
    """Restore recorded removed bytes only; retain every mixed/Git guard.

    Schema2 deliberately cannot be mistaken for schema1 forward replay. This
    bounded procedure never repeats a deletion or reconciles a private Git ref.
    """
    changes = data['changes']
    if not isinstance(changes, list) or not changes or len(changes) > 100_000:
        raise PermissionError('Invalid versioned change list')
    paths = set()
    entries = []
    for index, operation in enumerate(changes):
        if (not isinstance(operation, dict) or operation.get('op') not in {'create', 'replace', 'delete'}
                or operation.get('state') not in {'pending', 'applied'}):
            raise PermissionError('Invalid versioned change operation')
        relative = operation.get('path')
        _relative(relative)
        if relative in paths:
            raise PermissionError('Duplicate versioned operation path')
        paths.add(relative)
        keys = {'op', 'path', 'before_sha256', 'state'}
        if operation['op'] != 'delete':
            if set(operation) != keys:
                raise PermissionError('Invalid ordinary versioned operation')
            continue
        if set(operation) != keys | {'original', 'backup'}:
            raise PermissionError('Invalid deletion operation')
        if operation['backup'] != 'deletions/' + str(index):
            raise PermissionError('Deletion backup path differs from operation identity')
        record = operation['original']
        required = {'signature', 'sha256', 'backup_signature', 'mode', 'uid', 'gid', 'atime_ns', 'mtime_ns', 'xattrs'}
        if not isinstance(record, dict) or set(record) != required:
            raise PermissionError('Invalid deletion original record')
        for field in ('signature', 'backup_signature'):
            if (not isinstance(record[field], list) or len(record[field]) != 7
                    or any(type(item) is not int or item < 0 for item in record[field])):
                raise PermissionError('Invalid deletion file identity')
        digest = record['sha256']
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in '0123456789abcdef' for c in digest)
                or digest != operation['before_sha256']):
            raise PermissionError('Invalid deletion original digest')
        if (any(type(record[field]) is not int or record[field] < 0
                for field in ('mode', 'uid', 'gid', 'atime_ns', 'mtime_ns'))
                or record['mode'] > 0o777 or not isinstance(record['xattrs'], dict)):
            raise PermissionError('Invalid deletion access metadata')
        backup = directory / operation['backup']
        with _workspace_parent(directory, operation['backup']) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                _read_deletion_file(descriptor, expected_signature=record['backup_signature'], expected_sha256=digest)
            finally:
                os.close(descriptor)
        current = _current_hash(root, relative)
        receipt = directory / ('deletion-restore-' + str(index) + '.json')
        intent = directory / ('deletion-restore-' + str(index) + '.intent.json')
        restored = None
        from_intent = False
        if os.path.lexists(receipt) or os.path.lexists(intent):
            from_intent = not os.path.lexists(receipt)
            restored, _ = _read_private_json(intent if from_intent else receipt)
            if (not isinstance(restored, dict) or set(restored) != {'path', 'signature', 'sha256'}
                    or restored['path'] != relative or restored['sha256'] != digest):
                raise PermissionError('Invalid deletion restoration receipt')
        state = 'restore_pending' if current is None else 'conflict'
        if current == digest:
            signature = restored['signature'] if restored is not None else record['signature']
            try:
                _restored_signature(workspace, relative, record, signature, renamed=from_intent)
                state = ('restore_published' if from_intent else 'restored') if restored is not None else 'not_deleted'
            except (PermissionError, OSError):
                state = 'conflict'
        elif restored is not None and not (from_intent and current is None):
            state = 'conflict'
        entries.append({'path': relative, 'state': state, 'before_sha256': digest,
                        'current_sha256': current, 'operation_index': index})
    if not entries:
        raise PermissionError('Versioned deletion recovery requires a deletion')
    plan = {'status': 'planned', 'mode': 'restore_deleted_files_only', 'workspace': str(workspace),
            'transaction': str(directory), 'journal_sha256': journal_hash,
            'files': entries, 'guard_retained': True,
            'requires_reconciliation': 'Ordinary published edits, Git history and job state remain guarded for owner reconciliation'}
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    plan['plan_sha256'] = digest
    if not apply:
        return plan
    if not restore_deletions:
        raise PermissionError('Versioned journals require explicit restore-deletions mode; no deletion replay')
    if expected_plan_sha256 != digest:
        raise PermissionError('Deletion restoration requires the exact reviewed plan SHA256')
    if any(entry['state'] == 'conflict' for entry in entries):
        raise PermissionError('Deletion restoration conflicts with later owner changes')
    for entry in entries:
        if entry['state'] == 'restore_pending':
            index = entry['operation_index']
            operation = changes[index]
            signature = restore_workspace_deletion(workspace, entry['path'], directory / operation['backup'],
                record=operation['original'], intent_path=directory / ('deletion-restore-' + str(index) + '.intent.json'))
            _write_receipt(directory / ('deletion-restore-' + str(index) + '.json'),
                           {'path': entry['path'], 'signature': signature, 'sha256': entry['before_sha256']})
        elif entry['state'] == 'restore_published':
            index = entry['operation_index']
            operation = changes[index]
            intent, _ = _read_private_json(directory / ('deletion-restore-' + str(index) + '.intent.json'))
            signature = _restored_signature(workspace, entry['path'], operation['original'], intent['signature'], renamed=True)
            _write_receipt(directory / ('deletion-restore-' + str(index) + '.json'),
                           {'path': entry['path'], 'signature': signature, 'sha256': entry['before_sha256']})
    return {**plan, 'status': 'deletions_restored_guard_retained'}



def _rollback_journal(data, journal_hash, directory, workspace, root, state, journal, *,
                      apply, expected_plan_sha256, restore_deletions):
    """Reconcile schema3 to its captured baseline, preserving ambiguous owners.

    Git and directory recovery are explicit blockers until their own reviewed
    reconcilers are integrated; terminal job bookkeeping cannot bypass them.
    """
    if apply:
        raise PermissionError('Legacy schema3 apply requires reviewed custody migration; inspection remains available')
    context = data['recovery']
    if (not isinstance(context, dict) or set(context) != {'endpoint', 'directories', 'histories'}
            or context['endpoint'] != 'before' or not isinstance(context['directories'], list)
            or not isinstance(context['histories'], list)):
        raise PermissionError('Invalid rollback recovery context')
    if context['histories'] or any(directory.glob('git-*')):
        raise PermissionError('Private Git rollback requires matching versioned Git reconciliation')
    upper = directory / 'upper'
    _directory(upper)
    if context['directories'] or any(path.is_dir() for path in upper.rglob('*')):
        raise PermissionError('Directory rollback requires captured directory identity reconciliation')
    changes = data['changes']
    if not isinstance(changes, list) or not changes or len(changes) > 100_000:
        raise PermissionError('Invalid rollback operation list')
    paths = set()
    files = []
    def digest(value):
        return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    def signature(value):
        return isinstance(value, list) and len(value) == 7 and all(type(v) is int and v >= 0 for v in value)
    def verify_original(index, operation):
        original = operation['original']
        required = {'signature', 'sha256', 'backup_signature', 'mode', 'uid', 'gid', 'atime_ns', 'mtime_ns', 'xattrs'}
        if (not isinstance(original, dict) or set(original) != required
                or not signature(original['signature']) or not signature(original['backup_signature'])
                or original['sha256'] != operation['before_sha256']
                or any(type(original[f]) is not int or original[f] < 0 for f in ('mode','uid','gid','atime_ns','mtime_ns'))
                or original['mode'] > 0o777 or not isinstance(original['xattrs'], dict)):
            raise PermissionError('Invalid rollback original metadata')
        expected = ('deletions/' if operation['op'] == 'delete' else 'originals/') + str(index)
        if operation['backup'] != expected:
            raise PermissionError('Rollback backup identity differs from operation')
        with _workspace_parent(directory, expected) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                _read_deletion_file(descriptor, expected_signature=original['backup_signature'], expected_sha256=original['sha256'])
            finally:
                os.close(descriptor)
    def restore_record(index, operation):
        intent = directory / ('deletion-restore-' + str(index) + '.intent.json')
        receipt = directory / ('deletion-restore-' + str(index) + '.json')
        for path, renamed in ((receipt, False), (intent, True)):
            if os.path.lexists(path):
                record, _ = _read_private_json(path)
                if (not isinstance(record, dict) or set(record) != {'path','signature','sha256'}
                        or record['path'] != operation['path'] or record['sha256'] != operation['before_sha256']):
                    raise PermissionError('Invalid rollback restoration receipt')
                return record, renamed
        return None, False
    def inspect(index, operation):
        relative = operation['path']
        current = _current_hash(root, relative)
        if current is None:
            return 'baseline' if operation['op'] == 'create' else 'restore_pending'
        if operation['op'] != 'create' and current == operation['before_sha256']:
            restored, renamed = restore_record(index, operation)
            expected = restored['signature'] if restored is not None else operation['original']['signature']
            _restored_signature(workspace, relative, operation['original'], expected, renamed=renamed)
            return 'baseline'
        candidate = operation['candidate']
        if candidate is not None and current == operation['staged_sha256']:
            _restored_signature(workspace, relative, candidate, candidate['signature'], renamed=True)
            return 'published'
        raise PermissionError('Rollback conflicts with later owner changes')
    for index, operation in enumerate(changes):
        base = {'op','path','before_sha256','state','staged_sha256','candidate','published_signature'}
        if not isinstance(operation, dict) or operation.get('op') not in {'create','replace','delete'}:
            raise PermissionError('Invalid rollback operation')
        relative = operation['path']; _relative(relative)
        if relative in paths:
            raise PermissionError('Duplicate rollback operation path')
        paths.add(relative)
        if operation['state'] not in {'pending','applied'}:
            raise PermissionError('Invalid rollback publication state')
        if operation['op'] == 'create':
            if set(operation) != base or operation['before_sha256'] is not None:
                raise PermissionError('Invalid rollback create')
        else:
            if set(operation) != base | {'original','backup'} or not digest(operation['before_sha256']):
                raise PermissionError('Invalid rollback original operation')
            verify_original(index, operation)
        if operation['op'] == 'delete':
            if operation['staged_sha256'] is not None or operation['candidate'] is not None or operation['published_signature'] is not None:
                raise PermissionError('Deletion contains a published file identity')
        else:
            if not digest(operation['staged_sha256']):
                raise PermissionError('Invalid staged rollback digest')
            candidate = operation['candidate']
            if candidate is not None and (not isinstance(candidate, dict)
                    or set(candidate) != {'signature','sha256','mode','uid','gid','mtime_ns','xattrs'}
                    or not signature(candidate['signature']) or candidate['sha256'] != operation['staged_sha256']
                    or any(type(candidate[f]) is not int or candidate[f] < 0 for f in ('mode','uid','gid','mtime_ns'))
                    or candidate['mode'] > 0o777 or not isinstance(candidate['xattrs'], dict)):
                raise PermissionError('Invalid prepared rollback inode')
            if operation['published_signature'] is not None and not signature(operation['published_signature']):
                raise PermissionError('Invalid published rollback inode')
        try:
            status = inspect(index, operation)
        except (OSError, PermissionError):
            status = 'conflict'
        files.append({'path':relative,'state':status,'operation_index':index})
    plan = {'status':'planned','mode':'rollback_to_baseline','workspace':str(workspace),
            'transaction':str(directory),'journal_sha256':journal_hash,'files':files,'guard_retained':True}
    plan_hash = hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    plan['plan_sha256'] = plan_hash
    if not apply:
        return plan
    if not restore_deletions or expected_plan_sha256 != plan_hash:
        raise PermissionError('Rollback requires explicit restore-deletions and exact reviewed plan SHA256')
    if any(item['state'] == 'conflict' for item in files):
        raise PermissionError('Rollback conflicts with later owner changes')
    connection = None
    database = state / 'jobs.db'
    if not os.path.lexists(database):
        raise PermissionError('Rollback requires the existing job database')
    if os.path.lexists(database):
        info = database.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise PermissionError('Untrusted rollback job database')
        connection = sqlite3.connect(database)
    try:
        if connection is not None:
            connection.execute('SELECT job_id,status,workspace_transaction FROM jobs LIMIT 0')
            connection.execute('SELECT token,job_id FROM job_admissions LIMIT 0')
            connection.execute('BEGIN IMMEDIATE')
            if connection.execute("SELECT 1 FROM jobs WHERE workspace_transaction=? AND status NOT IN ('cleanup_failed','finalizing','recovered') LIMIT 1",(str(directory),)).fetchone():
                raise PermissionError('Matching job is not in an inspected recovery state')
        for index, operation in enumerate(changes):
            status = inspect(index, operation)
            if status == 'published':
                # Revalidate against the durably recorded candidate; never
                # promote an arbitrary freshly reopened owner inode to our CAS.
                candidate = operation['candidate']
                actual = _restored_signature(workspace, operation['path'], candidate,
                                             candidate['signature'], renamed=True)
                from agentporter.sandbox.workspace_delta import delete_workspace_file
                delete_workspace_file(workspace,operation['path'],expected_signature=actual,
                                      expected_sha256=operation['staged_sha256'])
                status = 'baseline' if operation['op'] == 'create' else 'restore_pending'
            if status == 'restore_pending':
                original = operation['original']
                result = restore_workspace_deletion(workspace,operation['path'],directory/operation['backup'],
                    record=original,intent_path=directory/('deletion-restore-'+str(index)+'.intent.json'))
                _write_receipt(directory/('deletion-restore-'+str(index)+'.json'),
                    {'path':operation['path'],'signature':result,'sha256':operation['before_sha256']})
        if any(inspect(index, operation) != 'baseline' for index,operation in enumerate(changes)):
            raise PermissionError('Rollback endpoint could not be verified')
        receipts = state/'recovery-receipts'; receipts.mkdir(mode=0o700,exist_ok=True)
        _directory(receipts,private=True)
        receipt = receipts/(directory.name+'.rollback.json')
        report = {**plan,'status':'recovered','endpoint':'before','operator_uid':os.getuid()}
        if os.path.lexists(receipt):
            previous, _ = _read_private_json(receipt)
            if (not isinstance(previous,dict) or previous.get('transaction') != str(directory)
                    or previous.get('journal_sha256') != journal_hash or previous.get('endpoint') != 'before'
                    or previous.get('workspace') != str(workspace) or previous.get('status') != 'recovered'):
                raise PermissionError('Terminal rollback receipt conflicts with journal')
        else:
            _write_receipt(receipt,report)
        # Retire only admissions bound to this exact transaction. Unbound
        # reservations and other jobs remain intact even if no guards remain.
        if connection is not None:
            with connection:
                ids = [row[0] for row in connection.execute("SELECT job_id FROM jobs WHERE workspace_transaction=? AND status IN ('cleanup_failed','finalizing','recovered')",(str(directory),))]
                for job_id in ids:
                    connection.execute("UPDATE jobs SET status='recovered',exit_code=1,finished_at=COALESCE(finished_at,?) WHERE job_id=?",(time.time(),job_id))
                    connection.execute('DELETE FROM job_admissions WHERE job_id=?',(job_id,))
        journal.unlink()
        _sync(journal.parent)
        return {**report,'guard_retained':False,'receipt':str(receipt)}
    finally:
        if connection is not None:
            connection.close()



def _pull_admission(connection,item,*,resolve=False,parent_workspace=None):
    approved=item['inspection'].get('approved_pull')
    if approved is None:return
    authority=approved['authorization'];token=approved['admission_token'];request_hash=authority['request_sha256']
    context=authority['request']['parameters'].get('job_context')
    expected_job=context['job_id'] if context is not None else None
    if context is not None and (context.get('admission_token')!=token
            or context.get('transaction_directory')!=approved['candidate_directory']):
        raise PermissionError('Signed pull job context differs from bound recovery admission')
    expected_guard=str(item['path'])
    parameters=authority['request']['parameters']
    if 'repository_relative' in parameters:
        from agentporter.git_remote_policy import repository_relative
        relative=repository_relative(parameters['repository_relative'])
        if relative=='.' or parent_workspace is None:
            raise PermissionError('Nested pull recovery requires trusted canonical parent context')
        parent=Path(parent_workspace).resolve(strict=True);identity=parent.stat()
        expected_identity={'path':str(parent),'device':identity.st_dev,'inode':identity.st_ino}
        if (parameters.get('workspace_identity')!=expected_identity
                or authority['request']['repository_path']!=str(parent/relative)):
            raise PermissionError('Nested pull recovery parent differs from exact signed registration')
        expected_guard=str(Path(item['path']).parent/(workspace_key(identity)+'.git-pending.json'))
        if approved.get('workspace_guard_path')!=expected_guard:
            raise PermissionError('Nested pull recovery consumed guard differs from exact canonical parent')
    elif 'workspace_guard_path' in approved:
        raise PermissionError('Root pull recovery cannot substitute its consumed guard')
    binding=connection.execute('SELECT request_sha256,guard_path,status FROM git_admissions WHERE token=?',(token,)).fetchone()
    admission=connection.execute('SELECT job_id FROM job_admissions WHERE token=?',(token,)).fetchone()
    if (binding is None or binding[:2]!=(request_hash,expected_guard)
            or binding[2] not in {'active','resolved'}):
        raise PermissionError('Pull recovery lacks its exact consumed Git admission binding')
    if binding[2]=='active':
        if admission is None or admission[0]!=expected_job:
            raise PermissionError('Pull recovery admission belongs to another execution')
        if expected_job is not None:
            row=connection.execute('SELECT workspace_transaction,status FROM jobs WHERE job_id=?',(expected_job,)).fetchone()
            if row is None or row[0]!=approved['candidate_directory'] or row[1] not in {'cleanup_failed','finalizing','recovered'}:
                raise PermissionError('Pull recovery job is outside its exact bound transaction')
        if resolve:
            updated=connection.execute("UPDATE git_admissions SET status='resolved' WHERE token=? AND request_sha256=? AND guard_path=? AND status='active'",
                (token,request_hash,expected_guard))
            if updated.rowcount!=1:raise PermissionError('Pull recovery lost its exact consumed Git admission during resolution')
            if expected_job is None:connection.execute('DELETE FROM job_admissions WHERE token=? AND job_id IS NULL',(token,))
    elif admission is not None:
        row=(connection.execute('SELECT workspace_transaction,status FROM jobs WHERE job_id=?',(expected_job,)).fetchone()
             if expected_job is not None and admission[0]==expected_job else None)
        if row is None or row[0]!=approved['candidate_directory'] or row[1] not in {'cleanup_failed','finalizing','recovered'}:
            raise PermissionError('Resolved pull admission token was rebound to later execution')


def _custody_rollback(data,journal_hash,directory,workspace,root,state,journal,*,
                      apply,expected_plan_sha256,restore_deletions,pull_registry=None,pull_owner_config_dir=None):
    """Schema4: return exact retained originals and archive published candidates."""
    from agentporter.sandbox.workspace_custody import preflight_workspace_custody, inspect_custody, restore_custody
    from agentporter.sandbox.workspace_delta import delete_workspace_file
    from agentporter.sandbox.workspace_directories import inspect_directory, rollback_directory
    from agentporter.sandbox import recovery_guards
    bundle_base=recovery_guards.location(state,workspace_key(os.fstat(root)),directory.name)
    existing_bundle=recovery_guards.load(bundle_base)
    journal_signature=(list(_file_signature(journal.lstat())) if os.path.lexists(journal)
                       else existing_bundle['guards'][-1]['record']['signature'] if existing_bundle is not None else None)
    context=data['recovery']
    if (not isinstance(context,dict) or set(context) not in ({'endpoint','directories','histories','retention'},{'endpoint','directories','histories','retention','approved_clone'})
            or context['endpoint']!='before' or not isinstance(context['directories'],list)
            or not isinstance(context['histories'],list)
            or context['retention']!='retain_all_custody_no_automatic_purge'):
        raise PermissionError('Unsupported schema4 directory/retention recovery contract')
    if 'approved_clone' in context:
        if pull_registry is None or pull_owner_config_dir is None:raise PermissionError('Clone recovery requires independent protected registry and owner configuration')
        from agentporter.git_clone_recovery import validate_clone_recovery_context
        validate_clone_recovery_context(context['approved_clone'],registry=pull_registry,state_dir=state,owner_config_dir=pull_owner_config_dir,transaction=directory,workspace=workspace)
    git_inspections=[]
    git_guard_records=[]
    for git_index,item in enumerate(context['histories']):
        if not isinstance(item,dict) or set(item)!={'repository','guard','guard_payload','plan','exchange'}:
            raise PermissionError('Invalid bound Git recovery context')
        relative=item['repository']
        if relative!='.':_relative(relative)
        data_root=f'/proc/self/fd/{root}/.'
        repository=data_root if relative=='.' else data_root+'/'+relative
        exchange=Path(item['exchange'])
        history=exchange.parent
        if (exchange.name!='exchange' or history.parent!=directory
                or not history.name.startswith('git-') or not history.name[4:].isdigit()):
            raise PermissionError('Git recovery history escapes its bound transaction')
        try:
            expected_guard=state/'workspace-transactions'/(workspace_key(Path(repository).stat())+'.git-pending.json')
            if item['guard']!=str(expected_guard):raise PermissionError('Git recovery guard is not bound to repository')
            retired=recovery_guards.retired_slot(bundle_base,git_index)
            actual,_=_read_private_json(expected_guard if os.path.lexists(expected_guard) else retired/'captured')
            if actual!=item['guard_payload'] or actual.get('plan')!=item['plan']:
                raise PermissionError('Git recovery guard payload differs from transaction')
            from agentporter.sandbox.workspace_git_recovery import inspect_git_reconciliation
            observed=inspect_git_reconciliation(repository,history,expected_guard,retired_guard=retired,
                pull_registry=pull_registry,pull_state_dir=state,pull_owner_config_dir=pull_owner_config_dir)
            from agentporter.sandbox.workspace_git_recovery import inspect_git_phases
            original_guard=inspect_git_phases(repository,history/'raw-before')['events'][0]['payload']['guard_record']
            git_guard_records.append({'path':expected_guard,'record':original_guard,'repository':repository,'history':history,
                                      'inspection':observed})
        except (OSError,PermissionError) as error:
            observed={'status':'conflict','reason':str(error),'apply_supported':False,'guards_retained':True}
        git_inspections.append({'repository':relative,'inspection':observed})
    orphan_git_guard=os.path.lexists(journal.with_name(journal.name.replace('.pending.json','.git-pending.json')))
    if not context['histories'] and orphan_git_guard and 'approved_clone' not in context:
        git_inspections.append({'repository':'.','inspection':{'status':'unbound_git_guard',
            'apply_supported':False,'guards_retained':True}})
    changes=data['changes']
    if not isinstance(changes,list) or len(changes)>100_000:
        raise PermissionError('Invalid schema4 operation list')
    source=f'/proc/self/fd/{root}/.'
    directory_paths=[];directory_states=[]
    if len(context['directories'])>100_000:raise PermissionError('Too many directory operations')
    for index,item in enumerate(context['directories']):
        if not isinstance(item,dict) or set(item)!={'path','operation','intent'}:
            raise PermissionError('Invalid directory operation')
        relative=item['path'];_relative(relative)
        if (item['operation']!='directory-custody/'+str(index)
                or any(relative==p or relative.startswith(p+'/') or p.startswith(relative+'/') for p in directory_paths)):
            raise PermissionError('Overlapping or invalid directory operation')
        observed=inspect_directory(source,relative,directory/item['operation'])
        if observed['intent']!=item['intent']:raise PermissionError('Directory intent differs from journal')
        directory_paths.append(relative)
        directory_states.append({'path':relative,'state':observed['state']})
    def signature(value):
        return isinstance(value,list) and len(value)==7 and all(type(v) is int and v>=0 for v in value)
    def digest(value):
        return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    def original_state(operation):
        path=directory/operation['custody']
        if os.path.lexists(path/'intent.json'):
            return inspect_custody(source,path)
        return None
    def undo_state(operation):
        path=directory/operation['undo_custody']
        if os.path.lexists(path/'intent.json'):
            return inspect_custody(source,path)
        return None
    def inspect(operation):
        current=_current_hash(root,operation['path'])
        original=original_state(operation) if operation['op']!='create' else None
        undone=undo_state(operation)
        if undone is not None and (not undone['expected'] or undone['state'] not in {'captured_expected','captured_conflict'}):
            raise PermissionError('Rollback candidate custody belongs to later owner work')
        if operation['op']!='create':
            if original is not None and original['state'] in {'captured_expected','captured_conflict'} and original['expected']:
                held=True
            elif original is None or original['state'] in {'uncaptured','restored'}:
                held=False
            else:
                raise PermissionError('Original custody conflicts with later owner work')
            if current==operation['before_sha256'] and not held:
                # Distinguish an unchanged original from a verified rename back;
                # no equal-byte owner inode is ever accepted as the baseline.
                _restored_signature(source,operation['path'],operation['original'],operation['original']['signature'],
                                    renamed=original is not None and original['state']=='restored')
                return 'baseline'
            if not held:raise PermissionError('Original inode is not retained for rollback')
        if current is None:
            return 'baseline' if operation['op']=='create' else 'restore_pending'
        candidate=operation['candidate']
        if candidate is not None and current==operation['staged_sha256']:
            _restored_signature(source,operation['path'],candidate,candidate['signature'],renamed=True)
            if undone is not None:raise PermissionError('Published candidate exists alongside retained rollback custody')
            return 'published'
        raise PermissionError('Rollback conflicts with later owner identity or content')
    paths=set();files=[]
    for index,operation in enumerate(changes):
        base={'op','path','before_sha256','state','staged_sha256','candidate','published_signature',
              'custody','undo_custody','support','undo_support'}
        if not isinstance(operation,dict) or operation.get('op') not in {'create','replace','delete'}:
            raise PermissionError('Invalid schema4 operation')
        relative=operation['path'];_relative(relative)
        if any(relative==p or relative.startswith(p+'/') or p.startswith(relative+'/') for p in directory_paths):
            raise PermissionError('File operation overlaps atomic directory publication')
        if relative in paths or operation['state'] not in {'pending','applied'}:
            raise PermissionError('Duplicate or invalid schema4 operation state')
        paths.add(relative)
        if operation['custody']!='custody/'+str(index) or operation['undo_custody']!='rollback-custody/'+str(index):
            raise PermissionError('Custody operation path differs from journal identity')
        if operation['op']=='create':
            if set(operation)!=base or operation['before_sha256'] is not None:
                raise PermissionError('Invalid schema4 create')
        else:
            if set(operation)!=base|{'original','backup'} or not digest(operation['before_sha256']):
                raise PermissionError('Invalid schema4 original operation')
            original=operation['original']
            if (not isinstance(original,dict) or set(original)!={'signature','sha256','backup_signature','mode','uid','gid','atime_ns','mtime_ns','xattrs'}
                    or not signature(original['signature']) or not signature(original['backup_signature'])
                    or original['sha256']!=operation['before_sha256']):
                raise PermissionError('Invalid schema4 original identity')
            backup=('deletions/' if operation['op']=='delete' else 'originals/')+str(index)
            if operation['backup']!=backup:raise PermissionError('Invalid schema4 original backup path')
            with _workspace_parent(directory,backup) as (parent,name):
                descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                try:_read_deletion_file(descriptor,expected_signature=original['backup_signature'],expected_sha256=original['sha256'])
                finally:os.close(descriptor)
        if operation['op']=='delete':
            if any(operation[key] is not None for key in ('staged_sha256','candidate','published_signature')):
                raise PermissionError('Deletion has an unexpected staged candidate')
        else:
            if not digest(operation['staged_sha256']):raise PermissionError('Invalid schema4 staged digest')
            candidate=operation['candidate']
            if candidate is not None and (not isinstance(candidate,dict)
                    or set(candidate)!={'signature','sha256','mode','uid','gid','mtime_ns','xattrs'}
                    or not signature(candidate['signature']) or candidate['sha256']!=operation['staged_sha256']):
                raise PermissionError('Invalid schema4 prepared candidate')
        # Validate ALL protected storage and source parents before any rollback.
        for path,key in (('custody','support'),('undo_custody','undo_support')):
            actual=preflight_workspace_custody(source,relative,directory/operation[path])
            if actual!=operation[key]:raise PermissionError('Recovery mount or parent differs from captured support')
        try:status=inspect(operation)
        except (OSError,PermissionError):status='conflict'
        files.append({'path':relative,'state':status,'operation_index':index})
    plan={'status':'planned','schema':4,'mode':'rollback_to_exact_original_inodes','workspace':str(workspace),
          'transaction':str(directory),'journal_sha256':journal_hash,'files':files,'guard_retained':True,
          'retention':context['retention'],'journal_signature':journal_signature,
          'recovery_bundle_sha256':hashlib.sha256(json.dumps(existing_bundle,sort_keys=True,separators=(',',':')).encode()).hexdigest() if existing_bundle is not None else None}
    if directory_states:plan['directories']=directory_states
    if git_inspections:plan['git']=git_inspections
    plan_hash=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    plan['plan_sha256']=plan_hash
    if not apply:return plan
    if any(not item['inspection'].get('apply_supported') for item in git_inspections):
        raise PermissionError('Git rollback inspection retained both guards; coherent Git apply remains unsupported')
    if not restore_deletions or expected_plan_sha256!=plan_hash:
        raise PermissionError('Schema4 rollback needs explicit restore mode and exact reviewed plan SHA256')
    if any(entry['state']=='conflict' for entry in files+directory_states):
        raise PermissionError('Schema4 rollback conflicts with owner work; all guards and custody retained')
    database=state/'jobs.db';info=database.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077):
        raise PermissionError('Untrusted schema4 job database')
    connection=sqlite3.connect(database)
    try:
        connection.execute('SELECT job_id,status,workspace_transaction FROM jobs LIMIT 0')
        connection.execute('SELECT token,job_id FROM job_admissions LIMIT 0')
        connection.execute('BEGIN IMMEDIATE')
        if connection.execute("SELECT 1 FROM jobs WHERE workspace_transaction=? AND status NOT IN ('cleanup_failed','finalizing','recovered') LIMIT 1",(str(directory),)).fetchone():
            raise PermissionError('Matching job is not in an inspected recovery state')
        for item in git_guard_records:_pull_admission(connection,item,parent_workspace=workspace)
        bundle=recovery_guards.prepare(bundle_base,state=state,workspace=workspace,transaction=directory,
            journal=journal,journal_hash=journal_hash,journal_signature=journal_signature,git_guards=git_guard_records)
        from agentporter.sandbox import git_metadata_custody as bridge
        from agentporter.sandbox import git_original_metadata as originals
        metadata_preflights=[]
        for item in git_guard_records:
            inspected=item['inspection'];storage=item['history']/'metadata-rollback'
            for entry in inspected['original_restore_plan']:
                originals.preflight_restore(item['repository'],Path(inspected['preserved_originals_directory']),entry['path'])
            if inspected['metadata_capture_plan']:
                storage.mkdir(mode=0o700,exist_ok=True);_directory(storage,private=True)
            for entry in inspected['metadata_capture_plan']:
                operation=storage/entry['slot']
                support=bridge.preflight_git_entry(item['repository'],entry['path'],operation,
                    identity=inspected['metadata_identity'],parents=inspected['metadata_parents'],
                    approved_paths=tuple(inspected['metadata_approved_paths']))
                metadata_preflights.append((item,entry,operation,support))
        for operation in changes:
            status=inspect(operation)
            if status=='published':
                candidate=operation['candidate']
                verified=_restored_signature(source,operation['path'],candidate,candidate['signature'],renamed=True)
                record={**candidate,'signature':verified}
                delete_workspace_file(source,operation['path'],expected_signature=verified,
                    expected_sha256=record['sha256'],expected_record=record,
                    custody_operation=directory/operation['undo_custody'],expected_support=operation['undo_support'])
                status='baseline' if operation['op']=='create' else 'restore_pending'
            if status=='restore_pending':
                result=restore_custody(source,directory/operation['custody'])
                if result['state']!='restored' or not result['expected']:
                    raise PermissionError('Exact original inode restoration is unresolved')
        if any(inspect(operation)!='baseline' for operation in changes):
            raise PermissionError('Exact inode rollback endpoint could not be verified')
        for item in reversed(context['directories']):
            rollback_directory(source,item['path'],directory/item['operation'])
        for item in context['directories']:
            observed=inspect_directory(source,item['path'],directory/item['operation'])
            if observed['intent']!=item['intent'] or observed['state'] not in {'prepared','rolled_back'}:
                raise PermissionError('Directory rollback endpoint is unresolved')
        for item,entry,operation,support in metadata_preflights:
            inspected=item['inspection']
            bridge.capture_git_entry(item['repository'],entry['path'],operation,
                identity=inspected['metadata_identity'],parents=inspected['metadata_parents'],
                approved_paths=tuple(inspected['metadata_approved_paths']),expected_record=entry['record'],expected_support=support)
        from agentporter.sandbox import git_original_metadata as originals
        for item in git_guard_records:
            inspected=item['inspection']
            for operation in inspected['original_restore_plan']:
                originals.restore_original(item['repository'],Path(inspected['preserved_originals_directory']),
                    operation['path'],proven_after=operation['proven_after'])
        for index,item in enumerate(git_guard_records):
            verified=inspect_git_reconciliation(item['repository'],item['history'],item['path'],
                retired_guard=recovery_guards.retired_slot(bundle_base,index),pull_registry=pull_registry,
                pull_state_dir=state,pull_owner_config_dir=pull_owner_config_dir)
            if not verified['apply_supported'] or not verified['before_endpoint_verified']:
                raise PermissionError('Unchanged Git before endpoint no longer holds')
        receipts=state/'recovery-receipts';receipts.mkdir(mode=0o700,exist_ok=True);_directory(receipts,private=True)
        receipt=receipts/(directory.name+'.rollback.json')
        report={**plan,'status':'recovered','endpoint':'before','operator_uid':os.getuid()}
        if os.path.lexists(receipt):
            old,_=_read_private_json(receipt)
            if (old.get('journal_sha256')!=journal_hash or old.get('transaction')!=str(directory)
                    or old.get('workspace')!=str(workspace) or old.get('endpoint')!='before' or old.get('status')!='recovered'):
                raise PermissionError('Terminal custody receipt conflicts with journal')
        else:_write_receipt(receipt,report)
        with connection:
            for item in git_guard_records:_pull_admission(connection,item,resolve=True,parent_workspace=workspace)
            ids=[row[0] for row in connection.execute("SELECT job_id FROM jobs WHERE workspace_transaction=? AND status IN ('cleanup_failed','finalizing','recovered')",(str(directory),))]
            for job_id in ids:
                connection.execute("UPDATE jobs SET status='recovered',exit_code=1,finished_at=COALESCE(finished_at,?) WHERE job_id=?",(time.time(),job_id))
                if 'approved_clone' not in context:connection.execute('DELETE FROM job_admissions WHERE job_id=?',(job_id,))
        recovery_guards.retire(bundle_base,bundle)
        if 'approved_clone' in context:
            return {**report,'guard_retained':True,'workspace_guard_retained':False,
                    'clone_recovery_required':True,'receipt':str(receipt)}
        return {**report,'guard_retained':False,'receipt':str(receipt)}
    finally:connection.close()


def recover_workspace(state_dir, workspace, *, apply=False, expected_plan_sha256=None,
                      restore_deletions=False,pull_registry=None,pull_owner_config_dir=None):
    state = Path(state_dir).resolve(strict=True)
    workspace = Path(workspace).resolve(strict=True)
    transactions = state / 'workspace-transactions'
    if state == workspace or state.is_relative_to(workspace):
        raise PermissionError('Recovery state must be outside the workspace')
    from agentporter.sandbox.common_publication import preflight_common_publication
    from agentporter.git_remote_policy import selected_repository
    preflight_common_publication(workspace,transactions)
    with _maintenance(state), mutation_lease(workspace, transactions, allow_pending=True):
        _directory(transactions, private=True)
        selection=selected_repository(workspace,'.',publication=True,state_dir=transactions)
        _,selected,_=selection.__enter__()
        try:root=os.dup(selected)
        except BaseException:
            selection.__exit__(None,None,None);raise
        connection = None
        publication = None
        try:
            identity = os.fstat(root)
            key = workspace_key(identity)
            journal = transactions / (key + '.pending.json')
            if os.path.lexists(journal):
                data, journal_hash = _read_journal(journal)
            else:
                from agentporter.sandbox import recovery_guards
                unfinished=recovery_guards.find_unfinished(state,key,workspace)
                if unfinished is None:raise FileNotFoundError('No pending workspace publication or unfinished guard retirement')
                base,bundle=unfinished
                from agentporter.sandbox.workspace_custody import inspect_custody
                held=inspect_custody(transactions,base/'workspace')
                if held['state']!='captured_expected' or not held['expected']:
                    raise PermissionError('Missing workspace journal has no exact retained guard')
                data,journal_hash=_read_journal(base/'workspace-backup.json')
                if journal_hash!=bundle['journal_sha256'] or data['transaction']!=bundle['transaction']:
                    raise PermissionError('Retained recovery journal differs from bound bundle')
            if data['workspace'] != str(workspace) or not isinstance(data['transaction'], str):
                raise PermissionError('Recovery workspace identity does not match journal')
            directory = Path(data['transaction'])
            if directory.parent != transactions or not directory.name.startswith(key[:12] + '-'):
                raise PermissionError('Recovery transaction is outside private storage')
            _directory(directory, private=True)
            if data.get('schema') == 4:
                return _custody_rollback(data,journal_hash,directory,workspace,root,state,journal,
                    apply=apply,expected_plan_sha256=expected_plan_sha256,restore_deletions=restore_deletions,
                    pull_registry=pull_registry,pull_owner_config_dir=pull_owner_config_dir)
            if data.get('schema') == 3:
                return _rollback_journal(data, journal_hash, directory, workspace, root, state, journal,
                    apply=apply, expected_plan_sha256=expected_plan_sha256, restore_deletions=restore_deletions)
            if data.get('schema') == 2:
                return _restore_deletion_journal(data, journal_hash, directory, workspace, root,
                    apply=apply, expected_plan_sha256=expected_plan_sha256, restore_deletions=restore_deletions)
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
            raise PermissionError('Legacy schema1 apply requires reviewed custody migration; inspection remains available')
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
            selection.__exit__(None,None,None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--owner-config-dir')
    parser.add_argument('--workspace-registry-json')
    parser.add_argument('--expect-plan-sha256')
    parser.add_argument('--restore-deletions', action='store_true',
                        help='Restore only recorded deleted files; retain guards for owner reconciliation')
    arguments = parser.parse_args()
    try:
        worker_uid = pwd.getpwnam('agentporter-worker').pw_uid
    except KeyError:
        parser.error('The Gateway worker account is not installed')
    if os.getuid() == 0 or os.geteuid() != os.getuid() or os.getuid() != worker_uid:
        parser.error('Run as agentporter-worker, never as root or another user')
    try:
        registry=None
        if arguments.workspace_registry_json:
            from agentporter.workspaces.registry import WorkspaceRegistry
            definitions,_=_read_private_json(Path(arguments.workspace_registry_json))
            registry=WorkspaceRegistry(definitions)
        result = recover_workspace(arguments.state_dir, arguments.workspace, apply=arguments.apply,
                                   expected_plan_sha256=arguments.expect_plan_sha256,
                                   restore_deletions=arguments.restore_deletions,pull_registry=registry,
                                   pull_owner_config_dir=arguments.owner_config_dir)
    except (OSError, ValueError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
