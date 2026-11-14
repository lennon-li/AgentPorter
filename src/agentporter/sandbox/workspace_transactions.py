"""Private overlay storage and controlled application for one workspace job.

Internal callers must stop and verify the complete job envelope before publish
or close. An interrupted publication retains a durable guard for owner recovery.
This serializes transactional jobs; other mutation tools must share the lease
before this can be enabled for a production workspace.
"""
import fcntl
import base64
import hashlib
import functools
import threading
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import workspace_key
from agentporter.sandbox.workspace_delta import (
    UnsafeWorkspaceDelta, _require_public_path, publish_workspace_file,
    validate_workspace_delta, backup_workspace_deletion, delete_workspace_file,
    publish_rollbackable_workspace_file, _workspace_parent, _file_signature,
)


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _fingerprint(path: Path, *, expected_signature=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if expected_signature is not None and _signature(before) != expected_signature:
            raise UnsafeWorkspaceDelta('Workspace edit conflicts with owner changes')
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024 * 1024:
            raise UnsafeWorkspaceDelta('Unsupported workspace baseline file')
        digest = hashlib.sha256()
        remaining = 64 * 1024 * 1024 + 1
        while chunk := os.read(descriptor, min(65536, remaining)):
            remaining -= len(chunk)
            if remaining <= 0:
                raise UnsafeWorkspaceDelta('Workspace baseline file exceeds size limit')
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise UnsafeWorkspaceDelta('Workspace file changed during baseline capture')
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _transaction_lifecycle(method):
    @functools.wraps(method)
    def locked(self, *args, **kwargs):
        with self._lifecycle_lock:
            return method(self, *args, **kwargs)
    return locked


class WorkspaceTransaction:
    _private_pull_guard_supported = True

    def __init__(self, workspace: Path, state: Path, *, max_entries=1_000_000, writable=True, git_sandbox=None, allow_git_birth=False):
        self._lifecycle_lock = threading.RLock()
        self.writable = writable
        self.git_sandbox=git_sandbox
        self._allow_git_birth=allow_git_birth is True
        self.git_histories = {}
        from agentporter.sandbox.git_snapshot import SnapshotBudget
        self._git_snapshot_budget = SnapshotBudget()
        self._runtime_view_fd = None
        self._runtime_namespace_fds = None
        self.workspace = Path(workspace).resolve(strict=True)
        state = Path(state).resolve()
        if state == self.workspace or state.is_relative_to(self.workspace):
            raise PermissionError('Workspace transaction state must be outside the workspace')
        from agentporter.sandbox.common_publication import preflight_common_publication
        if writable:preflight_common_publication(self.workspace,state)
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity = self.workspace.stat()
        key = workspace_key(identity)
        self._lock = os.open(state / (key + '.lock'), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        self._pending = state / (key + '.pending.json')
        self._started = False
        self._closed = False
        self._applied = False
        self._retain_directory = False
        self.directory = None
        self._root_fd = None
        self._projection_fd = None
        self._publication_fd = None
        try:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PermissionError('Workspace already has an active transaction') from error
            if os.path.lexists(self._pending) or os.path.lexists(state / (key + '.git-pending.json')):
                raise ResourceCleanupError('Workspace publication requires owner recovery')
            from agentporter.sandbox.recovery_guards import find_unfinished
            if find_unfinished(state.parent,key,self.workspace) is not None:
                raise ResourceCleanupError('Workspace recovery guard retirement remains unfinished')
            # Foreign-owned roots can be private (0700), and Git metadata files
            # can be owner-only. Pin their identity with O_PATH; all data reads
            # go through the verified idmapped read-only projection.
            foreign_owner = identity.st_uid != os.getuid()
            access = os.O_PATH if foreign_owner else os.O_RDONLY
            self._root_fd = os.open(self.workspace, access | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            pinned = os.fstat(self._root_fd)
            if (pinned.st_dev, pinned.st_ino) != (identity.st_dev, identity.st_ino):
                raise PermissionError('Workspace root changed during transaction creation')
            if foreign_owner:
                from agentporter.sandbox.workspace_projections import open_workspace_projection
                self._projection_fd = open_workspace_projection(self._root_fd)
                if writable:
                    from agentporter.sandbox.workspace_projections import open_workspace_publication
                    self._publication_fd = open_workspace_publication(self._root_fd, state_dir=state)
            data_fd = self._publication_fd
            if data_fd is None:
                data_fd = self._projection_fd
            if data_fd is None:
                data_fd = self._root_fd
            self._root_path = f'/proc/self/fd/{data_fd}/.'
            self.directory = Path(tempfile.mkdtemp(prefix=key[:12] + '-', dir=state))
            self.upper = self.directory / 'upper'
            self.work = self.directory / 'work'
            self.upper.mkdir(mode=0o700)
            self.work.mkdir(mode=0o700)
            self.baseline = {}
            self.baseline_directories = set()
            self._birth_empty_directories = {}
            self.masks = []
            remaining = max_entries
            scan_deadline = time.monotonic() + 30
            def failed(error):
                raise PermissionError('Cannot inspect workspace baseline') from error
            for root, directories, files in os.walk(self._root_path, followlinks=False, onerror=failed):
                if self._allow_git_birth and root != self._root_path and not directories and not files:
                    from agentporter.sandbox.workspace_directories import _directory_record
                    rel=Path(root).relative_to(Path(self._root_path)).as_posix()
                    with _workspace_parent(self._root_path,rel+'/placeholder') as (current,_):
                        self._birth_empty_directories[rel]=_directory_record(current,'.')
                for name in list(directories) + files:
                    remaining -= 1
                    if remaining < 0 or time.monotonic() >= scan_deadline:
                        raise PermissionError('Workspace baseline exceeds scan budget')
                    path = Path(root) / name
                    relative = path.relative_to(Path(self._root_path)).as_posix()
                    if relative == '.venv' and path.is_symlink():
                        raise PermissionError('Symlinked excluded development environment is not allowed')
                    try:
                        _require_public_path(relative)
                    except PermissionError:
                        if name in directories:
                            directories.remove(name)
                        # Git metadata stays available for read-only Git inspection;
                        # any private overlay changes are rejected before application.
                        if name.lower() == '.git' and path.is_symlink():
                            raise PermissionError('Symlinked Git metadata cannot be delegated')
                        if name.lower() == '.git' and path.is_file():
                            raise PermissionError('Linked Git worktree metadata cannot be delegated')
                        if name.lower() == '.git' and path.is_dir():
                            # Every admitted repository needs the private
                            # metadata view. _MetadataMount currently requires
                            # a real local config, so reject configless or
                            # incomplete repositories before running Git over
                            # any linked/common metadata paths.
                            if name != '.git' or git_sandbox is None:
                                raise PermissionError('Git metadata requires a private worker view')
                            if not (path / 'HEAD').is_file() or not (path / 'config').is_file():
                                raise PermissionError('Incomplete Git metadata cannot be delegated')
                            metadata_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                            try:
                                metadata = Path(f'/proc/self/fd/{metadata_fd}')
                                if os.path.lexists(metadata / 'objects/info/alternates'):
                                    raise PermissionError('Git metadata with external object alternates cannot be delegated')
                                from agentporter.sandbox.workspace_git import _reject_excluded_git_paths
                                _reject_excluded_git_paths(metadata, pass_fds=(metadata_fd,))
                            finally:
                                os.close(metadata_fd)
                        if name == '.git' and path.is_dir():
                            from agentporter.sandbox.workspace_git import WorkspaceGitHistory
                            # Trusted imports need the same owner-mapped view
                            # as ordinary publication, never the foreign-owned
                            # canonical mount. Both have the same dev/inode key.
                            repository = Path(self._root_path) / Path(relative).parent
                            self.git_histories[relative] = WorkspaceGitHistory(
                                repository, self.directory / ('git-' + str(len(self.git_histories))),
                                git_sandbox, nested=Path(relative).parent != Path('.'),
                                snapshot_budget=self._git_snapshot_budget)
                        if name.lower() != '.git':
                            self.masks.append((relative, path.is_dir() and not path.is_symlink()))
                        continue
                    info = path.lstat()
                    if stat.S_ISDIR(info.st_mode):self.baseline_directories.add(relative)
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    if stat.S_ISREG(info.st_mode):
                        if info.st_nlink != 1:
                            raise PermissionError('Workspace file has unsupported inode aliases')
                        if writable:
                            self.baseline[relative] = _signature(info)
                    elif not stat.S_ISDIR(info.st_mode):
                        raise PermissionError('Unsupported workspace baseline entry')
        except BaseException:
            for history in self.git_histories.values():
                history.close()
            if self.directory is not None:
                shutil.rmtree(self.directory)
            if self._publication_fd is not None:
                os.close(self._publication_fd)
            if self._projection_fd is not None:
                os.close(self._projection_fd)
            if self._root_fd is not None:
                os.close(self._root_fd)
            os.close(self._lock)
            self._closed = True
            raise

    def wrap_command(self, command, *, workspace_fd=None):
        """Replace only the exact authorized workspace bind with its overlay."""
        if self._closed or self._applied:
            raise PermissionError('Workspace transaction is no longer executable')
        command = list(command)
        self._check_root_identity()
        source = str(self.workspace)
        lower_fd = self._projection_fd if self._projection_fd is not None else self._root_fd
        overlay_source = f'/proc/self/fd/{lower_fd}'
        if workspace_fd is not None:
            pinned = os.fstat(workspace_fd)
            expected = os.fstat(self._root_fd)
            if (pinned.st_dev, pinned.st_ino) != (expected.st_dev, expected.st_ino):
                raise PermissionError('Pinned workspace does not match transaction identity')
            source = f'/proc/self/fd/{workspace_fd}'
            if self._projection_fd is None:
                overlay_source = source
        mounts = {'--bind', '--ro-bind'} if self.writable else {'--ro-bind'}
        matches = [i for i in range(len(command) - 2)
                   if command[i] in mounts and command[i + 1:i + 3] == [source, '/workspace']]
        if len(matches) != 1 or '--' in command:
            raise PermissionError('Expected one authorized workspace mount before command boundary')
        index = matches[0]
        if self.writable:
            command[index:index + 3] = ['--overlay-src', overlay_source, '--overlay', str(self.upper), str(self.work), '/workspace']
        else:
            command[index:index + 3] = ['--ro-bind', overlay_source, '/workspace']
        for i in range(len(command) - 2):
            if command[i:i + 2] == ['--ro-bind', str(self.workspace / '.git')]:
                command[i + 1] = overlay_source + '/.git'
        for relative, directory in self.masks:
            destination = '/workspace/' + relative
            command += ['--tmpfs', destination, '--remount-ro', destination] if directory else ['--ro-bind', '/dev/null', destination]
        # This is private metadata, not a writable canonical .git mount. The
        # ordinary delta validator remains unchanged and still refuses .git.
        for relative, history in self.git_histories.items():
            destination = '/workspace/' + relative
            command += ['--bind' if self.writable else '--ro-bind', str(history.private), destination,
                        '--ro-bind', str(history.clean_config), destination + '/config']
        return command

    @property
    def launch_fds(self):
        return (self._root_fd,) if self._projection_fd is None else (self._root_fd, self._projection_fd)

    @property
    def inspection_fd(self):
        """The exact read-only lower used for foreign-owner job visibility."""
        return self._projection_fd if self._projection_fd is not None else self._root_fd

    @staticmethod
    def wrap_argv(argv):
        # Bubblewrap needs the pinned mount FD, but the requested command must
        # never receive a host directory capability. Close before exec.
        closer = """import os, sys
for item in os.listdir('/proc/self/fd'):
    descriptor = int(item)
    if descriptor > 2:
        try:
            os.close(descriptor)
        except OSError:
            pass
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
"""
        return ['/usr/bin/python3', '-I', '-S', '-c', closer, *argv]

    def _check_root_identity(self):
        pinned = os.fstat(self._root_fd)
        current = self.workspace.stat()
        if (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino):
            raise PermissionError('Workspace root identity changed')

    def _journal(self, changes, *, version=1, update=False):
        document = {'workspace': str(self.workspace), 'transaction': str(self.directory), 'changes': changes}
        if version != 1:
            document['schema'] = version
        if version in (3, 4):
            document['recovery'] = self._recovery_context
        data = json.dumps(document).encode()
        if len(data)>16*1024*1024:
            raise PermissionError('Publication journal exceeds offline recovery limit')
        path = self._pending.with_name(self._pending.name + '.next') if update else self._pending
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(os.dup(descriptor), 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if update:
                os.replace(path, self._pending)
            info=os.fstat(descriptor)
            self._last_journal_record={'signature':list(_signature(info)), 'sha256':hashlib.sha256(data).hexdigest(),
                'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'mtime_ns':info.st_mtime_ns,
                'xattrs':{name:base64.b64encode(os.getxattr(descriptor,name)).decode('ascii') for name in os.listxattr(descriptor)}}
            self._sync_state()
        except BaseException as error:
            if os.path.lexists(self._pending):
                self._started = True
            raise ResourceCleanupError('Workspace publication journal requires recovery') from error
        finally:
            os.close(descriptor)

    def _sync_state(self):
        descriptor = os.open(self._pending.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @_transaction_lifecycle
    def publish_approved_pull(self):
        from agentporter.git_pulls import _PullPublicationIntent
        intent=getattr(self,'_pull_publication_intent',None)
        if not isinstance(intent,_PullPublicationIntent) or intent.transaction is not self:
            raise PermissionError('Coherent pull publication requires its native consumed intent')
        if self._closed or self._started or self._applied:
            raise PermissionError('Pull transaction is no longer publishable')
        intent.prepare()
        self._active_pull_publication=intent
        return self.publish()

    @_transaction_lifecycle
    def publish_approved_clone(self):
        from agentporter.git_clones import ClonePublicationIntent
        intent=getattr(self,'_clone_publication_intent',None)
        if not isinstance(intent,ClonePublicationIntent) or intent.transaction is not self:
            raise PermissionError('Clone publication requires exact consumed host intent')
        intent.validate();self._active_clone_publication=intent
        return self.publish()

    @_transaction_lifecycle
    def publish(self):
        clone=getattr(self,'_active_clone_publication',None)
        if getattr(self,'_private_clone_pending',False) and (clone is None or clone is not getattr(self,'_clone_publication_intent',None)):
            raise ResourceCleanupError('Consumed clone requires coherent publication or owner recovery')
        if clone is not None:clone.validate()
        intent=getattr(self,'_active_pull_publication',None)
        if getattr(self,'_private_pull_pending',False) and (intent is None or intent is not getattr(self,'_pull_publication_intent',None)):
            raise ResourceCleanupError('Private approved pull requires coherent tracking publication/recovery; candidate retained')
        """Publish schema4 using retained originals and create-only candidates."""
        if self._closed or self._started or self._applied:
            raise PermissionError('Workspace transaction cannot be published twice')
        self._check_root_identity()
        if not self.writable:
            if any(self.upper.iterdir()):
                raise UnsafeWorkspaceDelta('Read-only workspace transaction produced changes')
            self._applied = True
            return
        from agentporter.sandbox.workspace_custody import preflight_workspace_custody, inspect_custody
        from agentporter.sandbox.workspace_recovery import _restored_signature, _write_receipt
        from agentporter.sandbox.workspace_directories import prepare_directory, publish_directory, inspect_directory
        from agentporter.sandbox.repository_birth import discover
        births = discover(self)
        deletions = validate_workspace_delta(self.upper, deletion_baseline=self.baseline, repository_births=births)
        for history in self.git_histories.values():
            history.prepare()
            history_intent = history._pull_intent
            if history_intent is None and any(
                    history.plan['before'][field] != history.plan['after'][field]
                    for field in ('head', 'branch', 'refs', 'stash_log')):
                # Enforce after arbitrary worker code, including raw Git or
                # Python writes that bypass CLI deny lists. Ordinary edits and
                # index staging remain publishable; history needs its separate
                # trusted backend and consumed authorization.
                raise PermissionError('Worker Git history change requires independent owner approval')
            if history_intent is not None:
                expected = json.loads(history_intent.expected_private)
                before, after = history.plan['before'], history.plan['after']
                local_refs = set(before['refs']) | set(after['refs'])
                unauthorized_ref = any(
                    name != expected['branch']
                    and (name.startswith(('refs/heads/', 'refs/tags/')) or name == 'refs/stash')
                    and before['refs'].get(name) != after['refs'].get(name)
                    for name in local_refs)
                if (unauthorized_ref or before['stash_log'] != after['stash_log']
                        or any(after[field] != expected[field] for field in ('head', 'branch'))):
                    raise PermissionError('Approved inbound Git cannot expand worker history authority')
        changes = [];new_trees=[]
        for root, dirs, files in os.walk(self.upper):
            for name in list(dirs):
                relative=(Path(root)/name).relative_to(self.upper).as_posix()
                if births is not None and relative in births.replacement_paths():
                    new_trees.append(relative);dirs.remove(name)
                    continue
                if not os.path.lexists(Path(self._root_path)/relative):
                    if relative in self.baseline_directories:
                        raise UnsafeWorkspaceDelta('Owner removed an original directory')
                    new_trees.append(relative);dirs.remove(name)
                    continue
                with _workspace_parent(self._root_path,relative+'/placeholder') as (parent,_):
                    if not stat.S_ISDIR(os.fstat(parent).st_mode):
                        raise UnsafeWorkspaceDelta('Unsupported directory publication')
            for name in files:
                relative=(Path(root)/name).relative_to(self.upper).as_posix()
                target=Path(self._root_path)/relative
                expected=self.baseline.get(relative)
                if relative in deletions and expected is None:
                    raise UnsafeWorkspaceDelta('Deletion lacks a captured original')
                if expected is None:
                    if os.path.lexists(target):
                        raise UnsafeWorkspaceDelta('New workspace destination already exists')
                else:
                    expected=_fingerprint(target,expected_signature=expected)
                changes.append((relative,expected))
        if not changes and not new_trees and not any(history.changed for history in self.git_histories.values()):
            self._applied=True
            return
        for name in ('deletions','originals','custody','rollback-custody','directory-custody'):
            (self.directory/name).mkdir(mode=0o700)
        space=os.statvfs(self.directory)
        if space.f_bavail*space.f_frsize < sum(self.baseline[path][4]+4096 for path,expected in changes if expected is not None):
            raise UnsafeWorkspaceDelta('Insufficient original backup space')
        operations=[]
        for index,(relative,expected) in enumerate(sorted(changes)):
            operation={'op':'replace' if expected is not None else 'create','path':relative,
                       'before_sha256':expected,'state':'pending',
                       'staged_sha256':None if relative in deletions else _fingerprint(self.upper/relative),
                       'candidate':None,'published_signature':None,
                       'custody':'custody/'+str(index),'undo_custody':'rollback-custody/'+str(index)}
            operation['support']=preflight_workspace_custody(self._root_path,relative,self.directory/operation['custody'])
            operation['undo_support']=preflight_workspace_custody(self._root_path,relative,self.directory/operation['undo_custody'])
            if expected is not None:
                backup=('deletions/' if relative in deletions else 'originals/')+str(index)
                original=backup_workspace_deletion(self._root_path,relative,self.directory/backup,
                                                    expected_signature=self.baseline[relative])
                if original['sha256'] != expected:
                    raise UnsafeWorkspaceDelta('Original changed after publication preflight')
                operation.update(backup=backup,original=original)
            if relative in deletions:operation['op']='delete'
            operations.append(operation)
        directory_operations=[]
        for index,relative in enumerate(sorted(new_trees)):
            operation='directory-custody/'+str(index)
            directory_intent=prepare_directory(self._root_path,relative,self.directory/operation,
                source=self.upper/relative,mode=stat.S_IMODE((self.upper/relative).stat().st_mode), repository_births=births)
            directory_operations.append({'path':relative,'operation':operation,'intent':directory_intent})
        self._recovery_context={'endpoint':'before','directories':directory_operations, 'retention':'retain_all_custody_no_automatic_purge',
            'histories':[{'repository':Path(relative).parent.as_posix(),
                'guard':str(history.guard) if history.guard is not None else None,
                'guard_payload':None,'plan':history.plan,'exchange':str(history.exchange)}
                for relative,history in self.git_histories.items() if history.changed]}
        if clone is not None:self._recovery_context['approved_clone']=clone.to_payload()
        # All mount/parent/backup preflights finish before this first durable
        # publication intent and before any workspace entry is moved.
        descriptor=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        self._journal(operations,version=4)
        self._started=True
        self._retain_directory=True
        try:
            for history in self.git_histories.values():history.guard_publication()
            for item in self._recovery_context['histories']:
                descriptor=os.open(item['guard'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                with os.fdopen(descriptor,'r') as stream:item['guard_payload']=json.load(stream)
            if self._recovery_context['histories']:self._journal(operations,version=4,update=True)
            for item in directory_operations:
                publish_directory(self._root_path,item['path'],self.directory/item['operation'])
            for operation in operations:
                relative=operation['path']
                if operation['op']=='delete':
                    record=operation['original']
                    delete_workspace_file(self._root_path,relative,expected_signature=record['signature'],
                        expected_sha256=record['sha256'],custody_operation=self.directory/operation['custody'],
                        expected_record=record,expected_support=operation['support'])
                else:
                    def prepared(candidate,*,operation=operation):
                        operation['candidate']=candidate
                        self._journal(operations,version=4,update=True)
                    operation['published_signature']=publish_rollbackable_workspace_file(
                        self._root_path,relative,self.upper/relative,original=operation.get('original'),
                        on_prepared=prepared,custody_operation=self.directory/operation['custody'],
                        expected_support=operation['support'])
                operation['state']='applied'
                self._journal(operations,version=4,update=True)
            for history in self.git_histories.values():history.publish()
            for item in directory_operations:
                observed=inspect_directory(self._root_path,item['path'],self.directory/item['operation'])
                if observed!={'state':'published','intent':item['intent']}:
                    raise UnsafeWorkspaceDelta('Published directory tree changed')
            # Verify actual canonical candidates and original custody together.
            for operation in operations:
                if operation['op']=='delete':
                    with _workspace_parent(self._root_path,operation['path']) as (parent,name):
                        try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                        except FileNotFoundError:pass
                        else:raise UnsafeWorkspaceDelta('Deleted pathname was recreated by owner')
                else:
                    candidate=operation['candidate']
                    _restored_signature(self._root_path,operation['path'],candidate,candidate['signature'],renamed=True)
                if operation['op']!='create':
                    retained=inspect_custody(self._root_path,self.directory/operation['custody'])
                    if not retained['expected'] or retained['state'] not in {'captured_expected','captured_conflict'}:
                        raise UnsafeWorkspaceDelta('Original inode custody is unresolved')
            _write_receipt(self.directory/'publication-receipt.json',
                {'schema':4,'workspace':str(self.workspace),'transaction':str(self.directory),
                 'status':'published','endpoint':'after','retention':self._recovery_context['retention'],
                 'changes':operations,'directories':directory_operations,
                 **({'approved_pull':intent.to_payload()} if intent is not None else {}),
                 **({'approved_clone':clone.to_payload()} if clone is not None else {})})
            if intent is not None:
                from agentporter.sandbox import recovery_guards
                from agentporter.sandbox.workspace_custody import capture_workspace_entry
                base=recovery_guards.location(self.directory.parent.parent,workspace_key(os.fstat(self._root_fd)),self.directory.name)
                bundle=recovery_guards.prepare(base,state=self.directory.parent.parent,workspace=self.workspace,
                    transaction=self.directory,journal=self._pending,journal_hash=self._last_journal_record['sha256'],
                    journal_signature=self._last_journal_record['signature'],
                    git_guards=[{'path':history.guard,'record':history.guard_record}
                                for history in self.git_histories.values() if history.changed])
                for guard in bundle['guards']:
                    path=Path(guard['path'])
                    retired=capture_workspace_entry(path.parent,path.name,base/guard['slot'],
                        expected_record=guard['record'],expected_support=guard['support'])
                    if not retired['expected'] or retired['state']!='captured_expected':
                        raise ResourceCleanupError('Pull publication guard retirement conflicts with owner changes')
                intent.resolve_after_publication()
                recovery_guards._write(base,'done.json',{'schema':1,'workspace':bundle['workspace'],
                    'transaction':bundle['transaction'],'journal_sha256':bundle['journal_sha256']})
                self._private_pull_pending=False
            else:
                for history in self.git_histories.values():history.finish()
                if clone is not None:clone.finish()
                self._pending.unlink()
            self._sync_state()
            self._applied=True
        except BaseException as error:
            raise ResourceCleanupError('Workspace publication interrupted; retained custody requires recovery') from error

    def _restore_cleanup_access(self):
        # The job envelope must be quiescent before close. Operate only through
        # pinned directory descriptors; never chmod a staged symlink target.
        remaining = 1_000_000
        deadline = time.monotonic() + 30
        def restore(descriptor, depth):
            nonlocal remaining
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or depth > 128:
                raise ResourceCleanupError('Private directory cleanup requires owner inspection')
            os.chmod(f'/proc/self/fd/{descriptor}', 0o700)
            readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                with os.scandir(readable) as entries:
                    for entry in entries:
                        remaining -= 1
                        if remaining < 0 or time.monotonic() >= deadline:
                            raise ResourceCleanupError('Private directory cleanup exceeds scan budget')
                        if entry.is_dir(follow_symlinks=False):
                            child = os.open(entry.name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=readable)
                            try:
                                restore(child, depth + 1)
                            finally:
                                os.close(child)
            finally:
                os.close(readable)
        descriptor = os.open(self.directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            restore(descriptor, 0)
        finally:
            os.close(descriptor)

    @_transaction_lifecycle
    def _attach_runtime_view(self, descriptor, namespace_fds):
        """Host-only fixed-bootstrap handoff; never a worker RPC capability."""
        if self._closed or self._applied or self._runtime_view_fd is not None:
            raise PermissionError('Runtime view cannot be rebound')
        import ctypes
        info=os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):raise PermissionError('Runtime view is not a directory')
        buffer=ctypes.create_string_buffer(256)
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.fstatfs(descriptor,ctypes.byref(buffer))!=0 or ctypes.cast(buffer,ctypes.POINTER(ctypes.c_long))[0]!=0x794c7630:
            raise PermissionError('Runtime view is not the trusted workspace overlay')
        import fcntl
        if len(namespace_fds)!=3:raise PermissionError('Trusted runtime namespace capability set required')
        user,mount,root=namespace_fds
        if fcntl.ioctl(user,0xb703)!=0x10000000 or fcntl.ioctl(mount,0xb703)!=0x20000:
            raise PermissionError('Runtime namespace capability types differ')
        owner=fcntl.ioctl(mount,0xb701)
        try:
            if (os.fstat(owner).st_dev,os.fstat(owner).st_ino)!=(os.fstat(user).st_dev,os.fstat(user).st_ino):
                parent=fcntl.ioctl(user,0xb702)
                try:
                    if (os.fstat(owner).st_dev,os.fstat(owner).st_ino)!=(os.fstat(parent).st_dev,os.fstat(parent).st_ino):
                        raise PermissionError('Runtime mount namespace has an unrelated owning user namespace')
                finally:os.close(parent)
            if not stat.S_ISDIR(os.fstat(root).st_mode):
                raise PermissionError('Runtime sandbox root is not a directory')
            owned=[]
            try:
                for descriptor in (descriptor,owner,mount,root):owned.append(os.dup(descriptor))
            except BaseException:
                for descriptor in owned:os.close(descriptor)
                raise
            self._runtime_view_fd=owned[0]
            self._runtime_namespace_fds=tuple(owned[1:])
        finally:os.close(owner)

    @_transaction_lifecycle
    def close(self):
        if self._closed:
            return
        if self._started and not self._applied:
            raise ResourceCleanupError('Workspace publication recovery guard must remain held')
        for history in self.git_histories.values():
            history.close()
        if self._runtime_view_fd is not None:
            os.close(self._runtime_view_fd);self._runtime_view_fd=None
        if self._runtime_namespace_fds is not None:
            for fd in self._runtime_namespace_fds:os.close(fd)
            self._runtime_namespace_fds=None
        try:
            if not self._retain_directory:
                self._restore_cleanup_access()
                shutil.rmtree(self.directory)
        except ResourceCleanupError:
            raise
        except Exception as error:
            raise ResourceCleanupError('Private workspace cleanup remains unverified') from error
        if self._publication_fd is not None:
            os.close(self._publication_fd)
        if self._projection_fd is not None:
            os.close(self._projection_fd)
        os.close(self._root_fd)
        os.close(self._lock)
        self._closed = True
