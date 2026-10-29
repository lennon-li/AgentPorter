"""Real private-workspace execution followed by controlled edit application."""
import os
import subprocess
from pathlib import Path
import pytest
from agentporter.sandbox import workspace_transactions as transactions

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='BCC overlay integration requires its installed sandbox')

BWRAP = '/opt/agentporter-bcc/bin/bwrap'


def launch(transaction, script):
    if not Path(BWRAP).exists():
        pytest.skip('BCC overlay sandbox unavailable')
    args = [BWRAP, '--unshare-all', '--unshare-net', '--die-with-parent']
    for name in ('/usr', '/bin', '/lib', '/lib64'):
        if Path(name).exists():
            args += ['--ro-bind', name, name]
    args += ['--dev', '/dev', '--proc', '/proc', '--bind', str(transaction.workspace), '/workspace']
    return subprocess.run(transaction.wrap_command(args) + ['--', *transaction.wrap_argv(['/bin/sh', '-c', script])], pass_fds=transaction.launch_fds, capture_output=True, timeout=20)


def setup(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('original')
    return root, tmp_path / 'state'


def test_private_edit_is_applied_only_after_explicit_finalization(tmp_path):
    root, state = setup(tmp_path)
    transaction = transactions.WorkspaceTransaction(root, state)
    assert launch(transaction, 'printf changed > /workspace/ordinary').returncode == 0
    assert (root / 'ordinary').read_text() == 'original'
    transaction.publish()
    assert (root / 'ordinary').read_text() == 'changed'
    transaction.close()


def test_existing_nested_git_history_cannot_be_applied(tmp_path):
    root, state = setup(tmp_path)
    nested = root / 'nested/.git/refs/heads'
    nested.mkdir(parents=True)
    (nested / 'main').write_text('canonical')
    transaction = transactions.WorkspaceTransaction(root, state)
    assert launch(transaction, 'printf bypass > /workspace/nested/.git/refs/heads/main').returncode == 0
    with pytest.raises(PermissionError):
        transaction.publish()
    assert (nested / 'main').read_text() == 'canonical'
    transaction.close()


def test_conflicting_owner_edit_is_retained(tmp_path):
    root, state = setup(tmp_path)
    transaction = transactions.WorkspaceTransaction(root, state)
    assert launch(transaction, 'printf job > /workspace/ordinary').returncode == 0
    (root / 'ordinary').write_text('owner')
    with pytest.raises(PermissionError):
        transaction.publish()
    assert (root / 'ordinary').read_text() == 'owner'
    transaction.close()


def test_existing_secret_is_hidden_from_job(tmp_path):
    root, state = setup(tmp_path)
    (root / '.envrc').write_text('synthetic-secret')
    transaction = transactions.WorkspaceTransaction(root, state)
    result = launch(transaction, 'cat /workspace/.envrc')
    assert b'synthetic-secret' not in result.stdout
    transaction.close()


def test_concurrent_transaction_is_rejected(tmp_path):
    root, state = setup(tmp_path)
    first = transactions.WorkspaceTransaction(root, state)
    try:
        with pytest.raises(PermissionError):
            transactions.WorkspaceTransaction(root, state)
    finally:
        first.close()


class RecordingLease:
    def __init__(self, *, fail=False):
        self.closed = False
        self.fail = fail
        self.on_close = None
    def command(self, command):
        return command
    def close(self):
        if self.fail:
            from agentporter.resources import ResourceCleanupError
            raise ResourceCleanupError('synthetic failed quiescence proof')
        if self.on_close is not None:
            self.on_close()
        self.closed = True
    def terminate(self):
        pass


class RecordingResources:
    def __init__(self, *, fail=False):
        self.lease = RecordingLease(fail=fail)
    def create(self):
        return self.lease


def test_synchronous_execution_applies_edit_after_resource_cleanup(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    def assert_not_published_yet():
        assert (root / 'ordinary').read_text() == 'original'
    sandbox.resources.lease.on_close = assert_not_published_yet
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'printf changed > /workspace/ordinary'])
    assert result['exit_code'] == 0, result
    assert sandbox.resources.lease.closed
    assert (root / 'ordinary').read_text() == 'changed'


def test_synchronous_cleanup_failure_never_applies_edits(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    from agentporter.resources import ResourceCleanupError
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources(fail=True)
    with pytest.raises(ResourceCleanupError):
        sandbox.run(str(root), ['/bin/sh', '-c', 'printf changed > /workspace/ordinary'])
    assert (root / 'ordinary').read_text() == 'original'
    assert len(sandbox._unresolved_transactions) == 1
    assert sandbox._unresolved_transactions[0].upper.is_dir()
    # Resolve the test double's failed proof before cleaning its private fixture.
    sandbox.resources.lease.fail = False
    sandbox.resources.lease.close()
    sandbox._unresolved_transactions[0].close()


def test_synchronous_failed_job_discards_private_changes(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'printf changed > /workspace/ordinary; exit 7'])
    assert result['exit_code'] == 7
    assert (root / 'ordinary').read_text() == 'original'


def test_synchronous_nested_history_write_is_not_published(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    nested = root / 'nested/.git/refs/heads'
    nested.mkdir(parents=True)
    (nested / 'main').write_text('canonical')
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'printf bypass > /workspace/nested/.git/refs/heads/main'])
    assert result['exit_code'] != 0
    assert (nested / 'main').read_text() == 'canonical'


def test_recovery_guard_survives_interrupted_publication(tmp_path, monkeypatch):
    from agentporter.resources import ResourceCleanupError
    root, state = setup(tmp_path)
    transaction = transactions.WorkspaceTransaction(root, state)
    assert launch(transaction, 'printf changed > /workspace/ordinary').returncode == 0
    def fail_publication(*args, **kwargs):
        raise OSError('synthetic publication failure')
    monkeypatch.setattr(transactions, 'publish_workspace_file', fail_publication)
    with pytest.raises(ResourceCleanupError):
        transaction.publish()
    assert transaction._pending.is_file()
    assert transaction.upper.is_dir()
    with pytest.raises(ResourceCleanupError):
        transaction.close()
    # Simulate loss of the owner process's lock while leaving its durable guard.
    os.close(transaction._root_fd)
    os.close(transaction._lock)
    transaction._closed = True
    with pytest.raises(ResourceCleanupError):
        transactions.WorkspaceTransaction(root, state)
    assert (root / 'ordinary').read_text() == 'original'
    # Test-only cleanup after verifying the retained recovery evidence.
    transaction._pending.unlink()
    internal_work = transaction.work / 'work'
    if internal_work.exists():
        internal_work.chmod(0o700)


def test_synchronous_hardlink_alias_fails_before_command_launch(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    refs = root / '.git/refs/heads'
    refs.mkdir(parents=True)
    (refs / 'main').write_text('canonical')
    os.link(refs / 'main', root / 'alias')
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    with pytest.raises(PermissionError):
        sandbox.run(str(root), ['/bin/sh', '-c', 'printf bypass > /workspace/alias'])
    assert (refs / 'main').read_text() == 'canonical'


def test_transaction_mode_requires_resource_envelope(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    with pytest.raises(PermissionError):
        sandbox.run(str(root), ['/bin/true'])


def test_root_replacement_cannot_redirect_file_application(tmp_path):
    root, state = setup(tmp_path)
    transaction = transactions.WorkspaceTransaction(root, state)
    try:
        assert launch(transaction, 'printf changed > /workspace/ordinary').returncode == 0
        original = root.with_name('original-project')
        root.rename(original)
        root.mkdir()
        (root / 'ordinary').write_text('original')
        with pytest.raises(PermissionError):
            transaction.publish()
        assert (root / 'ordinary').read_text() == 'original'
        assert (original / 'ordinary').read_text() == 'original'
    finally:
        transaction.close()


def test_prepared_command_keeps_original_root_after_path_replacement(tmp_path):
    root, state = setup(tmp_path)
    transaction = transactions.WorkspaceTransaction(root, state)
    try:
        args = [BWRAP, '--unshare-all', '--unshare-net', '--die-with-parent']
        for name in ('/usr', '/bin', '/lib', '/lib64'):
            if Path(name).exists():
                args += ['--ro-bind', name, name]
        args += ['--dev', '/dev', '--proc', '/proc', '--bind', str(root), '/workspace']
        command = transaction.wrap_command(args)
        original = root.with_name('original-project')
        root.rename(original)
        root.mkdir()
        (root / 'ordinary').write_text('replacement')
        result = subprocess.run(command + ['--', '/bin/cat', '/workspace/ordinary'],
            pass_fds=(transaction._root_fd,), capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert result.stdout == b'original'
    finally:
        transaction.close()


def test_readonly_command_hides_existing_secrets_and_denies_writes(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    (root / '.envrc').write_text('synthetic-secret')
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'cat /workspace/.envrc; printf changed > /workspace/ordinary'], writable=False)
    assert b'synthetic-secret' not in result['stdout'].encode()
    assert result['exit_code'] != 0
    assert (root / 'ordinary').read_text() == 'original'


def test_generic_worker_does_not_inherit_host_workspace_descriptor(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    script = "import os; print([os.readlink('/proc/self/fd/'+name) for name in os.listdir('/proc/self/fd') if name not in {'0','1','2'} and os.path.exists('/proc/self/fd/'+name)])"
    result = sandbox.run(str(root), ['/usr/bin/python3', '-c', script])
    assert result['exit_code'] == 0, result
    assert result['stdout'].strip() == '[]'


def test_masked_secret_does_not_prevent_ordinary_file_application(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    (root / '.envrc').write_text('synthetic-secret')
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'cat /workspace/.envrc; printf changed > /workspace/ordinary'])
    assert result['exit_code'] == 0, result
    assert result['stdout'] == ''
    assert (root / 'ordinary').read_text() == 'changed'
    assert (root / '.envrc').read_text() == 'synthetic-secret'


def test_readonly_secret_hardlink_alias_is_rejected(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    (root / '.envrc').write_text('synthetic-secret')
    os.link(root / '.envrc', root / 'alias')
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    with pytest.raises(PermissionError):
        sandbox.run(str(root), ['/bin/cat', '/workspace/alias'], writable=False)


def test_large_untouched_project_data_does_not_block_code_edit(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    with (root / 'scientific-data').open('wb') as stream:
        stream.truncate(65 * 1024 * 1024)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'printf changed > /workspace/ordinary'])
    assert result['exit_code'] == 0, result
    assert (root / 'ordinary').read_text() == 'changed'
    assert (root / 'scientific-data').stat().st_size == 65 * 1024 * 1024


def test_failed_job_with_inaccessible_private_directories_releases_workspace(tmp_path):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    root, state = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    sandbox.resources = RecordingResources()
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'mkdir /workspace/private; chmod 000 /workspace/private; exit 7'])
    assert result['exit_code'] == 7
    assert not (root / 'private').exists()
    followup = sandbox.run(str(root), ['/bin/sh', '-c', 'printf healthy > /workspace/ordinary'])
    assert followup['exit_code'] == 0, followup
    assert (root / 'ordinary').read_text() == 'healthy'


def test_private_cleanup_does_not_chmod_symlink_target(tmp_path):
    root, state = setup(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o500)
    transaction = transactions.WorkspaceTransaction(root, state)
    (transaction.upper / 'alias').symlink_to(outside, target_is_directory=True)
    transaction.close()
    assert outside.stat().st_mode & 0o777 == 0o500
