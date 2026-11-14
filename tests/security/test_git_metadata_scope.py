"""Narrow Git metadata admission and telemetry namespace coverage."""
import os
from pathlib import Path
import subprocess

import pytest

from agentporter.sandbox.git_snapshot import SnapshotBudget
from agentporter.sandbox.workspace_git_recovery import capture_git_baseline
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction


def _init(root):
    root.mkdir()
    subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
    (root / 'tracked').write_text('fixture\n')
    subprocess.run(['/usr/bin/git', '-C', str(root), 'add', 'tracked'], check=True)
    subprocess.run(['/usr/bin/git', '-C', str(root), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)


@pytest.mark.parametrize('writable', [False, True])
@pytest.mark.parametrize('layout', ['missing_config', 'commondir', 'http_alternates'])
def test_incomplete_or_external_metadata_is_rejected_before_worker_admission(tmp_path, writable, layout):
    root = tmp_path / 'repo'
    _init(root)
    if layout == 'commondir':
        (root / '.git/commondir').write_text(str(tmp_path / 'external.git') + '\n')
    elif layout == 'http_alternates':
        (root / '.git/objects/info/http-alternates').write_text('https://example.invalid/objects\n')
    (root / '.git/config').unlink()

    with pytest.raises(PermissionError):
        WorkspaceTransaction(root, tmp_path / 'state', writable=writable, git_sandbox=object())


def test_foreign_readonly_transaction_uses_projection_without_publication_view(tmp_path, monkeypatch):
    from agentporter.sandbox import workspace_projections
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'ordinary').write_text('fixture\n')
    actual_getuid = os.getuid
    actual_uid = actual_getuid()
    monkeypatch.setattr(os, 'getuid', lambda: actual_uid + 1)
    opened = []

    def projection(source_fd):
        descriptor = os.dup(source_fd)
        opened.append(descriptor)
        return descriptor

    def publication(*args, **kwargs):
        raise AssertionError('Read-only transaction requested a publication view')

    monkeypatch.setattr(workspace_projections, 'open_workspace_projection', projection)
    monkeypatch.setattr(workspace_projections, 'open_workspace_publication', publication)
    transaction = WorkspaceTransaction(root, tmp_path / 'state', writable=False)
    try:
        assert transaction._projection_fd in transaction.launch_fds
        assert transaction.inspection_fd == transaction._projection_fd
        assert transaction._publication_fd is None
        command = transaction.wrap_command(['bwrap', '--ro-bind', str(root), '/workspace'])
        assert command[command.index('/workspace') - 1] == f'/proc/self/fd/{transaction._projection_fd}'
    finally:
        monkeypatch.setattr(os, 'getuid', actual_getuid)
        transaction.close()
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_root_agent_dispatch_append_during_raw_capture_is_ignored_but_git_state_is_not(tmp_path):
    root = tmp_path / 'repo'
    _init(root)
    log = root / '.git/agent-dispatch/runs/synthetic/stdout.log'
    log.parent.mkdir(parents=True)
    log.write_text('first output\n')
    nested = root / '.git/refs/heads/agent-dispatch/branch'
    nested.parent.mkdir(parents=True)
    nested.write_text('synthetic nested metadata\n')
    nested_worktree = root / '.git/worktrees/agent-dispatch/marker'
    nested_worktree.parent.mkdir(parents=True)
    nested_worktree.write_text('synthetic nested worktree metadata\n')
    changed = []

    def append_telemetry(_fd, size):
        if size == 0 and not changed:
            with log.open('ab') as stream:
                stream.write(b'concurrent output\n')
            changed.append(True)

    result = capture_git_baseline(root, tmp_path / 'raw-baseline', copy_guard=append_telemetry)
    files = result['manifest']['files']
    assert changed
    assert 'agent-dispatch/runs/synthetic/stdout.log' not in files
    assert 'refs/heads/agent-dispatch/branch' in files
    assert 'worktrees/agent-dispatch/marker' in files


@pytest.mark.parametrize('relative', [
    'HEAD', 'refs/heads/master', 'index', 'config', 'hooks/pre-commit',
])
def test_raw_baseline_still_rejects_git_control_tampering(tmp_path, relative):
    root = tmp_path / 'repo'
    _init(root)
    subprocess.run(['/usr/bin/git', '-C', str(root), 'branch', '-M', 'master'], check=True)
    control = root / '.git' / relative
    control.parent.mkdir(parents=True, exist_ok=True)
    if not control.exists():
        control.write_text('synthetic original\n')
    baseline = capture_git_baseline(root, tmp_path / 'raw-baseline')
    control.write_bytes(control.read_bytes() + b'tampered\n')

    from agentporter.sandbox.workspace_git_recovery import verify_git_baseline
    with pytest.raises(PermissionError):
        verify_git_baseline(root, tmp_path / 'raw-baseline', baseline['sha256'])


def test_private_snapshot_omits_only_root_agent_dispatch(tmp_path):
    root = tmp_path / 'git'
    root.mkdir()
    telemetry = root / 'agent-dispatch/runs/current/stdout.log'
    telemetry.parent.mkdir(parents=True)
    telemetry.write_text('host telemetry\n')
    nested = root / 'refs/heads/agent-dispatch/branch'
    nested.parent.mkdir(parents=True)
    nested.write_text('synthetic Git metadata\n')
    worktree_nested = root / 'worktrees/agent-dispatch/marker'
    worktree_nested.parent.mkdir(parents=True)
    worktree_nested.write_text('synthetic worktree metadata\n')
    destination = tmp_path / 'destination'
    destination.mkdir()

    source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        budget = SnapshotBudget()
        records = budget.preflight(source_fd, destination)
        copied = destination / 'private'
        budget.copy(source_fd, copied, records)
    finally:
        os.close(source_fd)

    assert not (copied / 'agent-dispatch').exists()
    assert (copied / 'refs/heads/agent-dispatch/branch').read_text() == 'synthetic Git metadata\n'
    assert (copied / 'worktrees/agent-dispatch/marker').read_text() == 'synthetic worktree metadata\n'


def test_root_agent_dispatch_cannot_be_replaced_by_an_alias(tmp_path):
    root = tmp_path / 'git'
    root.mkdir()
    (root / 'agent-dispatch').symlink_to(tmp_path, target_is_directory=True)
    destination = tmp_path / 'destination'
    destination.mkdir()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(PermissionError, match='real directory'):
            SnapshotBudget().preflight(descriptor, destination)
    finally:
        os.close(descriptor)

    repository = tmp_path / 'repository'
    _init(repository)
    (repository / '.git/agent-dispatch').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(PermissionError, match='real directory'):
        capture_git_baseline(repository, tmp_path / 'raw-alias-baseline')


def test_snapshot_preflight_still_rejects_git_control_and_external_object_paths(tmp_path):
    for relative in ('commondir', 'objects/info/alternates', 'objects/info/http-alternates', 'HEAD.lock'):
        root = tmp_path / relative.replace('/', '-')
        root.mkdir()
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic\n')
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        destination = tmp_path / (root.name + '-destination')
        destination.mkdir()
        try:
            with pytest.raises(PermissionError):
                SnapshotBudget().preflight(descriptor, destination)
        finally:
            os.close(descriptor)
