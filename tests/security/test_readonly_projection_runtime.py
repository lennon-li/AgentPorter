"""Read-only foreign roots use the verified lower for both mount and masks."""
import fcntl
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest
from test_development_runtime import runtime_factory, no_probe
from agentporter.sandbox import workspace_projections as projections


def foreign_root(monkeypatch, workspace):
    original = os.fstat
    identity = workspace.stat()
    def fstat(fd):
        value = original(fd)
        if ((value.st_dev, value.st_ino) == (identity.st_dev, identity.st_ino)
                and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH):
            fields = list(value)
            fields[4] = os.getuid() + 10000
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(os, 'fstat', fstat)
    return original


def test_real_foreign_readonly_projection_masks_and_closes_fds(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    (workspace / '.env').write_text('synthetic secret')
    (workspace / '.git').mkdir()
    (workspace / '.git' / 'config').write_text('synthetic metadata')
    original = foreign_root(monkeypatch, workspace)
    opened = []
    def lower(source):
        assert fcntl.fcntl(source, fcntl.F_GETFL) & os.O_PATH
        fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        opened.append(fd)
        return fd
    monkeypatch.setattr(projections, 'open_workspace_projection', lower)
    monkeypatch.setattr(projections, 'open_workspace_publication', lambda *a, **k: pytest.fail('No writable publication view permitted'))
    scan = runtime._masks
    def masks(path, writable):
        assert path == Path(f'/proc/self/fd/{opened[0]}')
        assert writable is False
        return scan(path, writable)
    monkeypatch.setattr(runtime, '_masks', masks)
    script = """import os
from pathlib import Path
assert Path('/workspace/source.txt').read_text() == 'source'
assert Path('/workspace/.env').read_text() == ''
assert Path('/workspace/.git/config').read_text() == 'synthetic metadata'
for name in ('source.txt', '.git/config', 'new-file'):
    try:
        Path('/workspace', name).write_text('forbidden')
    except OSError:
        pass
    else:
        raise AssertionError('workspace became writable')
for name in os.listdir('/proc/self/fd'):
    if int(name) > 2:
        try:
            os.fstat(int(name))
        except OSError:
            continue
        raise AssertionError('host descriptor inherited')
print('VERIFIED_READONLY_PROJECTED_MASKS')
"""
    launch = runtime.prepare('codex_review', str(workspace), False, ['/usr/bin/python3', '-c', script])
    fds = launch.pass_fds
    try:
        i = launch.command.index('/workspace')
        assert launch.command[i-2:i] == ['--ro-bind', f'/proc/self/fd/{opened[0]}']
        for fd in fds:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            assert flags & os.O_PATH or (flags & os.O_ACCMODE) == os.O_RDONLY
        result = subprocess.run(launch.command, env={}, pass_fds=fds, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'VERIFIED_READONLY_PROJECTED_MASKS'
        assert (workspace / 'source.txt').read_text() == 'source'
        assert not (workspace / 'new-file').exists()
    finally:
        launch.cleanup()
    for fd in fds:
        with pytest.raises(OSError):
            original(fd)


@pytest.mark.parametrize('failure', ['missing', 'wrong_inode', 'wrong_uid', 'writable', 'symlink'])
def test_foreign_readonly_projection_validation_failure_is_fatal(runtime_factory, monkeypatch, tmp_path, failure):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    foreign_root(monkeypatch, workspace)
    views = tmp_path / 'views'
    views.mkdir()
    info = workspace.stat()
    view = views / f'{info.st_dev:x}-{info.st_ino:x}'
    if failure == 'wrong_inode':
        view.mkdir()
    elif failure == 'symlink':
        view.symlink_to(workspace, target_is_directory=True)
    elif failure != 'missing':
        # Simulate a provisioned same-inode mount without root mount operations.
        workspace.rename(view)
        workspace.mkdir()
        # Keep logical canonical O_PATH pinned to the original inode.
        original_pin = runtime._pin
        def pin(path, descriptors, root_fd=None):
            return original_pin(view if root_fd is None and path == workspace else path, descriptors, root_fd)
        monkeypatch.setattr(runtime, '_pin', pin)
    monkeypatch.setattr(projections, 'PROJECTION_ROOT', views)
    monkeypatch.setattr(projections, '_require_trusted_parent', lambda info: None)
    monkeypatch.setattr(projections.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=0 if failure == 'writable' else os.ST_RDONLY))
    if failure == 'wrong_uid':
        monkeypatch.setattr(projections.os, 'getgid', lambda: os.stat(view).st_gid + 1)
    with pytest.raises((PermissionError, OSError)):
        runtime.prepare('codex_review', str(workspace), False, ['/usr/bin/python3', '--version'])
    assert not list(runtime.state_dir.glob('development-*'))


def test_same_owner_readonly_never_requests_projection(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    monkeypatch.setattr(projections, 'open_workspace_projection', lambda fd: pytest.fail('same-owner root needs no projection'))
    launch = runtime.prepare('codex_review', str(workspace), False, ['/usr/bin/python3', '--version'])
    launch.cleanup()
