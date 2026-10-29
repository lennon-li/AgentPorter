import os
from types import SimpleNamespace
import pytest
from agentporter.sandbox import workspace_projections as projections


def test_foreign_transaction_pins_root_with_path_only_descriptor(tmp_path, monkeypatch):
    from agentporter.sandbox import workspace_transactions as transactions
    import fcntl

    root = tmp_path / 'project'
    root.mkdir(mode=0o700)
    original_uid = os.getuid()
    monkeypatch.setattr(transactions.os, 'getuid', lambda: original_uid + 1)
    def view(fd):
        assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(projections, 'open_workspace_projection', view)
    monkeypatch.setattr(projections, 'open_workspace_publication', view)
    transaction = transactions.WorkspaceTransaction(root, tmp_path / 'state')
    monkeypatch.setattr(transactions.os, 'getuid', lambda: original_uid)
    transaction.close()


@pytest.mark.parametrize('uid,mode', [(1, 0o755), (0, 0o775), (0, 0o757)])
def test_untrusted_parent_rejected(uid, mode):
    with pytest.raises(PermissionError, match='Untrusted'):
        projections._require_trusted_parent(SimpleNamespace(st_uid=uid, st_mode=mode))


def fixture_view(tmp_path, monkeypatch):
    root = tmp_path / 'views'
    root.mkdir()
    canonical = tmp_path / 'source'
    canonical.mkdir()
    (canonical / 'ordinary').write_text('source')
    fd = os.open(canonical, os.O_RDONLY | os.O_DIRECTORY)
    info = os.fstat(fd)
    view = root / f'{info.st_dev:x}-{info.st_ino:x}'
    canonical.rename(view)
    monkeypatch.setattr(projections, 'PROJECTION_ROOT', root)
    # These tests isolate leaf validation from the separately tested root trust gate.
    monkeypatch.setattr(projections, '_require_trusted_parent', lambda info: None)
    return fd, view


def test_writable_view_rejected(tmp_path, monkeypatch):
    fd, _ = fixture_view(tmp_path, monkeypatch)
    monkeypatch.setattr(projections.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=0))
    try:
        with pytest.raises(PermissionError, match='read-only'):
            projections.open_workspace_projection(fd)
    finally:
        os.close(fd)


def test_wrong_directory_rejected(tmp_path, monkeypatch):
    fd, view = fixture_view(tmp_path, monkeypatch)
    view.rename(view.with_name('original'))
    view.mkdir()
    try:
        with pytest.raises(PermissionError, match='canonical'):
            projections.open_workspace_projection(fd)
    finally:
        os.close(fd)


def test_symlink_view_rejected(tmp_path, monkeypatch):
    fd, view = fixture_view(tmp_path, monkeypatch)
    original = view.with_name('original')
    view.rename(original)
    view.symlink_to(original)
    try:
        with pytest.raises(OSError):
            projections.open_workspace_projection(fd)
    finally:
        os.close(fd)


def test_verified_descriptor_keeps_original_directory_after_path_replacement(tmp_path, monkeypatch):
    fd, view = fixture_view(tmp_path, monkeypatch)
    monkeypatch.setattr(projections.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY))
    mapped = None
    try:
        mapped = projections.open_workspace_projection(fd)
        view.rename(view.with_name('original'))
        view.mkdir()
        (view / 'ordinary').write_text('replacement')
        assert open(f'/proc/self/fd/{mapped}/ordinary').read() == 'source'
    finally:
        if mapped is not None:
            os.close(mapped)
        os.close(fd)


def test_missing_projection_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(projections, 'PROJECTION_ROOT', tmp_path / 'missing')
    monkeypatch.setattr(projections, '_require_trusted_parent', lambda info: None)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(PermissionError, match='owner-provisioned'):
            projections.open_workspace_projection(fd)
    finally:
        os.close(fd)


def test_wrong_worker_identity_rejected(tmp_path, monkeypatch):
    fd, _ = fixture_view(tmp_path, monkeypatch)
    monkeypatch.setattr(projections.os, 'getgid', lambda: os.fstat(fd).st_gid + 1)
    try:
        with pytest.raises(PermissionError, match='worker identity'):
            projections.open_workspace_projection(fd)
    finally:
        os.close(fd)


def test_transaction_uses_projection_lower_and_releases_it(tmp_path):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('canonical')
    transaction = WorkspaceTransaction(root, tmp_path / 'state')
    # Distinct descriptors verify overlay selection, even when testing without
    # the root-only host mount needed to change the directory's presented UID.
    projection_fd = os.dup(transaction._root_fd)
    transaction._projection_fd = projection_fd
    workspace_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        args = transaction.wrap_command(['bwrap', '--bind', f'/proc/self/fd/{workspace_fd}', '/workspace'], workspace_fd=workspace_fd)
        assert args[args.index('--overlay-src') + 1] == f'/proc/self/fd/{projection_fd}'
        assert projection_fd in transaction.launch_fds
        assert (root / 'ordinary').read_text() == 'canonical'
    finally:
        os.close(workspace_fd)
        transaction.close()
    with pytest.raises(OSError):
        os.fstat(projection_fd)


def test_publication_view_rejects_read_only_mount(tmp_path, monkeypatch):
    fd, view = fixture_view(tmp_path, monkeypatch)
    monkeypatch.setattr(projections, 'PUBLICATION_ROOT', view.parent)
    monkeypatch.setattr(projections.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY))
    try:
        with pytest.raises(PermissionError, match='must be writable'):
            projections.open_workspace_publication(fd)
    finally:
        os.close(fd)


def test_publication_descriptor_is_not_inherited_by_job_and_is_closed(tmp_path):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root = tmp_path / 'source'
    root.mkdir()
    transaction = WorkspaceTransaction(root, tmp_path / 'state')
    publication = os.dup(transaction._root_fd)
    transaction._publication_fd = publication
    assert publication not in transaction.launch_fds
    transaction.close()
    with pytest.raises(OSError):
        os.fstat(publication)


def test_missing_publication_view_closes_already_pinned_lower(tmp_path, monkeypatch):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root = tmp_path / 'source'
    root.mkdir()
    uid = os.getuid()
    monkeypatch.setattr(projections.os, 'getuid', lambda: uid + 1)
    opened = []
    def lower(fd):
        duplicate = os.dup(fd)
        opened.append(duplicate)
        return duplicate
    def fail(fd):
        raise PermissionError('publication view unavailable')
    monkeypatch.setattr(projections, 'open_workspace_projection', lower)
    monkeypatch.setattr(projections, 'open_workspace_publication', fail)
    with pytest.raises(PermissionError, match='publication view unavailable'):
        WorkspaceTransaction(root, tmp_path / 'state')
    assert opened
    with pytest.raises(OSError):
        os.fstat(opened[0])
