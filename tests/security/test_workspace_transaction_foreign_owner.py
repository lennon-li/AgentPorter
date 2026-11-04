"""Unprivileged regression checks for foreign-owned workspace transactions."""
import fcntl
import os

import pytest

from agentporter.sandbox import workspace_projections, workspace_transactions


pytestmark = pytest.mark.skipif(not hasattr(os, 'O_PATH'), reason='O_PATH is Linux-specific')


def test_foreign_owner_without_projection_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('original')
    monkeypatch.setattr(os, 'getuid', lambda: root.stat().st_uid + 1)
    # The test-owned parent is not a provisioned system projection directory.
    monkeypatch.setattr(workspace_projections, 'PROJECTION_ROOT', tmp_path / 'missing')
    monkeypatch.setattr(workspace_projections, '_require_trusted_parent', lambda info: None)

    with pytest.raises(PermissionError, match='owner-provisioned idmapped projection'):
        workspace_transactions.WorkspaceTransaction(root, tmp_path / 'state')
    assert (root / 'ordinary').read_text() == 'original'
    assert not list((tmp_path / 'state').glob('*/upper'))


def test_foreign_owner_pins_identity_with_o_path_and_uses_projection(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'ordinary').write_text('original')
    real_getuid = os.getuid
    monkeypatch.setattr(os, 'getuid', lambda: root.stat().st_uid + 1)
    opened = []

    def view(source_fd, **kwargs):
        assert fcntl.fcntl(source_fd, fcntl.F_GETFL) & os.O_PATH
        assert (os.fstat(source_fd).st_dev, os.fstat(source_fd).st_ino) == (root.stat().st_dev, root.stat().st_ino)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        opened.append(fd)
        return fd

    monkeypatch.setattr(workspace_projections, 'open_workspace_projection', view)
    monkeypatch.setattr(workspace_projections, 'open_workspace_publication', view)
    transaction = workspace_transactions.WorkspaceTransaction(root, tmp_path / 'state')
    try:
        assert transaction.inspection_fd == opened[0]
        assert transaction.launch_fds == (transaction._root_fd, opened[0])
        command = transaction.wrap_command(['bwrap', '--bind', str(root), '/workspace'])
        assert command[1:3] == ['--overlay-src', f'/proc/self/fd/{opened[0]}']
        root.rename(tmp_path / 'original-project')
        root.mkdir()
        with pytest.raises(PermissionError, match='root identity changed'):
            transaction.wrap_command(['bwrap', '--bind', str(root), '/workspace'])
    finally:
        monkeypatch.setattr(os, 'getuid', real_getuid)
        transaction.close()
