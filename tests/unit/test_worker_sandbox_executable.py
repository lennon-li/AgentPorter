"""Worker sandbox selection never accepts workspace-controlled programs."""
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from agentporter.agents.development import DevelopmentRuntime


@pytest.mark.parametrize('name', ['/tmp/bwrap', 'bwrap', '/usr/bin/../bin/bwrap', [], None])
def test_unapproved_sandbox_path_is_rejected(name):
    with pytest.raises(PermissionError, match='Unapproved'):
        DevelopmentRuntime._sandbox_executable({'sandbox_executable': name})


@pytest.mark.parametrize('unsafe', ['symlink', 'writable', 'setuid', 'foreign_owner', 'writable_parent'])
def test_selected_sandbox_requires_root_control(monkeypatch, unsafe):
    original = Path.lstat
    target = Path('/usr/bin/bwrap')

    def metadata(path):
        info = original(path)
        if path == target:
            mode = info.st_mode
            uid = info.st_uid
            if unsafe == 'symlink': mode = stat.S_IFLNK | 0o777
            elif unsafe == 'writable': mode |= 0o020
            elif unsafe == 'setuid': mode |= stat.S_ISUID
            elif unsafe == 'foreign_owner': uid = 12345
            return SimpleNamespace(st_mode=mode, st_uid=uid)
        if path == target.parent and unsafe == 'writable_parent':
            return SimpleNamespace(st_mode=info.st_mode | 0o020, st_uid=0)
        return info

    monkeypatch.setattr(Path, 'lstat', metadata)
    with pytest.raises(PermissionError, match='root ownership'):
        DevelopmentRuntime._sandbox_executable({})


@pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').exists(), reason='BCC owner-installed sandbox absent')
def test_bcc_installed_sandbox_can_be_selected():
    assert DevelopmentRuntime._sandbox_executable({
        'sandbox_executable': '/opt/agentporter-bcc/bin/bwrap'}) == '/opt/agentporter-bcc/bin/bwrap'
