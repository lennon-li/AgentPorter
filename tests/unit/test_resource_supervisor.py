"""Older systemd bootstrap must prove exclusive delegated membership."""
import os
from pathlib import Path

import pytest

from agentporter import resource_supervisor as supervisor


@pytest.fixture
def cgroup(tmp_path):
    relative = Path('/system.slice/agentporter-bcc-worker.service')
    mount = tmp_path / 'cgroup'
    root = mount / str(relative).lstrip('/')
    root.mkdir(parents=True)
    (root / 'cgroup.controllers').write_text('cpu memory pids\n')
    (root / 'cgroup.procs').write_text(str(os.getpid()))
    (root / 'supervisor').mkdir(mode=0o700)
    (root / 'supervisor/cgroup.procs').write_text('')
    membership = tmp_path / 'membership'
    membership.write_text('0::' + str(relative))
    return mount, root, membership, relative


def test_moves_only_own_process_and_verifies_kernel_result(cgroup, monkeypatch):
    mount, root, membership, relative = cgroup
    write = os.write
    writes = []

    def kernel_write(fd, data):
        writes.append(data)
        result = write(fd, data)
        (root / 'cgroup.procs').write_text('')
        membership.write_text('0::' + str(relative / 'supervisor'))
        return result

    monkeypatch.setattr(supervisor.os, 'write', kernel_write)
    assert supervisor.enter_supervisor(cgroup_mount=mount, membership_file=membership) == root
    assert writes == [str(os.getpid()).encode()]


def test_already_entered_subgroup_remains_exclusive(cgroup, monkeypatch):
    mount, root, membership, relative = cgroup
    membership.write_text('0::' + str(relative / 'supervisor'))
    (root / 'cgroup.procs').write_text('')
    (root / 'supervisor/cgroup.procs').write_text(str(os.getpid()))
    monkeypatch.setattr(supervisor.os, 'write', lambda *args: pytest.fail('Unexpected cgroup mutation'))
    assert supervisor.enter_supervisor(cgroup_mount=mount, membership_file=membership) == root


def test_bcc_gateway_supervisor_is_admitted_only_in_its_own_cgroup(tmp_path, monkeypatch):
    relative = Path('/user.slice/user-test.slice/agentporter-bcc-gateway.service')
    mount = tmp_path / 'cgroup'
    root = mount / str(relative).lstrip('/')
    root.mkdir(parents=True)
    (root / 'cgroup.controllers').write_text('cpu memory pids\n')
    (root / 'cgroup.procs').write_text(str(os.getpid()))
    (root / 'supervisor').mkdir(mode=0o700)
    (root / 'supervisor/cgroup.procs').write_text('')
    membership = tmp_path / 'membership'
    membership.write_text('0::' + str(relative))
    write = os.write
    def kernel_write(fd, data):
        result = write(fd, data)
        (root / 'cgroup.procs').write_text('')
        membership.write_text('0::' + str(relative / 'supervisor'))
        return result
    monkeypatch.setattr(supervisor.os, 'write', kernel_write)
    assert supervisor.enter_supervisor(cgroup_mount=mount, membership_file=membership) == root


@pytest.mark.parametrize('mutation', ['busy_parent', 'busy_supervisor', 'unknown_child',
                                     'missing_controllers', 'symlink_supervisor', 'wrong_unit',
                                     'traversal', 'root_identity'])
def test_refuses_unsafe_bootstrap_before_moving_process(cgroup, monkeypatch, mutation):
    mount, root, membership, _ = cgroup
    if mutation == 'busy_parent':
        (root / 'cgroup.procs').write_text(f'{os.getpid()}\n123\n')
    elif mutation == 'busy_supervisor':
        (root / 'supervisor/cgroup.procs').write_text('123\n')
    elif mutation == 'unknown_child':
        (root / 'unrelated').mkdir()
    elif mutation == 'missing_controllers':
        (root / 'cgroup.controllers').write_text('memory\n')
    elif mutation == 'symlink_supervisor':
        (root / 'supervisor/cgroup.procs').unlink()
        (root / 'supervisor').rmdir()
        (root / 'supervisor').symlink_to(root, target_is_directory=True)
    elif mutation == 'wrong_unit':
        membership.write_text('0::/system.slice/agentporter.service')
    elif mutation == 'traversal':
        membership.write_text('0::/system.slice/../agentporter-bcc-worker.service')
    else:
        monkeypatch.setattr(supervisor.os, 'getuid', lambda: 0)
    monkeypatch.setattr(supervisor.os, 'write', lambda *args: pytest.fail('Unsafe membership write'))
    with pytest.raises(PermissionError):
        supervisor.enter_supervisor(cgroup_mount=mount, membership_file=membership)


def test_membership_write_without_kernel_transition_is_rejected(cgroup):
    mount, _, membership, _ = cgroup
    with pytest.raises(PermissionError, match='remains unverified'):
        supervisor.enter_supervisor(cgroup_mount=mount, membership_file=membership)
