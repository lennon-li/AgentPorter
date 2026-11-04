"""Nested service-looking cgroups must fail before controller/process writes."""
from pathlib import Path

import pytest

from agentporter import resource_supervisor as supervisor, resources


@pytest.mark.parametrize('outer', sorted(supervisor.SERVICE_UNITS))
@pytest.mark.parametrize('inner', sorted(supervisor.SERVICE_UNITS))
def test_nested_service_refused_at_both_mutation_boundaries(tmp_path, monkeypatch, outer, inner):
    relative = Path('/system.slice') / outer / ('apj_' + '0' * 32) / inner / 'supervisor'
    member = tmp_path / 'membership'
    member.write_text('0::' + str(relative))
    monkeypatch.setattr(supervisor.os, 'write', lambda *args: pytest.fail('Process moved'))
    with pytest.raises(PermissionError, match='service ancestry'):
        supervisor.enter_supervisor(cgroup_mount=tmp_path / 'missing', membership_file=member)

    original = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/proc/self/cgroup':
            return member.read_text()
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(Path, 'write_text', lambda *args, **kwargs: pytest.fail('Controller changed'))
    with pytest.raises(PermissionError, match='service ancestry'):
        resources.JobResources({'memory_bytes': 2 * 1024**3, 'pids': 128,
                               'cpu_quota_us': 200000, 'cpu_period_us': 100000})


@pytest.mark.parametrize('unit', sorted(supervisor.SERVICE_UNITS))
def test_exact_service_ancestry_accepted(unit):
    supervisor.require_service_ancestry(Path('/system.slice') / unit / 'supervisor', unit)


