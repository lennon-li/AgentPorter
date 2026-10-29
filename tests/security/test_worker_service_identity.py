import pytest

from agentporter.agents.development import DevelopmentRuntime
from agentporter.resources import JobResources, WORKER_RELEASE_ROOTS, worker_service_unit

SETTINGS = {'memory_bytes': 4 * 1024**3, 'pids': 128, 'cpu_quota_us': 200000, 'cpu_period_us': 100000}


def test_default_identity_is_the_development_service():
    assert worker_service_unit({}) == 'agentporter-development.service'
    assert DevelopmentRuntime._release_root({}) == DevelopmentRuntime._RELEASES


def test_worker_identity_selects_its_own_release_root():
    config = {'service_unit': 'agentporter-worker.service'}
    assert worker_service_unit(config) == 'agentporter-worker.service'
    assert str(DevelopmentRuntime._release_root(config)) == '/opt/agentporter-worker/versions'


@pytest.mark.parametrize('value', ['agentporter.service', 'other.service', '', None, 7, ['agentporter-worker.service']])
def test_unknown_service_identity_is_rejected(value):
    with pytest.raises(PermissionError):
        worker_service_unit({'service_unit': value})


def test_release_root_and_unit_are_bound_together():
    assert set(WORKER_RELEASE_ROOTS) == {'agentporter-development.service', 'agentporter-worker.service'}
    assert len(set(WORKER_RELEASE_ROOTS.values())) == 2


def test_snapshot_must_come_from_the_configured_service_release_root():
    worker = {'service_unit': 'agentporter-worker.service',
              'shared_obsidian': '/opt/agentporter-development/versions/20261028T000000.000000Z/shared/obsidian'}
    with pytest.raises(PermissionError, match='inside the installed release'):
        DevelopmentRuntime._shared_obsidian_source(worker)


def test_cgroup_identity_must_match_requested_unit_not_any_known_unit():
    with pytest.raises(PermissionError):
        JobResources(SETTINGS, expected_unit='unknown.service')
    # The test process is not in a delegated supervisor cgroup for either unit.
    for unit in WORKER_RELEASE_ROOTS:
        with pytest.raises(PermissionError):
            JobResources(SETTINGS, expected_unit=unit)
