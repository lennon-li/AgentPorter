"""Owner-selected BCC gateway budgets must fail closed and stay service-scoped."""
import os
from pathlib import Path

import pytest
import yaml

from agentporter.resources import JobResources, load_gateway_job_resources

BUDGET = {'memory_bytes': 2 * 1024**3, 'pids': 128, 'cpu_quota_us': 200000, 'cpu_period_us': 100000}


def test_gateway_resource_profile_is_optional_private_and_strict(tmp_path):
    config = tmp_path / 'config'
    config.mkdir(mode=0o700)
    assert load_gateway_job_resources(config) is None
    policy = config / 'gateway-job-resources.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'job_resources': BUDGET}))
    policy.chmod(0o600)
    assert load_gateway_job_resources(config) == BUDGET
    alias = tmp_path / 'alias'
    os.link(policy, alias)
    with pytest.raises(PermissionError):
        load_gateway_job_resources(config)
    alias.unlink()
    policy.chmod(0o644)
    with pytest.raises(PermissionError):
        load_gateway_job_resources(config)
    policy.chmod(0o600)
    policy.write_text('version: 1\nversion: 1\njob_resources: {}\n')
    with pytest.raises(ValueError):
        load_gateway_job_resources(config)
    policy.unlink()
    policy.symlink_to('/etc/passwd')
    with pytest.raises(OSError):
        load_gateway_job_resources(config)


def test_gateway_profile_refuses_other_delegated_service(monkeypatch):
    original = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/proc/self/cgroup':
            return '0::/system.slice/agentporter-bcc-worker.service/supervisor\n'
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    with pytest.raises(PermissionError, match='wrong service cgroup'):
        JobResources(BUDGET, expected_service='agentporter-bcc-gateway.service')


def test_gateway_resource_profile_refuses_changes_during_read(tmp_path, monkeypatch):
    from agentporter import resources
    config = tmp_path / 'config'; config.mkdir(mode=0o700)
    policy = config / 'gateway-job-resources.yaml'
    policy.write_text(yaml.safe_dump({'version': 1, 'job_resources': BUDGET}))
    policy.chmod(0o600)
    inode = policy.stat().st_ino
    original = os.read
    changed = False
    def read(fd, count):
        nonlocal changed
        data = original(fd, count)
        if not changed and os.fstat(fd).st_ino == inode:
            changed = True
            policy.write_text('version: 1\njob_resources: {}\n')
        return data
    monkeypatch.setattr(resources.os, 'read', read)
    with pytest.raises(PermissionError, match='changed while reading'):
        load_gateway_job_resources(config)


def test_gateway_profile_activates_transaction_supervisor(temp_config, monkeypatch):
    from agentporter import server, resources
    seen = []
    class FakeResources:
        def __init__(self, settings, *, expected_service):
            seen.append((settings, expected_service))
        def recover(self): pass
    monkeypatch.setattr(resources, 'load_gateway_job_resources', lambda _: dict(BUDGET))
    monkeypatch.setattr(server, 'JobResources', FakeResources)
    temp_config.sandbox.workspace_transactions = True
    with pytest.raises(PermissionError, match='requires an explicit public-client policy'):
        server.build_mcp_server(temp_config)
    policy = temp_config.config_dir / 'public-client-policy.yaml'
    policy.write_text('version: 1\nworkspaces: {}\n')
    policy.chmod(0o600)
    _, context = server.build_mcp_server(temp_config)
    assert seen == [(BUDGET, 'agentporter-bcc-gateway.service')]
    assert context['sandbox'].resources is context['job_manager'].resources
    assert context['sandbox'].transactional_writes is True
