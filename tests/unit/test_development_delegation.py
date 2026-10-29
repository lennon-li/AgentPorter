"""Development wiring: fail closed, verified inventory, and async cleanup."""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentporter.agents.broker import AgentBroker
from agentporter.agents.policy import ExecutionPolicy
from agentporter.agents.roster import PUBLIC_AGENT_IDS, public_agent_inventory
from agentporter.tools.jobs import JobManager
from agentporter.tools.agents import create_agent_tools


class StubRuntime:
    def __init__(self, command=None, *, enabled=True):
        self.command = command
        self.enabled = enabled
        self.cleanup = Mock()
        self.prepare_calls = []

    def status(self, agent, adapter=None, detection=None):
        enabled = self.enabled and agent in PUBLIC_AGENT_IDS
        return {
            'delegatable': enabled,
            'confinement_status': 'verified_development_bubblewrap' if enabled else 'blocked_runtime_verification_failed',
            'availability_reason': 'ready' if enabled else 'confinement probe failed',
            'runtime_profile': 'development-test-profile',
            'worker_executable': '/usr/bin/true',
        }

    def executable_for(self, agent):
        return '/usr/bin/true'

    def prepare(self, *args):
        self.prepare_calls.append(args)
        return SimpleNamespace(command=self.command, cleanup=self.cleanup)


def launch(manager, **kwargs):
    options = dict(workspace_id='dev', workspace_path='/tmp',
                   cmd=['/usr/bin/true'], agent='prof',
                   policy=ExecutionPolicy.for_workspace(writable=False))
    options.update(kwargs)
    return manager.start_confined_agent_job(**options)


def wait_done(manager, job):
    until = time.monotonic() + 8
    while time.monotonic() < until:
        status = manager.get_status(job)
        if status['status'] not in {'running','cancelling'} and status['finished_at']:
            return status
        time.sleep(.02)
    pytest.fail('Confined job monitor did not finish')


def test_production_launcher_stays_blocked(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    popen = Mock(side_effect=AssertionError('must not execute'))
    monkeypatch.setattr(subprocess, 'Popen', popen)
    with pytest.raises(PermissionError, match='blocked_pending_os_confinement'):
        launch(manager)
    popen.assert_not_called()


def test_failed_verification_cannot_prepare_or_spawn(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    runtime = StubRuntime(enabled=False)
    manager.development_runtime = runtime
    popen = Mock(side_effect=AssertionError('must not execute'))
    monkeypatch.setattr(subprocess, 'Popen', popen)
    with pytest.raises(PermissionError, match='probe failed'):
        launch(manager)
    assert runtime.prepare_calls == []
    popen.assert_not_called()


def test_malicious_prepared_launcher_rejected_and_cleaned(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    runtime = StubRuntime(['/usr/bin/python3', '-c', 'raise SystemExit(0)'])
    manager.development_runtime = runtime
    popen = Mock(side_effect=AssertionError('must not execute'))
    monkeypatch.setattr(subprocess, 'Popen', popen)
    with pytest.raises(PermissionError, match='trusted Bubblewrap'):
        launch(manager)
    runtime.cleanup.assert_called_once()
    popen.assert_not_called()


def test_popen_error_cleans_prepared_credentials(tmp_path, monkeypatch):
    manager = JobManager(tmp_path)
    runtime = StubRuntime(['/usr/bin/bwrap', '--version'])
    manager.development_runtime = runtime
    monkeypatch.setattr(shutil, 'which', lambda *a, **k: '/usr/bin/bwrap')
    monkeypatch.setattr(subprocess, 'Popen', Mock(side_effect=OSError('test launch failure')))
    with pytest.raises(OSError, match='test launch failure'):
        launch(manager)
    runtime.cleanup.assert_called_once()
    assert not manager.active_processes


@pytest.mark.parametrize('action,expected', [('finish', 'completed'), ('cancel', 'cancelled'), ('timeout', 'timed_out')])
@pytest.mark.parametrize('sandbox', ['/usr/bin/bwrap', '/opt/agentporter-bcc/bin/bwrap'])
def test_async_lifecycle_retains_bounds_and_cleans(tmp_path, monkeypatch, action, expected, sandbox):
    if not Path(sandbox).exists():
        pytest.skip('Optional BCC owner-installed sandbox absent')
    manager = JobManager(tmp_path)
    runtime = StubRuntime([sandbox, '--fixture-only'])
    original_status = runtime.status
    runtime.status = lambda *a, **k: {**original_status(*a, **k), 'sandbox_executable': sandbox}
    manager.development_runtime = runtime
    real_popen = subprocess.Popen
    observed = []

    def fake_confined(command, **kwargs):
        # Unit fixture substitutes a bounded child only after observing the
        # trusted launcher call. Real Bubblewrap security tests are separate.
        observed.append((command, kwargs))
        code = "print('done')" if action == 'finish' else 'import time; time.sleep(30)'
        return real_popen([sys.executable, '-c', code], **kwargs)

    monkeypatch.setattr(shutil, 'which', lambda *a, **k: '/usr/bin/bwrap')
    monkeypatch.setattr(subprocess, 'Popen', fake_confined)
    monkeypatch.setenv('PRODUCTION_SECRET_TEST', 'must-not-inherit')
    monitor = Mock(wraps=manager._monitor_proc)
    manager._monitor_proc = monitor
    job = launch(manager, timeout_seconds=1 if action == 'timeout' else 10000)
    if action == 'cancel':
        manager.cancel(job)
    status = wait_done(manager, job)
    assert status['status'] == expected
    assert status['runtime_profile'] == 'development-test-profile'
    assert monitor.call_args.args[-2] == (1 if action == 'timeout' else 900)
    command, options = observed[0]
    assert command[0] == sandbox
    assert options['stdin'] == subprocess.DEVNULL
    assert options['cwd'] == '/'
    assert options['env'] == {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    runtime.cleanup.assert_called_once()
    assert not manager.active_processes
    assert not manager._job_cleanups
    assert 'fixture-only' not in manager._get_db().execute('SELECT argv FROM jobs').fetchone()['argv']


def test_monitor_start_error_records_failed_and_cleans(tmp_path, monkeypatch):
    import agentporter.tools.jobs as jobs_module

    manager = JobManager(tmp_path)
    runtime = StubRuntime(['/usr/bin/bwrap', '--fixture-only'])
    manager.development_runtime = runtime
    real_popen = subprocess.Popen
    monkeypatch.setattr(shutil, 'which', lambda *a, **k: '/usr/bin/bwrap')
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd, **kwargs: real_popen(
        [sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs))
    monkeypatch.setattr(jobs_module.threading, 'Thread', Mock(return_value=SimpleNamespace(
        start=Mock(side_effect=RuntimeError('monitor start failed')))))
    with pytest.raises(RuntimeError, match='monitor start failed'):
        launch(manager)
    conn = manager._get_db()
    row = conn.execute('SELECT status, finished_at FROM jobs').fetchone()
    conn.close()
    assert row['status'] == 'failed' and row['finished_at']
    runtime.cleanup.assert_called_once()
    assert not manager.active_processes


def broker_for(tmp_path, monkeypatch, runtime):
    monkeypatch.setenv('AGENTPORTER_CONFIG_DIR', str(tmp_path / 'config'))
    ws = SimpleNamespace(path=str(tmp_path), writable=True, allow_agent_dispatch=True)
    jobs = Mock()
    jobs.start_confined_agent_job.return_value = 'job-test'
    broker = AgentBroker(SimpleNamespace(get=lambda _: ws), jobs)
    broker.development_runtime = runtime
    for adapter in broker.adapters.values():
        adapter.detect = Mock(side_effect=AssertionError('No unconfined --version probe'))
    return broker, jobs


def test_all_seven_inventory_uses_verified_runtime_not_host_probe(tmp_path, monkeypatch):
    runtime = StubRuntime()
    runtime.status = Mock(wraps=runtime.status)
    broker, _ = broker_for(tmp_path, monkeypatch, runtime)
    rows = public_agent_inventory(broker.list_agents())
    assert {row['agent'] for row in rows} == PUBLIC_AGENT_IDS
    assert all(row['available'] and row['delegatable'] and row['supports_read_only'] for row in rows)
    assert next(row for row in rows if row['agent'] == 'ming')['worker_cli'] == 'claude'
    assert next(row for row in rows if row['agent'] == 'argie')['worker_cli'] == 'agy'
    assert all(sum(call.args[0] == agent for call in runtime.status.call_args_list) == 1
               for agent in PUBLIC_AGENT_IDS)


def test_probe_failure_inventory_and_dispatch_fail_closed(tmp_path, monkeypatch):
    broker, jobs = broker_for(tmp_path, monkeypatch, StubRuntime(enabled=False))
    rows = public_agent_inventory(broker.list_agents())
    assert all(not row['available'] and not row['delegatable'] for row in rows)
    with pytest.raises(PermissionError, match='probe failed'):
        broker.dispatch_agent('prof', 'audit only', 'dev')
    jobs.start_confined_agent_job.assert_not_called()


def test_public_dispatch_explains_verified_runtime_blocker(tmp_path, monkeypatch):
    broker, jobs = broker_for(tmp_path, monkeypatch, StubRuntime(enabled=False))
    _, dispatch = create_agent_tools(broker)
    with pytest.raises(PermissionError) as error:
        dispatch('prof', 'independent read-only audit', 'dev')
    message = str(error.value)
    assert message.startswith('Named agent is unavailable, unregistered, or misrouted: prof; no alternate runtime will be substituted')
    assert 'blocked_runtime_verification_failed' in message
    assert 'confinement probe failed' in message
    jobs.start_confined_agent_job.assert_not_called()


@pytest.mark.parametrize('agent', ['ming', 'argie'])
def test_os_confined_readonly_supported_without_cli_claim(tmp_path, monkeypatch, agent):
    broker, jobs = broker_for(tmp_path, monkeypatch, StubRuntime())
    result = broker.dispatch_agent(agent, 'audit only', 'dev', read_only=True)
    assert result['read_only'] is True
    assert result['runtime_profile'] == 'development-test-profile'
    options = jobs.start_confined_agent_job.call_args.kwargs
    assert options['policy'].workspace_write is False
    assert options['cmd'][0] == '/usr/bin/true'


@pytest.mark.parametrize('agent', sorted(PUBLIC_AGENT_IDS))
def test_every_confined_worker_receives_local_write_policy(tmp_path, monkeypatch, agent):
    broker, jobs = broker_for(tmp_path, monkeypatch, StubRuntime())
    result = broker.dispatch_agent(agent, 'authorized source edit', 'dev', read_only=False)
    options = jobs.start_confined_agent_job.call_args.kwargs
    assert result['read_only'] is False
    assert options['policy'].workspace_write is True
    assert options['policy'].git_commit is True
    assert options['policy'].git_push is False
    assert options['agent'] == agent
    jobs.start_raw_job.assert_not_called()
