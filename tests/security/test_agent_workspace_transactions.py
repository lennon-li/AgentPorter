"""Native delegated launches must share private-workspace finalization."""
import subprocess
from pathlib import Path
import pytest
from agentporter.agents.policy import ExecutionPolicy
from agentporter.tools.jobs import JobManager
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from tests.security.test_development_runtime import runtime_factory, no_probe
from tests.security.test_workspace_transactions import RecordingResources
from tests.security.test_async_workspace_transactions import wait

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='BCC overlay integration requires its installed sandbox')


def test_pinned_development_launch_keeps_edits_private(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    transaction = WorkspaceTransaction(workspace, runtime.state_dir / 'workspace-transactions')
    launch = None
    try:
        launch = runtime.prepare('liz', str(workspace), True,
            ['/usr/bin/python3', '-c', "from pathlib import Path; Path('/workspace/source.txt').write_text('changed')"], workspace_transaction=transaction)
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds,
            capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert (workspace / 'source.txt').read_text() == 'source'
        launch.cleanup()
        launch = None
        transaction.publish()
        assert (workspace / 'source.txt').read_text() == 'changed'
    finally:
        if launch is not None:
            launch.cleanup()
        transaction.close()


def test_confined_agent_job_uses_transaction_finalization(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    manager = JobManager(runtime.state_dir, transactional_writes=True)
    manager.development_runtime = runtime
    manager.resources = RecordingResources()
    job_id = manager.start_confined_agent_job(agent='liz', workspace_id='selected',
        workspace_path=str(workspace), cmd=['/usr/bin/python3', '-c', "from pathlib import Path; Path('/workspace/source.txt').write_text('changed')"],
        policy=ExecutionPolicy.for_workspace(writable=True))
    result = wait(manager, job_id)
    assert result['status'] == 'completed', result
    assert manager.resources.lease.closed
    assert (workspace / 'source.txt').read_text() == 'changed'


@pytest.mark.parametrize('script', [
    "from pathlib import Path; Path('/workspace/source.txt').write_text('changed'); raise SystemExit(7)",
    "from pathlib import Path; Path('/workspace/new/.git').mkdir(parents=True); Path('/workspace/new/.git/HEAD').write_text('unauthorized'); Path('/workspace/source.txt').write_text('changed')",
])
def test_agent_failure_or_protected_delta_keeps_project_unchanged(runtime_factory, monkeypatch, script):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    manager = JobManager(runtime.state_dir, transactional_writes=True)
    manager.development_runtime = runtime
    manager.resources = RecordingResources()
    job_id = manager.start_confined_agent_job(agent='liz', workspace_id='selected',
        workspace_path=str(workspace), cmd=['/usr/bin/python3', '-c', script],
        policy=ExecutionPolicy.for_workspace(writable=True))
    assert wait(manager, job_id)['status'] == 'failed'
    assert (workspace / 'source.txt').read_text() == 'source'
    assert not (workspace / 'new').exists()


@pytest.mark.parametrize('fail', [False, True])
def test_relay_dispatch_runs_confined_transaction(runtime_factory, temp_config, monkeypatch, tmp_path, fail):
    """Exercise relay admission through a real synthetic sandboxed write job."""
    import asyncio
    from types import SimpleNamespace
    import httpx
    import yaml
    from agentporter import server
    from agentporter.agents import production_relay
    from agentporter.workspaces.registry import WorkspaceRegistry

    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    # This native fixture has no provider/network credentials. The admission
    # check itself is covered separately; the job is an offline Python worker.
    monkeypatch.setattr(runtime, 'require_production_egress', lambda agent=None: frozenset({'liz'}))
    manager = JobManager(runtime.state_dir, transactional_writes=True)
    manager.development_runtime = runtime
    manager.resources = RecordingResources()
    registry = WorkspaceRegistry({'selected': {'path': str(workspace), 'writable': True,
                                                'allow_agent_dispatch': True}})
    key = temp_config.config_dir / 'delegation-relay.key'
    key.write_text('r' * 43)
    key.chmod(0o600)
    for filename in ('delegation-relay-scope.yaml', 'delegation-relay-write-scope.yaml'):
        path = temp_config.config_dir / filename
        path.write_text(yaml.safe_dump({'version': 1, 'workspaces': {'selected': str(workspace)}}))
        path.chmod(0o600)
    temp_config.sandbox.workspace_transactions = True
    script = "from pathlib import Path; Path('/workspace/source.txt').write_text('changed')"
    if fail:
        script += '; raise SystemExit(7)'
    def dispatch(**arguments):
        assert arguments['read_only'] is False
        jid = manager.start_confined_agent_job(agent='liz', workspace_id='selected',
            workspace_path=str(workspace), cmd=['/usr/bin/python3', '-c', script],
            policy=ExecutionPolicy.for_workspace(writable=True))
        return {'job_id': jid, 'status': 'running'}
    context = {'client_policy': SimpleNamespace(scopes=None, internal_key=None), 'registry': registry,
               'agent_broker': SimpleNamespace(development_runtime=runtime), 'delegation_relay_client': None,
               'job_manager': manager, 'tools': {'dispatch_agent': dispatch}}
    monkeypatch.setattr(server, 'build_mcp_server', lambda _: (server.MCPServer('native-relay'), context))
    app = server.create_asgi_app(temp_config)

    async def issue(message, headers):
        transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1:8876') as client:
            return await client.post('/internal/delegation/v1', headers=headers, content=message)

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ('127.0.0.1', 8876, 8)
        def request(self, method, path, body, headers):
            assert (method, path) == ('POST', '/internal/delegation/v1')
            self.body, self.headers = body, headers
        def getresponse(self):
            response = asyncio.run(issue(self.body, self.headers))
            return SimpleNamespace(status=response.status_code, read=lambda limit: response.content[:limit])
        def close(self): pass
    monkeypatch.setattr(production_relay.http.client, 'HTTPConnection', Connection)
    gateway_state = tmp_path / 'gateway-state'
    gateway_state.mkdir()
    gateway = production_relay.ProductionDelegationClient('r' * 43, {'selected': str(workspace)},
        gateway_state, write_workspace_paths={'selected': str(workspace)})
    public = gateway.call('dispatch_agent', {'agent': 'liz', 'task': 'synthetic edit',
                                           'workspace_id': 'selected', 'read_only': False})['job_id']
    job = gateway.ledger.get_request(public.removeprefix('rjob_'))[0]
    result = wait(manager, job)
    assert result['status'] == ('failed' if fail else 'completed'), result
    assert (workspace / 'source.txt').read_text() == ('source' if fail else 'changed')
    assert manager.resources.lease.closed


@pytest.mark.parametrize('agent', ['jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie'])
def test_each_named_worker_can_commit_without_confirmation(runtime_factory, monkeypatch, agent):
    """Exercise each named worker's OS launch path with synthetic offline code."""
    from tests.security.test_git_approval_state import git
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    git(workspace, 'init', '-q', '-b', 'main')
    git(workspace, 'config', 'user.name', 'Fixture')
    git(workspace, 'config', 'user.email', 'fixture@example.invalid')
    git(workspace, 'add', 'source.txt')
    git(workspace, 'commit', '-qm', 'Initial fixture')
    old = git(workspace, 'rev-parse', 'HEAD')
    manager = JobManager(runtime.state_dir, transactional_writes=True)
    manager.development_runtime = runtime
    manager.resources = RecordingResources()
    job = manager.start_confined_agent_job(agent=agent, workspace_id='selected',
        workspace_path=str(workspace), cmd=['/usr/bin/python3', '-c',
            'import subprocess; subprocess.run(["/bin/sh", "-c", "cd /workspace && printf changed > source.txt && git add source.txt && git commit -qm Autonomous-worker-commit && git rev-parse HEAD"], check=True)'],
        policy=ExecutionPolicy.for_workspace(writable=True))
    wait(manager, job)
    result = manager.get_result(job)
    assert result['status'] == 'completed', result.get('stderr')
    assert result.get('stderr', '') == '', result.get('stderr')
    assert git(workspace, 'rev-parse', 'HEAD') != old
    assert git(workspace, 'rev-parse', 'HEAD') in result['stdout']
    assert git(workspace, 'status', '--short') == ''
    assert 'git push' in ExecutionPolicy.for_workspace(writable=True).denied_commands()


def test_mapped_lower_descriptor_reaches_bwrap_but_not_worker(runtime_factory, monkeypatch):
    import os
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    transaction = WorkspaceTransaction(workspace, runtime.state_dir / 'workspace-transactions')
    # A second pinned descriptor exercises the foreign-owner lower path without
    # provisioning a privileged idmapped mount in this synthetic native test.
    transaction._projection_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    launch = None
    try:
        launch = runtime.prepare('liz', str(workspace), True,
            ['/usr/bin/python3', '-c',
             "import os; from pathlib import Path; assert Path('/workspace/source.txt').read_text() == 'source'; assert all(int(n) <= 2 or not Path('/proc/self/fd/'+n).is_dir() for n in os.listdir('/proc/self/fd'))"],
            workspace_transaction=transaction)
        assert set(transaction.launch_fds) <= set(launch.pass_fds)
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds,
                                capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        launch.cleanup()
        launch = None
    finally:
        if launch is not None:
            launch.cleanup()
        transaction.close()
