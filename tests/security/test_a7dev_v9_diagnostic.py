"""Candidate-only diagnostic tests; no sudo, live reads, or worker execution."""
import ast
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def launcher():
    path = Path(__file__).resolve().parents[2] / 'scripts/diagnose-a7dev-v9.py'
    spec = importlib.util.spec_from_file_location('diagnostic_launcher', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bootstrap(launcher):
    namespace = {'__name__': 'synthetic_diagnostic'}
    exec(compile(launcher.BOOTSTRAP, '<diagnostic-bootstrap>', 'exec'), namespace)
    return namespace


@pytest.fixture
def child(bootstrap):
    # Load definitions without running the real UID/path-sensitive driver.
    tree = ast.parse(bootstrap['DIAGNOSTIC'])
    tree.body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom,
                                                                ast.Assign, ast.FunctionDef))]
    namespace = {}
    exec(compile(tree, '<diagnostic-child-definitions>', 'exec'), namespace)
    return namespace


@pytest.mark.parametrize('returncode,malformed', [(0, False), (1, False), (1, True)])
def test_root_retains_nonzero_summary_without_raw_stderr(bootstrap, capsys, returncode, malformed):
    secret = 'SECRET_CANARY_NOT_FOR_OUTPUT'
    report = {'diagnostic': 'candidate_v9_only', 'live_config_changed': False,
              'passes': [{'context': 'initial_runuser', 'phases': [
                  {'phase': 'app_initialization', 'ok': False,
                   'failure': {'exception': 'PermissionError', 'error': {
                       'classification': 'separate development worker authentication unavailable',
                       'markers': ['credential_guard']}}}]}]}
    runner = Mock(return_value=SimpleNamespace(returncode=returncode,
                  stdout=secret if malformed else json.dumps(report), stderr=secret))
    bootstrap.update(
        os=SimpleNamespace(geteuid=lambda: 0, close=lambda _: None,
                           readlink=lambda *a, **kw: bootstrap['BASE_RELEASE']),
        sys=SimpleNamespace(flags=SimpleNamespace(isolated=True)),
        private_account=lambda: SimpleNamespace(pw_uid=994, pw_gid=981),
        interpreter_for=lambda release: release + '/venv/bin/python',
        trusted_directory=lambda _: 101,
        read_owned_file=lambda fd, name, *args: name.encode(),
        SOURCE_PINS={name: __import__('hashlib').sha256(name.encode()).hexdigest()
                     for name in ('development.py', 'broker.py')},
        candidate_runtime=lambda _: b'{"candidate":"pinned"}',
        fcntl=SimpleNamespace(flock=Mock(), LOCK_SH=fcntl.LOCK_SH, LOCK_NB=fcntl.LOCK_NB),
        subprocess=SimpleNamespace(run=runner, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL),
    )
    assert bootstrap['main']() == (0 if returncode == 0 and not malformed else 2)
    output = capsys.readouterr().out
    assert secret not in output
    parsed = json.loads(output)
    if not malformed:
        assert parsed['report'] == report
        assert parsed['diagnostic_child_exit'] == returncode
    else:
        assert parsed == {'diagnostic': 'failed', 'phase': 'service_uid_diagnostic',
                          'exception': 'JSONDecodeError'}
    command = runner.call_args.args[0]
    assert command[:6] == ['/usr/sbin/runuser', '-u', 'agentporter-dev', '--', '/usr/bin/env', '-i']
    assert 'AGENTPORTER_API_KEY=DIAGNOSTIC_PLACEHOLDER_NO_SERVER' in command
    assert command[-1] == bootstrap['DIAGNOSTIC']
    assert runner.call_args.kwargs['check'] is False
    assert runner.call_args.kwargs['stderr'] == subprocess.DEVNULL
    assert runner.call_args.kwargs['input'] == '{"candidate":"pinned"}'
    assert runner.call_args.kwargs['timeout'] == 420
    bootstrap['fcntl'].flock.assert_called_once_with(101, fcntl.LOCK_SH | fcntl.LOCK_NB)


@pytest.mark.parametrize('message,classification', [
    ('separate development worker authentication unavailable: SECRET_CANARY',
     'separate development worker authentication unavailable'),
    ('separate development worker credentials unavailable: SECRET_CANARY',
     'separate development worker credentials unavailable'),
    ('worker executable and credentials must be outside registered development workspaces SECRET_CANARY',
     'worker executable and credentials must be outside registered development workspaces'),
    ('private unexpected SECRET_CANARY', 'unclassified_failure'),
])
def test_exception_classifier_discards_raw_messages(child, message, classification):
    try:
        raise PermissionError(message)
    except PermissionError as error:
        summary = child['error_summary'](error)
    assert summary['error']['classification'] == classification
    assert summary['exception'] == 'PermissionError'
    assert 'SECRET_CANARY' not in json.dumps(summary)
    assert set(summary['frames'][0]) == {'file', 'function', 'line'}


@pytest.mark.parametrize('stage', ['app_initialization', 'seven_worker_inventory', 'success'])
def test_child_preserves_classified_phase_failure(child, tmp_path, monkeypatch, stage):
    import sys
    import tempfile
    import types
    config_module = types.ModuleType('agentporter.config')
    config_module.Config = lambda **kwargs: kwargs
    server_module = types.ModuleType('agentporter.server')
    def fail():
        raise PermissionError('separate development worker authentication unavailable: SECRET_CANARY')
    def create_app(config):
        from agentporter.middleware import SecurityMiddleware
        assert config['state_dir'].parent == config['cache_dir'].parent
        assert config['config_dir'].parent == config['state_dir'].parent
        if stage == 'app_initialization':
            fail()
        inventory = fail if stage == 'seven_worker_inventory' else lambda: [
            {'agent': name, 'available': True, 'delegatable': True,
             'confinement_status': 'verified_development_bwrap'}
            for name in ('jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie')]
        return SecurityMiddleware(
            app=SimpleNamespace(state=SimpleNamespace(tools={'list_agents': inventory})),
            api_key='diagnostic-test', allowed_hosts=['localhost'])
    server_module.create_asgi_app = create_app
    monkeypatch.setitem(sys.modules, 'agentporter.config', config_module)
    monkeypatch.setitem(sys.modules, 'agentporter.server', server_module)
    real_temporary = tempfile.TemporaryDirectory
    child['tempfile'] = SimpleNamespace(TemporaryDirectory=lambda **kwargs: real_temporary(dir=tmp_path))
    child['copy_metadata'] = lambda *args: None
    child['nnp'] = lambda: 0
    report = child['run_pass'](b'{"allowed_workspace_roots":[]}', 'synthetic')
    failure = report['phases'][-1]
    if stage == 'success':
        assert failure['phase'] == 'seven_worker_inventory' and failure['ok'] is True
        assert len(failure['agents']) == 7
        assert list(tmp_path.iterdir()) == []
        return
    assert failure['phase'] == stage and failure['ok'] is False
    assert failure['failure']['error']['classification'] == 'separate development worker authentication unavailable'
    assert 'SECRET_CANARY' not in json.dumps(report)
    assert list(tmp_path.iterdir()) == []


def test_launcher_returns_short_failure_without_calledprocesserror(launcher, monkeypatch, capsys):
    monkeypatch.setattr(launcher.os, 'geteuid', lambda: 1000)
    runner = Mock(return_value=SimpleNamespace(returncode=2))
    monkeypatch.setattr(launcher.subprocess, 'run', runner)
    assert launcher.main() == 2
    assert runner.call_args.kwargs['check'] is False
    assert runner.call_args.args[0][:5] == ['/usr/bin/sudo', '/usr/bin/python3', '-I', '-B', '-c']
    assert capsys.readouterr().out == 'Candidate diagnosis did not complete; live release was not changed.\n'


def test_fixed_child_scope_excludes_live_secrets_and_dispatch(bootstrap):
    code = bootstrap['DIAGNOSTIC']
    compile(code, '<candidate-diagnostic-child>', 'exec')
    assert "('config.yaml','workspaces.yaml','agents.yaml','action-policy.yaml','public-https.yaml')" in code
    assert 'secrets.env' not in code and 'relay-keys' not in code
    assert 'dispatch_agent' not in code and 'uvicorn' not in code
    assert "'matching_systemd_nnp'" in code and '.prctl(38,1,0,0,0)' in code
    assert "dir='/var/lib/agentporter-dev/state'" in code
    assert '8ed4c5b2616577fc67c4e6af97dc47f352badbe4294b8af11dd061ecd0ddea6e' in code
    assert '/usr/bin/systemctl' not in bootstrap['main'].__code__.co_consts
