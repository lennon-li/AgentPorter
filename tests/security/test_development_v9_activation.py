"""Synthetic-only tests of fixed v9 activation, evidence recovery and metadata."""
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def load_script(name):
    path = Path(__file__).resolve().parents[2] / 'scripts' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=["v9", "v10", "v11", "v12"])
def launcher(request):
    return load_script("install-approved-a7dev-" + request.param)


@pytest.fixture
def bootstrap(launcher):
    namespace = {'__name__': 'synthetic_v9_bootstrap'}
    exec(compile(launcher.BOOTSTRAP, '<fixed-v9-bootstrap>', 'exec'), namespace)
    return namespace


@pytest.mark.parametrize('failure', [None, 'startup', 'health', 'install_before_mutation',
                                     'install_after_switch', 'partial_runtime_only', 'rollback'])
def test_activation_and_failure_restore_exact_pair_only(bootstrap, failure):
    effects = []
    current = [bootstrap['BASE_RELEASE']]
    runtime = ['previous-runtime-digest']
    evidence = '.candidate-' + 'a' * 32
    added = [False]
    account = SimpleNamespace(pw_uid=994, pw_gid=981)
    info = SimpleNamespace(st_uid=0, st_gid=981, st_mode=stat.S_IFDIR | 0o750)

    def no_acl(*_):
        raise OSError(errno.ENODATA, 'no ACL')

    def run_helper(arguments):
        effects.append(('helper', arguments))
        if arguments[0] == '--artifact':
            if failure == 'install_before_mutation':
                raise RuntimeError('synthetic install failed before changing pair')
            added[0] = True
            runtime[0] = 'candidate-runtime-digest'
            if failure == 'partial_runtime_only':
                raise RuntimeError('synthetic partial config switch')
            current[0] = bootstrap['RELEASE']
            if failure == 'install_after_switch':
                raise RuntimeError('synthetic helper failed after changing pair')
            return {'installed': bootstrap['RELEASE'], 'rollback_evidence': bootstrap['INSTALL'] + '/' + evidence,
                    'service_restarted': False}
        assert arguments == ['--rollback', evidence, '--activate']
        if failure == 'rollback':
            raise RuntimeError('synthetic rollback failed')
        current[0] = bootstrap['BASE_RELEASE']
        runtime[0] = 'previous-runtime-digest'
        return {'rolled_back': bootstrap['BASE_RELEASE'], 'service_restarted': True}

    def service_probe(interpreter, code, timeout):
        effects.append(('probe', interpreter, code, timeout))
        assert code == bootstrap['STARTUP_PROBE'] and timeout == 300
        if failure in ('startup', 'rollback'):
            raise RuntimeError('synthetic seven-worker acceptance failure')
        return {'inventory': [{'agent': name, 'available': True, 'delegatable': True,
                               'confinement_status': 'verified_development_bwrap'}
                              for name in ('jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie')]}

    health_calls = [0]

    def healthy():
        health_calls[0] += 1
        effects.append(('health', current[0], runtime[0]))
        if failure == 'health' and health_calls[0] == 1:
            raise RuntimeError('synthetic candidate unhealthy')

    bootstrap.update(
        os=SimpleNamespace(geteuid=lambda: 0, umask=lambda mode: effects.append(('umask', mode)),
                           fstat=lambda _: info, getxattr=no_acl, close=lambda _: None,
                           listdir=lambda _: {'versions', 'current'}, readlink=lambda *a, **kw: current[0]),
        sys=SimpleNamespace(flags=SimpleNamespace(isolated=True)), private_account=lambda: account,
        fcntl=SimpleNamespace(flock=lambda fd, flags: effects.append(('lock', fd, flags)),
                              LOCK_EX=fcntl.LOCK_EX, LOCK_NB=fcntl.LOCK_NB),
        trusted_helper=lambda: effects.append(('trusted_helper',)),
        archive_digest=lambda: effects.append(('archive_digest',)),
        interpreter_for=lambda release: release + '/venv/bin/python',
        trusted_directory=lambda path: 101 if path == bootstrap['DATA'] else 102,
        existing_private_key=lambda *args: effects.append(('key_metadata',)),
        runtime_digest=lambda *args: runtime[0],
        job_snapshot=lambda phase: effects.append(('jobs', phase)),
        control=lambda operation: effects.append(('control', operation)),
        find_evidence=lambda *_: evidence if added[0] else None,
        service_probe=service_probe, run_helper=run_helper, healthy=healthy,
    )
    if failure:
        with pytest.raises((RuntimeError, PermissionError)):
            bootstrap['main']()
    else:
        bootstrap['main']()
    assert [('jobs', 'before_stop'), ('control', 'stop'), ('jobs', 'after_stop')] == [
        effect for effect in effects if effect[0] == 'jobs' or effect == ('control', 'stop')][:3]
    assert effects.index(('lock', 102, fcntl.LOCK_EX | fcntl.LOCK_NB)) < effects.index(('jobs', 'before_stop'))
    install_call = next(effect[1] for effect in effects if effect[0] == 'helper')
    assert install_call == ['--artifact', bootstrap['ARTIFACT'], '--sha256', bootstrap['ARCHIVE_SHA256']]
    assert '--activate' not in install_call
    if failure in ('startup', 'health', 'install_after_switch'):
        assert current[0] == bootstrap['BASE_RELEASE'] and runtime[0] == 'previous-runtime-digest'
        assert ('helper', ['--rollback', evidence, '--activate']) in effects
    elif failure == 'install_before_mutation':
        assert ('helper', ['--rollback', evidence, '--activate']) not in effects
        assert ('control', 'restart') in effects
    elif failure in ('partial_runtime_only', 'rollback'):
        assert [effect for effect in effects if effect[0] == 'control'][-1] == ('control', 'stop')
        assert ('control', 'restart') not in effects
    else:
        assert current[0] == bootstrap['RELEASE'] and ('control', 'restart') in effects


def test_service_preflight_uses_real_uid_context_and_full_inventory(bootstrap):
    runner = Mock(return_value=SimpleNamespace(stdout='{"inventory":[]}'))
    bootstrap['subprocess'] = SimpleNamespace(run=runner, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)
    bootstrap['service_probe']('/trusted/release/venv/bin/python', bootstrap['STARTUP_PROBE'], 300)
    command = runner.call_args.args[0]
    assert command[:6] == ['/usr/sbin/runuser', '-u', 'agentporter-dev', '--', '/usr/bin/env', '-i']
    assert command[-4:] == ['-I', '-B', '-c', bootstrap['STARTUP_PROBE']]
    assert 'create_asgi_app(Config(' in command[-1]
    assert ("app.state.tools['list_agents']()" if bootstrap["ARTIFACT"].endswith("-v9.tgz") else "app.app.state.tools['list_agents']()") in command[-1]
    assert 'dispatch_agent' not in command[-1] and 'uvicorn' not in command[-1]
    assert runner.call_args.kwargs['cwd'] == '/var/lib/agentporter-dev/home'
    assert runner.call_args.kwargs['stderr'] == subprocess.DEVNULL


def test_directory_descriptor_lock_excludes_concurrent_activation_without_lockfile(tmp_path):
    first = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    second = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert list(tmp_path.iterdir()) == []
    finally:
        os.close(second)
        os.close(first)


def test_helper_execution_rechecks_immutable_pin_and_never_imports_mutable_preparer(bootstrap):
    verified = Mock()
    runner = Mock(return_value=SimpleNamespace(stdout='{"installed":"synthetic"}'))
    bootstrap['trusted_helper'] = verified
    bootstrap['subprocess'] = SimpleNamespace(run=runner, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)
    bootstrap['run_helper'](['--artifact', bootstrap['ARTIFACT'], '--sha256', bootstrap['ARCHIVE_SHA256']])
    verified.assert_called_once()
    command = runner.call_args.args[0]
    assert command[:4] == ['/usr/bin/python3', '-I', '-B', '/usr/local/libexec/agentporter/install-development-artifact.py']
    assert not any('prepare-development-overlay' in part or '/agent-work/' in part for part in command)


@pytest.mark.parametrize('mutation', [None, 'stale', 'other_candidate', 'wrong_runtime', 'mutable_runtime', 'symlink_record', 'ambiguous'])
def test_new_evidence_requires_exact_private_previous_pair(bootstrap, tmp_path, mutation):
    install = tmp_path / 'install'
    stage = install / ('.candidate-' + 'a' * 32)
    stage.mkdir(parents=True, mode=0o700)
    previous = b'previous synthetic runtime, no credential contents'
    record = {'release': bootstrap['BASE_RELEASE'], 'candidate': bootstrap['VERSION']}
    if mutation == 'other_candidate':
        record['candidate'] = '20261020T000000.000000Z'
    (stage / 'rollback.json').write_text(json.dumps(record))
    (stage / 'previous-runtime.yaml').write_bytes(previous if mutation != 'wrong_runtime' else b'other pair')
    for path in stage.iterdir():
        path.chmod(0o600)
    if mutation == 'mutable_runtime':
        (stage / 'previous-runtime.yaml').chmod(0o666)
    elif mutation == 'symlink_record':
        (stage / 'rollback.json').rename(stage / 'saved-record')
        (stage / 'rollback.json').symlink_to('saved-record')
    elif mutation == 'ambiguous':
        other = install / ('.candidate-' + 'b' * 32)
        other.mkdir(mode=0o700)
        for name in ('rollback.json', 'previous-runtime.yaml'):
            (other / name).write_bytes((stage / name).read_bytes())
            (other / name).chmod(0o600)
    original_fstat = os.fstat

    def root_metadata(fd):
        info = original_fstat(fd)
        values = {name: getattr(info, name) for name in (
            'st_mode', 'st_uid', 'st_gid', 'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        values['st_uid'] = 0
        return SimpleNamespace(**values)

    # Only root ownership/ancestor admission is simulated. File opens enforce
    # O_NOFOLLOW, actual private modes, bounded reads, hashes and membership.
    fake_os = SimpleNamespace(**{name: getattr(os, name) for name in (
        'open', 'close', 'listdir', 'fdopen', 'O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK')}, fstat=root_metadata)
    bootstrap.update(os=fake_os, INSTALL=str(install),
                     trusted_directory=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    fd = os.open(install, os.O_RDONLY | os.O_DIRECTORY)
    try:
        before = {stage.name} if mutation == 'stale' else set()
        if mutation in ('wrong_runtime', 'mutable_runtime', 'symlink_record', 'ambiguous'):
            with pytest.raises((PermissionError, OSError)):
                bootstrap['find_evidence'](fd, before, hashlib.sha256(previous).hexdigest())
        else:
            result = bootstrap['find_evidence'](fd, before, hashlib.sha256(previous).hexdigest())
            assert result == (None if mutation in ('stale', 'other_candidate') else stage.name)
    finally:
        os.close(fd)


def test_jobs_snapshot_reads_only_requested_metadata_and_filters_jax(tmp_path, bootstrap, monkeypatch, capsys):
    database = tmp_path / 'jobs.db'
    connection = sqlite3.connect(database)
    connection.execute('CREATE TABLE jobs(job_id TEXT,agent TEXT,workspace_id TEXT,status TEXT,created_at REAL,argv TEXT)')
    for suffix, agent, created in [('a', 'jax', 1792544191), ('b', 'phil', 1792544191), ('c', 'jax', 1792544189)]:
        connection.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?)', ('job_' + suffix * 24, agent, 'agentporter-dev', 'failed', created, 'PRIVATE_ARGV_CANARY'))
    connection.commit()
    connection.close()
    before = database.read_bytes()
    monkeypatch.setattr(os, 'getuid', lambda: 994)
    monkeypatch.setattr(os, 'geteuid', lambda: 994)
    code = bootstrap['JOBS_PROBE'].replace('/var/lib/agentporter-dev/state/jobs.db', str(database))
    exec(compile(code, '<synthetic-readonly-jobs-query>', 'exec'), {})
    output = capsys.readouterr().out
    assert 'PRIVATE_ARGV_CANARY' not in output
    rows = json.loads(output)
    assert rows == [{'job_id': 'job_' + 'a' * 24, 'agent': 'jax', 'workspace_id': 'agentporter-dev',
                     'status': 'failed', 'created_at': 1792544191.0}]
    assert database.read_bytes() == before
    assert 'mode=ro' in bootstrap['JOBS_PROBE'] and 'PRAGMA query_only=ON' in bootstrap['JOBS_PROBE']


def test_launcher_sudo_receives_only_fixed_isolated_bootstrap(launcher, monkeypatch):
    monkeypatch.setattr(launcher.os, 'geteuid', lambda: 1000)
    runner = Mock()
    monkeypatch.setattr(launcher.subprocess, 'run', runner)
    launcher.main()
    assert runner.call_args.args[0] == ['/usr/bin/sudo', '/usr/bin/python3', '-I', '-B', '-c', launcher.BOOTSTRAP]


def test_overlay_source_pin_rejects_changed_source_before_payload_execution(tmp_path):
    overlay = load_script('prepare-development-overlay')
    path = tmp_path / 'synthetic.py'
    path.write_text('raise AssertionError("never execute")')
    with pytest.raises(ValueError, match='Reviewed source changed'):
        overlay.pinned_bytes(path, '0' * 64)


def test_overlay_replacement_preserves_readonly_modes(tmp_path):
    overlay = load_script('prepare-development-overlay')
    directory = tmp_path / 'release'
    directory.mkdir()
    path = directory / 'payload'
    path.write_bytes(b'old inert data')
    path.chmod(0o444)
    directory.chmod(0o555)
    try:
        overlay.replace_file(path, b'new inert data')
        assert path.read_bytes() == b'new inert data'
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert stat.S_IMODE(directory.stat().st_mode) == 0o555
    finally:
        directory.chmod(0o700)


def test_v10_startup_probe_handles_actual_security_wrapper(monkeypatch, capsys):
    import sys
    import types
    from fastapi import FastAPI
    from agentporter.middleware import SecurityMiddleware
    module = load_script('install-approved-a7dev-v10')
    namespace = {'__name__': 'probe_test'}
    exec(compile(module.BOOTSTRAP, '<v10-bootstrap>', 'exec'), namespace)
    rows = [{'agent': name, 'available': True, 'delegatable': True,
             'confinement_status': 'verified_development_bwrap'}
            for name in ('jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie')]
    app = FastAPI()
    app.state.tools = {'list_agents': lambda: rows}
    wrapped = SecurityMiddleware(app, api_key='test-placeholder', allowed_hosts=['localhost'])
    config = types.ModuleType('agentporter.config')
    config.Config = lambda **kwargs: kwargs
    server = types.ModuleType('agentporter.server')
    server.create_asgi_app = lambda config: wrapped
    monkeypatch.setitem(sys.modules, 'agentporter.config', config)
    monkeypatch.setitem(sys.modules, 'agentporter.server', server)
    monkeypatch.setattr(os, 'getuid', lambda: 994)
    monkeypatch.setattr(os, 'geteuid', lambda: 994)
    monkeypatch.setattr(Path, 'is_file', lambda self: True)
    monkeypatch.setattr(Path, 'is_symlink', lambda self: False)
    exec(compile(namespace['STARTUP_PROBE'], '<v10-startup>', 'exec'), {})
    assert json.loads(capsys.readouterr().out) == {'inventory': rows}
