"""Exercise the production results transport without opening SSH or sockets."""

import hashlib
import json
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from agentporter.tools import scinet, scinet_broker as broker, scinet_inference as inference
from agentporter.tools import scinet_training as training


def results_argv():
    cases = ','.join(f'P{i:04d}_{kind}' for i in range(1, 22) for kind in ('pos', 'ctl'))
    return ['/usr/bin/python3', '-I', '-B', '-c', inference.REMOTE_INFERENCE_RESULTS,
            '/scratch/user/run', '123456', 'a' * 32, cases]


def test_reader_pins_are_independent_and_consistent():
    digest = hashlib.sha256(inference.REMOTE_INFERENCE_RESULTS.encode()).hexdigest()
    assert digest == inference.RESULT_READER_SHA256 == broker.INFERENCE_RESULTS_READER_SHA256


@pytest.mark.parametrize('transport', ['broker', 'fallback'])
def test_actual_results_transport_roundtrip(monkeypatch, tmp_path, transport):
    settings = SimpleNamespace(host='cluster.example', user='user', control_socket='~/.ssh/master',
                               broker_socket=str(tmp_path / 'broker.sock') if transport == 'broker' else '')
    service = broker.ScinetBroker(str(tmp_path / 'broker.sock'), str(tmp_path / 'master'),
                                 settings.host, settings.user)
    monkeypatch.setattr(broker, '_control_socket_available', lambda _: True)
    remote = results_argv()
    output = b'\xc3\xa9' * 100  # Validate byte preservation and byte output limits.
    calls = []

    def host(argv, home, **kwargs):
        calls.append((argv, kwargs))
        assert argv[0] == '/usr/bin/ssh' and '-n' in argv
        assert argv[-3:-1] == [settings.user, settings.host]
        assert shlex.split(argv[-1]) == [
            'exec', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', '/usr/bin/timeout', '60s', *remote]
        assert kwargs['input_bytes'] is None
        assert kwargs['max_output'] == len(output)
        return dict(exit_code=0, stdout=output, stderr=b'', timed_out=False, truncated=False)

    monkeypatch.setattr(broker, 'run_host_bytes', host)
    monkeypatch.setattr(scinet, 'run_host_bytes', host)

    class FakeChannel:
        """Use the real client framing and server dispatch, with no network I/O."""
        def __enter__(self):
            self.sent = b''
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, path):
            assert path == settings.broker_socket

        def sendall(self, data):
            self.sent += data

        def recv(self, size):
            header, body = self.sent.split(b'\n', 1)
            record = json.loads(header)
            assert record['operation'] == 'inference_results'
            assert record['remote'] == remote
            assert record['input_length'] == len(body) == 0
            return json.dumps(service._request(record, body)).encode() + b'\n'

    monkeypatch.setattr(broker.socket, 'socket', lambda *a, **k: FakeChannel())
    result = training._call(settings, SimpleNamespace(pw_dir=str(tmp_path)), remote,
                            operation='inference_results', max_output=len(output))
    assert result['stdout'] == output and len(result['stdout']) == 200
    assert len(calls) == 1


@pytest.mark.parametrize('change', [
    'python', 'flags', 'digest', 'wrapped', 'extra', 'missing', 'scratch', 'job', 'stage',
    'case-count', 'case-format', 'case-duplicate', 'nul',
])
def test_broker_and_fallback_reject_unreviewed_argv_before_execution(monkeypatch, tmp_path, change):
    remote = results_argv()
    if change == 'python': remote[0] = '/scratch/venv/bin/python'
    elif change == 'flags': remote[1] = '-E'
    elif change == 'digest': remote[4] += '\n# changed'
    elif change == 'wrapped': remote = ['/bin/bash', '-lc', shlex.join(remote)]
    elif change == 'extra': remote.append('extra')
    elif change == 'missing': remote.pop()
    elif change == 'scratch': remote[5] = '/scratch/user/../other'
    elif change == 'job': remote[6] = '000123'
    elif change == 'stage': remote[7] = 'A' * 32
    elif change == 'case-count': remote[8] += ',P9999_pos'
    elif change == 'case-format': remote[8] = remote[8].replace('P0001_pos', 'P0001_pos;id')
    elif change == 'case-duplicate': remote[8] = remote[8].replace('P0001_pos', 'P0001_ctl')
    elif change == 'nul': remote[8] += '\x00'
    service = broker.ScinetBroker(str(tmp_path / 'broker'), str(tmp_path / 'master'), 'host', 'user')
    # Validation must happen before checking the authenticated connection.
    monkeypatch.setattr(broker, '_control_socket_available', lambda _: pytest.fail('socket checked'))
    with pytest.raises(PermissionError):
        service._request(dict(version=1, operation='inference_results', remote=remote), b'')
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(SimpleNamespace(), SimpleNamespace(), remote,
                                operation='inference_results')


@pytest.mark.parametrize('body,length,command', [(b'x', 1, None), (b'', 1, None),
                                               (b'\xc3\xa9', 1, None), (b'', 0, 'id')])
def test_results_reject_stdin_command_and_wrong_byte_length(tmp_path, body, length, command):
    service = broker.ScinetBroker(str(tmp_path / 'broker'), str(tmp_path / 'master'), 'host', 'user')
    with pytest.raises((PermissionError, ValueError)):
        service._request(dict(version=1, operation='inference_results', remote=results_argv(),
                              input_length=length, command=command), body)
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(SimpleNamespace(), SimpleNamespace(), results_argv(),
                                operation='inference_results', input_bytes=body)


def test_results_envelope_ignores_hostile_environment(monkeypatch, tmp_path):
    marker = tmp_path / 'executed'
    startup = tmp_path / 'startup.sh'
    startup.write_text(f'touch {shlex.quote(str(marker))}\n')
    for name in ('python3', 'timeout', 'sacct'):
        path = tmp_path / name
        path.write_text(f'#!/bin/sh\n/bin/touch {shlex.quote(str(marker))}\n')
        path.chmod(0o700)
    for name in ('BASH_ENV', 'ENV', 'PYTHONSTARTUP'):
        monkeypatch.setenv(name, str(startup))
    monkeypatch.setenv('PATH', str(tmp_path))
    monkeypatch.setenv('PYTHONPATH', str(tmp_path))
    remote = results_argv()
    remote[5] = '/scratch/agentporter-absent-fixture-' + tmp_path.name
    for command in (broker._ssh_envelope('host', 'user', '/master', remote,
                                        operation='inference_results')[-1],
                    scinet.ssh_remote_argv(SimpleNamespace(control_socket='~/.ssh/master',
                                                           user='user', host='host'),
                                           str(tmp_path), remote, operation='inference_results')[-1]):
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, timeout=10)
        assert result.returncode == 65  # Fixed reader rejects the absent fixture, not PATH helpers.
    assert not marker.exists()


def test_broker_pin_cannot_be_overridden_by_inference_pin(monkeypatch):
    remote = results_argv()
    remote[4] += '\nprint("unreviewed")'
    monkeypatch.setattr(inference, 'RESULT_READER_SHA256', hashlib.sha256(remote[4].encode()).hexdigest())
    with pytest.raises(PermissionError, match='digest mismatch'):
        broker.inference_results_command(remote)


def test_training_call_keeps_operation_and_login_environment(monkeypatch, tmp_path):
    settings = SimpleNamespace(host='cluster.example', user='user', control_socket='~/.ssh/master',
                               broker_socket='')
    remote = ['/usr/bin/python3', '-c', 'print("training")']
    payload = b'\xc3\xa9\n'
    calls = []
    def host(argv, home, **kwargs):
        calls.append(argv)
        shell = shlex.split(argv[-1])
        assert shell[:2] == ['/bin/bash', '-lc']
        assert shlex.split(shell[2]) == ['exec', '/usr/bin/timeout', '17s', *remote]
        assert '-n' not in argv and kwargs['input_bytes'] == payload
        return {'exit_code': 0, 'stdout': payload}
    monkeypatch.setattr(scinet, 'run_host_bytes', host)
    assert training._call(settings, SimpleNamespace(pw_dir=str(tmp_path)), remote,
                          input_bytes=payload, timeout=17)['stdout'] == payload
    assert len(calls) == 1
