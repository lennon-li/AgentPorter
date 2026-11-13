"""Native local socket contract for BCC's separately installed Qman module."""
import json
import os
from pathlib import Path
import socket
import threading
import time

import pytest

live = pytest.importorskip('agentporter.qman_live')


def test_ambiguous_live_selector_is_actionable_without_starting_a_collector(monkeypatch):
    monkeypatch.setattr(live, 'policy', lambda _: pytest.fail('Selector must be checked before capability access'))
    result = live.request_live(None, 'all', 'all', '')
    assert result['agentporter']['reason'] == 'live_quota_requires_exact_provider_profile'
    assert result['agentporter']['cached_fallback_used'] is False


def test_unapproved_profile_never_opens_a_socket(monkeypatch):
    monkeypatch.setattr(live, 'policy', lambda _: {'profiles': ['phil']})
    monkeypatch.setattr(live, '_trusted', lambda *a, **kw: pytest.fail('Unauthorized socket access'))
    result = live.request_live(None, 'codex', 'prof', '')
    assert result['agentporter']['reason'] == 'live_quota_capability_not_authorized'
    assert result['agentporter']['provider_processes_started'] is False


@pytest.mark.parametrize('kind', ['fresh', 'stale', 'wrong_nonce', 'cached'])
def test_unix_response_requires_request_nonce_and_fresh_uncached_evidence(tmp_path, monkeypatch, kind):
    directory = tmp_path/'quota'
    directory.mkdir(mode=0o700)
    path = directory/'quota.sock'
    monkeypatch.setattr(live, 'SOCKET', path)
    monkeypatch.setattr(live, 'policy', lambda _: {'profiles': ['phil']})
    # Fixture directories under /tmp are not production control roots. All
    # socket mode and SO_PEERCRED checks in request_live remain exercised.
    monkeypatch.setattr(live, '_trusted', lambda path, directory=False: Path(path).lstat())
    errors = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            listener.bind(f'/proc/self/fd/{directory_fd}/quota.sock')
        finally:
            os.close(directory_fd)
        os.chmod(path, 0o600)
        listener.listen(1)
        listener.settimeout(5)
        def respond():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    raw = bytearray()
                    while not raw.endswith(b'\n'):
                        raw.extend(connection.recv(2048))
                        if len(raw) > 2048:
                            raise ValueError('Unbounded request')
                    request = json.loads(raw)
                    observed = time.time() if kind != 'stale' else 0
                    data = {'mode': 'live_first', 'execution_authorized': False,
                        'dispatch_enabled': False, 'database_used': kind == 'cached',
                        'collected_at_utc_epoch': time.time(),
                        'agents': [{'provider': 'copilot', 'profile': 'phil', 'live': True,
                            'source_kind': 'live_provider', 'source': 'synthetic_native_quota',
                            'observed_at': observed, 'identity_bound': False,
                            'windows': [{'observed_at_utc_epoch': observed, 'remaining_percent': 23}]}]}
                    nonce = request['nonce'] if kind != 'wrong_nonce' else '0' * 32
                    connection.sendall(json.dumps({'nonce': nonce, 'data': data}).encode()+b'\n')
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=respond)
        thread.start()
        # Keep the client connect address short as well as the bind address.
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        monkeypatch.setattr(live, 'SOCKET', Path(f'/proc/self/fd/{directory_fd}/quota.sock'))
        try:
            result = live.request_live(None, 'copilot', 'phil', '')
        finally:
            thread.join(6)
            os.close(directory_fd)
        assert not thread.is_alive() and not errors
    assert result['agentporter']['cached_fallback_used'] is False
    if kind == 'fresh':
        assert result['agentporter']['mode'] == 'live'
        assert result['agents'][0]['identity_bound'] is False
    else:
        assert result['agentporter']['mode'] == 'live_unavailable'
        assert result['agentporter']['reason'] == 'invalid_live_scope_or_response'
