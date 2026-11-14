"""Copilot account alias validation with synthetic credentials only."""
import base64
import json
import os
from pathlib import Path
import socket
import threading

import pytest

from agentporter.agents import credential_broker


def account(login='fixture-owner', host='github.com'):
    return {'login': login, 'host': host}


def test_matching_aliases_canonicalize_to_selected_account():
    document = {
        'lastLoggedInUser': account(),
        'last_logged_in_user': account('FIXTURE-OWNER', 'https://github.com'),
        'loggedInUsers': [account()],
        'logged_in_users': [account('FIXTURE-OWNER', 'https://github.com')],
        'authTokens': {'github.com': 'SYNTHETIC AUTH'},
        'auth_tokens': {'https://github.com': 'SYNTHETIC AUTH'},
        'copilotTokens': {'fixture-owner': 'SYNTHETIC COPILOT'},
        'copilot_tokens': {'FIXTURE-OWNER': 'SYNTHETIC COPILOT'},
        'settings': 'must not cross boundary',
    }
    assert credential_broker._copilot_access_document(document, 'fixture-owner') == {
        'lastLoggedInUser': account(), 'loggedInUsers': [account()],
        'authTokens': {'github.com': 'SYNTHETIC AUTH'},
        'copilotTokens': {'fixture-owner': 'SYNTHETIC COPILOT'},
    }


def test_current_owner_qualified_native_token_shape_is_preserved():
    document = {
        'lastLoggedInUser': account(), 'loggedInUsers': [account()],
        'authTokens': {'https://github.com:fixture-owner:github': {'token': 'SYNTHETIC AUTH'}},
        'copilotTokens': {'https://github.com:fixture-owner': 'SYNTHETIC COPILOT'},
    }
    assert credential_broker._copilot_access_document(document, 'fixture-owner') == document


def test_native_host_and_token_key_spellings_are_preserved():
    document = {
        'lastLoggedInUser': account(host='https://github.com'),
        'loggedInUsers': [account(host='github.com')],
        'authTokens': {'https://github.com:fixture-owner:github': {'token': 'SYNTHETIC AUTH'}},
        'copilotTokens': {'https://github.com:fixture-owner': 'SYNTHETIC COPILOT'},
    }
    assert credential_broker._copilot_access_document(document, 'fixture-owner') == {
        'lastLoggedInUser': account(host='https://github.com'),
        'loggedInUsers': [account(host='https://github.com')],
        'authTokens': {'https://github.com:fixture-owner:github': {'token': 'SYNTHETIC AUTH'}},
        'copilotTokens': {'https://github.com:fixture-owner': 'SYNTHETIC COPILOT'},
    }


@pytest.mark.parametrize('field,value', [
    ('last_logged_in_user', account('fixture-other')),
    ('logged_in_users', [account('fixture-other')]),
    ('auth_tokens', {'github.com': 'SYNTHETIC OTHER AUTH'}),
    ('copilot_tokens', {'fixture-other': 'SYNTHETIC OTHER COPILOT'}),
    ('loggedInUsers', [account(), account()]),
    ('logged_in_users', 'not-a-list'),
    ('lastLoggedInUser', {'login': 'fixture-owner', 'host': 'evil.example'}),
    ('authTokens', ['not-a-map']),
    ('copilotTokens', {'fixture-owner': ''}),
    ('authTokens', {'github.com': 'SYNTHETIC', 'fixture-owner': 'SYNTHETIC'}),
    ('authTokens', {'https://github.com:fixture-other:github': {'token': 'SYNTHETIC'}}),
    ('copilotTokens', {'https://github.com:fixture-other': 'SYNTHETIC'}),
    ('authTokens', {'https://github.com:fixture-owner:github': {'token': 'SYNTHETIC', 'other': 'x'}}),
])
def test_invalid_copilot_aliases_fail_closed(field, value):
    document = {'lastLoggedInUser': account(), 'loggedInUsers': [account()],
                'authTokens': {'github.com': 'SYNTHETIC AUTH'},
                'copilotTokens': {}}
    document[field] = value
    with pytest.raises(PermissionError):
        credential_broker._copilot_access_document(document, 'fixture-owner')


def test_receiver_rejects_conflicting_alias_before_creating_credential(tmp_path):
    socket_path = tmp_path / 'broker.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    listener.settimeout(2)
    bad_document = {
        'lastLoggedInUser': account(), 'loggedInUsers': [account()],
        'authTokens': {'github.com': 'SYNTHETIC AUTH'},
        'last_logged_in_user': account('fixture-other'),
    }
    response = {'status': 'issued', 'lease_id': 'lease-' + 'a' * 32,
                'auth_b64': base64.b64encode(json.dumps(bad_document).encode()).decode()}
    requests, server_errors = [], []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                # Complete the real framed handshake before closing. An early
                # close can race the client's send and mask alias validation.
                requests.append(credential_broker._receive(connection))
                credential_broker._send(connection, response)
        except Exception as error:
            server_errors.append(type(error).__name__)

    thread = threading.Thread(target=serve)
    thread.start()
    target = tmp_path / 'worker' / 'config.json'
    try:
        with pytest.raises(PermissionError, match='Conflicting Copilot account aliases'):
            credential_broker.BrokerCredentialLease(
                {'owner_uid': os.getuid(), 'socket_path': str(socket_path),
                 'account': 'prof', 'provider': 'copilot'}, target)
        assert not target.exists()
        assert requests == [{'version': 1, 'op': 'begin', 'account': 'prof'}]
    finally:
        listener.close()
        thread.join(2)
        assert not thread.is_alive()
        assert not server_errors
