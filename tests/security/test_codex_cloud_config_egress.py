"""Observed Codex 0.166.0 managed-policy GET; synthetic TLS only, no providers."""
import socket
import ssl
import threading

import pytest

from agentporter.agents import provider_egress as broker
from tests.security.test_provider_origin_broker import relay, connect_client

PATH = '/backend-api/wham/config/bundle'


@pytest.mark.parametrize('agent', ['codex_review', 'codex_impl', 'codex_research'])
def test_managed_bundle_read_is_exact_for_codex_accounts(agent):
    rules = broker.provider_rules(agent)
    header = ('GET '+PATH+' HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer synthetic').encode()
    outgoing, length = broker.request_header(header, 'chatgpt.com', rules)
    assert length == 0
    assert outgoing.startswith(('GET '+PATH+' HTTP/1.1\r\nHost: chatgpt.com\r\n').encode())
    assert b'authorization: Bearer synthetic' in outgoing
    assert broker.diagnostic_operation(('GET '+PATH+'?token=SYNTHETIC HTTP/1.1').encode()) == 'GET '+PATH


@pytest.mark.parametrize('method,target', [
    ('POST', PATH), ('DELETE', PATH), ('HEAD', PATH),
    ('GET', '/backend-api/codex/config/bundle'),
    ('GET', '/codex/config/bundle'), ('GET', '/api/codex/config/bundle'),
    ('GET', '/wham/config/bundle'), ('GET', PATH+'/'),
    ('GET', PATH+'/other'), ('GET', '/backend-api/wham/config'),
    ('GET', '/backend-api/wham/config/%62undle'),
    ('GET', '/backend-api/wham/config/../config/bundle'),
    ('GET', '//chatgpt.com'+PATH), ('GET', 'https://chatgpt.com'+PATH),
])
def test_bundle_rule_does_not_expand_to_other_paths_or_methods(method,target):
    for agent in ('codex_review','codex_impl','codex_research'):
        rules=broker.provider_rules(agent)
        assert not broker.operation_allowed(rules,'chatgpt.com',method,target)
        with pytest.raises((PermissionError,ValueError)):
            broker.request_header((method+' '+target+' HTTP/1.1\r\nHost: chatgpt.com').encode(),'chatgpt.com',rules)


@pytest.mark.parametrize('host', ['api.openai.com','auth.openai.com','evil.chatgpt.com','chatgpt.com.evil.invalid','127.0.0.1'])
def test_bundle_rule_does_not_expand_authorities(host):
    assert not broker.operation_allowed(broker.provider_rules('codex_review'),host,'GET',PATH)


@pytest.mark.parametrize('agent', ['claude_agent','opencode_free','agy_agent','copilot_agent'])
def test_other_agents_do_not_gain_codex_bundle_access(agent):
    assert not broker.operation_allowed(broker.provider_rules(agent),'chatgpt.com','GET',PATH)


def test_bundle_get_cannot_smuggle_body_or_rewrite_authority():
    base=('GET '+PATH+' HTTP/1.1\r\nHost: chatgpt.com').encode()
    with pytest.raises(ValueError,match='Unexpected HTTP body'):
        broker.request_header(base+b'\r\nContent-Length: 2','chatgpt.com',broker.provider_rules('codex_review'))
    with pytest.raises(PermissionError,match='authority differs'):
        broker.request_header(base.replace(b'Host: chatgpt.com',b'Host: api.openai.com'),'chatgpt.com',broker.provider_rules('codex_review'))


def test_real_tls_bundle_get_preserves_upstream_policy_denial(relay,monkeypatch):
    """The admitted GET reaches verified same-origin TLS; server denial stays denial."""
    observed=[];servers=[]
    relay._upstream_context=ssl.create_default_context(cafile=str(relay.ca_bundle))
    def connect(host):
        assert host=='chatgpt.com'
        local,remote=socket.socketpair()
        def serve():
            with relay._contexts[host].wrap_socket(remote,server_side=True) as connection:
                header,body=broker.read_header(connection)
                observed.append((header,body))
                connection.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        server=threading.Thread(target=serve,daemon=True);server.start();servers.append(server)
        return local
    monkeypatch.setattr(broker,'_connect_public',connect)
    client,thread,_=connect_client(relay,host='chatgpt.com')
    try:
        client.sendall(('GET '+PATH+' HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n').encode())
        response=bytearray()
        while block:=client.recv(4096):response.extend(block)
        assert response.startswith(b'HTTP/1.1 403 Forbidden\r\n')
    finally:
        client.close();thread.join(2)
        for server in servers:server.join(2)
    assert not thread.is_alive() and all(not server.is_alive() for server in servers)
    assert len(observed)==1 and observed[0][1]==b''
    assert observed[0][0].startswith(('GET '+PATH+' HTTP/1.1\r\nHost: chatgpt.com\r\n').encode())
