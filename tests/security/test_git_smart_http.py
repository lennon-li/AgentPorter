"""Scoped smart HTTP must reject ambiguous protocol and credential routing."""
from io import BytesIO
from pathlib import Path
import hashlib
import struct

import pytest

from agentporter import git_smart_http as transport
from agentporter.resources import ResourceCleanupError


def pack():
    body = b'PACK' + struct.pack('>II', 2, 0)
    return body + hashlib.sha1(body).digest()


def advertisement(refs=None):
    refs = {'refs/heads/main': 'a' * 40} if refs is None else refs
    lines = [transport.packet(b'# service=git-receive-pack\n'), b'0000']
    for index, (name, oid) in enumerate(refs.items()):
        line = (oid + ' ' + name).encode()
        if index == 0:
            line += b'\0report-status ofs-delta object-format=sha1'
        lines.append(transport.packet(line + b'\n'))
    if not refs:
        lines.append(transport.packet(b'0' * 40 + b' capabilities^{}\0report-status object-format=sha1\n'))
    return b''.join(lines) + b'0000'


def test_discovery_and_single_ref_push_status():
    observed = transport.parse_advertisement(advertisement(), 'git-receive-pack')
    assert observed.refs == {'refs/heads/main': 'a' * 40}
    update = transport.RefUpdate('refs/heads/main', 'a' * 40, 'b' * 40)
    body = transport.push_body(update, pack(), observed)
    assert body.endswith(pack())
    transport.check_push_result(transport.packet(b'unpack ok\n') +
        transport.packet(b'ok refs/heads/main\n') + b'0000', update)


@pytest.mark.parametrize('body', [b'0001', b'zzzz', b'0008x', b'0003', b'ffff' + b'x' * 10])
def test_malformed_packet_framing_is_rejected(body):
    with pytest.raises(ValueError):
        transport.parse_advertisement(body, 'git-receive-pack')


def test_duplicate_and_cross_service_advertisements_are_rejected():
    body = advertisement()
    duplicate = body[:-4] + transport.packet(b'b' * 40 + b' refs/heads/main\n') + b'0000'
    with pytest.raises(ValueError):
        transport.parse_advertisement(duplicate, 'git-receive-pack')
    with pytest.raises(ValueError):
        transport.parse_advertisement(body, 'git-upload-pack')


@pytest.mark.parametrize('ref', ['HEAD', 'refs/tags/release', 'refs/heads/../main', 'refs/heads/a.lock', 'refs/heads/a\n'])
def test_only_explicit_single_branch_updates_are_encodable(ref):
    with pytest.raises(ValueError):
        transport.RefUpdate(ref, 'a' * 40, 'b' * 40)


@pytest.mark.parametrize('url', [
    'http://github.com/owner/repo.git', 'https://user:token@github.com/owner/repo.git',
    'https://github.com/owner/repo.git?redirect=x', 'https://github.com:444/owner/repo.git',
    'https://github.com/owner/../repo.git', 'https://github.com/owner%2frepo.git',
])
def test_remote_origin_cannot_hide_credentials_or_select_other_routes(url):
    with pytest.raises(ValueError):
        transport.RemoteRepository(url)


class Response(BytesIO):
    def __init__(self, body, *, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or [('Content-Type', 'application/x-git-receive-pack-advertisement')]
    def getheaders(self):
        return self.headers


def test_transport_uses_fixed_origin_and_private_basic_credential(tmp_path, monkeypatch):
    secret = tmp_path / 'private/token'
    secret.parent.mkdir(mode=0o700)
    secret.write_text('synthetic-git-token-not-a-real-credential')
    secret.chmod(0o600)
    calls = []
    class Connection:
        def __init__(self, host, timeout):
            assert host == 'github.com'
        def request(self, method, target, body=None, headers=None):
            calls.append((method, target, body, headers))
        def getresponse(self):
            return Response(advertisement())
        def close(self):
            pass
    monkeypatch.setattr(transport, '_PinnedPublicHTTPS', Connection)
    broker = transport.ScopedGitHTTP(transport.RemoteRepository('https://github.com/owner/repo.git'),
                                     credential_file=secret)
    broker.discover('git-receive-pack')
    assert calls[0][:2] == ('GET', '/owner/repo.git/info/refs?service=git-receive-pack')
    assert calls[0][3]['Authorization'].startswith('Basic ')
    assert secret.read_text() not in repr(broker)


@pytest.mark.parametrize('kind', ['redirect', 'wrong_type', 'compressed', 'duplicate_length'])
def test_invalid_http_responses_do_not_trigger_fallback_or_redirect(kind, monkeypatch):
    headers = [('Content-Type', 'application/x-git-receive-pack-advertisement')]
    status = 200
    if kind == 'redirect':
        status = 302
        headers.append(('Location', 'https://attacker.invalid/'))
    elif kind == 'wrong_type':
        headers = [('Content-Type', 'text/plain')]
    elif kind == 'compressed':
        headers.append(('Content-Encoding', 'gzip'))
    else:
        headers += [('Content-Length', '4'), ('Content-Length', '5')]
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return Response(advertisement(), status=status, headers=headers)
        def close(self):
            pass
    monkeypatch.setattr(transport, '_PinnedPublicHTTPS', Connection)
    broker = transport.ScopedGitHTTP(transport.RemoteRepository('https://github.com/owner/repo.git'))
    with pytest.raises(PermissionError):
        broker.discover('git-receive-pack')


def test_post_failure_is_uncertain_and_never_retried(monkeypatch):
    calls = []
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, method, *args, **kwargs):
            calls.append(method)
            if method == 'POST':
                raise OSError('simulated private credential reflection')
        def getresponse(self):
            return Response(advertisement())
        def close(self):
            pass
    monkeypatch.setattr(transport, '_PinnedPublicHTTPS', Connection)
    broker = transport.ScopedGitHTTP(transport.RemoteRepository('https://github.com/owner/repo.git'))
    with pytest.raises(ResourceCleanupError) as failure:
        broker.send_push(transport.RefUpdate('refs/heads/main', 'a' * 40, 'b' * 40), pack())
    assert 'reflection' not in str(failure.value)
    assert calls == ['GET', 'POST']


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public', 'inside_workspace'])
def test_private_git_credentials_are_not_loaded_from_untrusted_locations(tmp_path, monkeypatch, kind):
    import os
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    token = directory / 'token'
    token.write_text('synthetic-private-git-token')
    token.chmod(0o600)
    roots = []
    if kind == 'symlink':
        token.rename(directory / 'original')
        token.symlink_to(directory / 'original')
    elif kind == 'hardlink':
        os.link(token, directory / 'alias')
    elif kind == 'public':
        token.chmod(0o644)
    else:
        roots = [tmp_path]
    calls = []
    def connection(*args, **kwargs):
        calls.append(args)
        raise AssertionError('Unsafe credential reached network setup')
    monkeypatch.setattr(transport, '_PinnedPublicHTTPS', connection)
    with pytest.raises((PermissionError, OSError)):
        broker = transport.ScopedGitHTTP(transport.RemoteRepository('https://github.com/owner/repo.git'),
                                         credential_file=token, workspace_roots=roots)
        broker.discover('git-receive-pack')
    assert calls == []


def test_success_status_for_another_ref_is_not_publication_confirmation():
    update = transport.RefUpdate('refs/heads/main', 'a' * 40, 'b' * 40)
    response = transport.packet(b'unpack ok\n') + transport.packet(b'ok refs/heads/other\n') + b'0000'
    with pytest.raises(ValueError):
        transport.check_push_result(response, update)


def test_corrupt_pack_is_rejected_before_command_encoding():
    update = transport.RefUpdate('refs/heads/main', 'a' * 40, 'b' * 40)
    observed = transport.parse_advertisement(advertisement(), 'git-receive-pack')
    with pytest.raises(ValueError, match='checksum'):
        transport.push_body(update, pack()[:-1] + b'!', observed)
