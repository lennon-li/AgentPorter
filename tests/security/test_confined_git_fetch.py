"""Confined Git transport never interprets workspace Git configuration."""
from pathlib import Path
import subprocess
import pytest
from agentporter import confined_git_fetch as fetch

@pytest.fixture
def repo(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
    (root / '.git/config').write_text('[remote "origin"]\nurl = https://github.com/example/repo.git\n')
    return root

@pytest.mark.parametrize('url', ['file:///tmp/repo', 'ssh://github.com/r', 'http://github.com/r',
    'https://user:secret@github.com/r', 'https://github.com/r?secret=x',
    'https://localhost/r', 'https://127.0.0.1/r', 'https://10.0.0.1/r'])
def test_rejects_unsafe_remote(repo, tmp_path, url):
    (repo / '.git/config').write_text(f'[remote "origin"]\nurl = {url}\n')
    result = fetch.fetch_repository(repo, state_dir=tmp_path / 'state')
    assert result['status'] in {'denied', 'authunavailable'}
    assert url not in str(result)

def test_untrusted_config_is_not_executed(repo, tmp_path, monkeypatch):
    marker = tmp_path / 'executed'
    (repo / '.git/config').write_text(f'''[include]\npath = {tmp_path}/credentials\n[core]\nsshCommand = touch {marker}\n[credential]\nhelper = !touch {marker}\n[remote "origin"]\nurl = https://github.com/example/repo.git\n''')
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: [(2, 1, 6, '', ('140.82.114.4', 443))])
    monkeypatch.setattr(fetch, '_transport', lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    before = (repo / '.git/config').read_bytes()
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'timeout'
    assert not marker.exists()
    assert (repo / '.git/config').read_bytes() == before

def test_external_gitdir_denied(tmp_path):
    root = tmp_path / 'repo'; root.mkdir()
    (root / '.git').write_text('gitdir: ../private\n')
    assert fetch.fetch_repository(root, state_dir=tmp_path / 'state')['status'] == 'denied'

def test_success_imports_only_pack_and_remote_refs(repo, tmp_path, monkeypatch):
    source = tmp_path / 'source'
    subprocess.run(['/usr/bin/git', 'init', '-q', str(source)], check=True)
    subprocess.run(['/usr/bin/git', '-C', str(source), '-c', 'user.name=Test', '-c', 'user.email=t@example.org', 'commit', '--allow-empty', '-qm', 'fixture'], check=True)
    original = (repo / '.git/config').read_bytes()
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: [(2, 1, 6, '', ('140.82.114.4', 443))])
    def transport(bare, url, host, address, **kwargs):
        subprocess.run(['/usr/bin/git', '--git-dir', str(bare), 'fetch', '--quiet', '--no-tags', str(source), '+refs/heads/*:refs/heads/*'], check=True)
        subprocess.run(['/usr/bin/git', '--git-dir', str(bare), 'repack', '-adq'], check=True)
    monkeypatch.setattr(fetch, '_transport', transport)
    result = fetch.fetch_repository(repo, state_dir=tmp_path / 'state')
    assert result['status'] == 'ok', result
    assert result['refs'] == 1
    assert list((repo / '.git/objects/pack').glob('*.pack'))
    assert list((repo / '.git/refs/remotes/origin').iterdir())
    assert (repo / '.git/config').read_bytes() == original
    assert not (repo / '.git/index').exists()
    # Repeat import uses an atomic exchange of only this remote's loose refs.
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'ok'
    assert (repo / '.git/config').read_bytes() == original

def test_oversized_pack_leaves_original_unchanged(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: [(2, 1, 6, '', ('140.82.114.4', 443))])
    def transport(bare, *a, **kw):
        (bare / 'objects/pack/pack-0000000000000000000000000000000000000000.pack').write_bytes(b'x' * 2048)
    monkeypatch.setattr(fetch, '_transport', transport)
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state', max_pack_bytes=1024)['status'] == 'denied'
    assert not list((repo / '.git/objects/pack').iterdir())

def test_metadata_symlink_denied(repo, tmp_path):
    (repo / '.git/objects/pack').rmdir()
    (repo / '.git/objects/pack').symlink_to(tmp_path, target_is_directory=True)
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'denied'

def test_public_dns_answers_are_pinned_not_reresolved(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: [(2, 1, 6, '', ('140.82.114.4', 443))])
    def transport(bare, url, host, address, **kw):
        assert address == '140.82.114.4'
        raise TimeoutError()
    monkeypatch.setattr(fetch, '_transport', transport)
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'timeout'

def test_sandbox_has_no_owner_or_workspace_mounts(tmp_path):
    command = fetch._sandbox(tmp_path, True)
    assert '--share-net' not in command
    assert '/home/operator' not in command
    assert '--clearenv' in command
    assert 'GIT_CONFIG_NOSYSTEM' in command
    assert 'http_proxy' not in fetch._ENV

@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1'])
def test_private_dns_answers_denied(repo, tmp_path, monkeypatch, ip):
    import socket
    from agentporter.scoped_https import _resolve_public_addresses
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: _resolve_public_addresses(host, resolver=lambda *a, **kw: [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))]))
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'denied'

def test_transport_disables_redirects_helpers_and_other_protocols(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(fetch.subprocess, 'run', lambda command, **kw: calls.append((command, kw)) or subprocess.CompletedProcess(command, 0))
    fetch._transport(tmp_path, 'https://github.com/example/r', 'github.com', '140.82.114.4', timeout_seconds=2, max_pack_bytes=1024)
    command, options = calls[0]
    assert 'http.curloptResolve=github.com:443:140.82.114.4' in command
    assert 'http.followRedirects=false' in command
    assert 'protocol.allow=never' in command
    assert 'protocol.https.allow=always' in command
    assert 'credential.helper=' in command
    assert 'http.sslVerify=true' in command
    assert options['env'] == fetch._ENV
    assert options['stdin'] == subprocess.DEVNULL
    assert options['timeout'] == 2


def test_remote_reference_symlink_preserved_on_failure(repo, tmp_path, monkeypatch):
    remotes = repo / '.git/refs/remotes'
    remotes.mkdir()
    (remotes / 'origin').symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(fetch, '_resolve_public_addresses', lambda host: [(2, 1, 6, '', ('140.82.114.4', 443))])
    monkeypatch.setattr(fetch, '_transport', lambda *a, **kw: None)
    monkeypatch.setattr(fetch, '_run', lambda *a, **kw: b'')
    assert fetch.fetch_repository(repo, state_dir=tmp_path / 'state')['status'] == 'denied'
    assert (remotes / 'origin').is_symlink()
    assert not list((repo / '.git/objects/pack').iterdir())

def test_origin_proxy_denies_alternate_host_without_connecting(tmp_path, monkeypatch):
    import socket
    from agentporter.confined_git_fetch import OriginEgress
    def never(*a, **kw):
        raise AssertionError('No network socket should be created for denied origin')
    proxy = OriginEgress(tmp_path / 'proxy.sock', 'github.com', '140.82.114.4')
    # Connect to its Unix listener before preventing outbound socket creation.
    with proxy:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(tmp_path / 'proxy.sock'))
        monkeypatch.setattr(fetch, '_connect_pinned', never)
        client.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        assert b'403' in client.recv(1024)
        client.close()
