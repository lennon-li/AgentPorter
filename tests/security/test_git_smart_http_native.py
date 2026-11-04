"""Wire compatibility against native Git CGI in an isolated local fixture."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import threading
from urllib.parse import urlsplit

import pytest

from agentporter import git_smart_http as transport
from agentporter.resources import ResourceCleanupError

_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/nonexistent',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}


def git(root, *args, data=None):
    return subprocess.check_output(['/usr/bin/git', *args], cwd=root, input=data, env=_ENV)


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_native_smart_http_push_cas_and_fetch_pack(tmp_path, monkeypatch, algorithm):
    executable = shutil.which('git')
    if executable is None:
        pytest.skip('Native Git unavailable')
    backend = Path(subprocess.check_output([executable, '--exec-path']).decode().strip()) / 'git-http-backend'
    if not backend.is_file():
        pytest.skip('Native Git HTTP CGI unavailable')
    local = tmp_path / 'local'
    remote = tmp_path / 'http/owner/repo.git'
    local.mkdir()
    remote.parent.mkdir(parents=True)
    git(local, 'init', '-q', '-b', 'main', '--object-format=' + algorithm)
    git(local, 'config', 'user.name', 'Fixture')
    git(local, 'config', 'user.email', 'fixture@example.invalid')
    (local / 'ordinary').write_text('approved test data')
    git(local, 'add', 'ordinary')
    git(local, 'commit', '-qm', 'fixture')
    head = git(local, 'rev-parse', 'HEAD').decode().strip()
    git(local, 'init', '-q', '--bare', '--object-format=' + algorithm, str(remote))
    git(remote, 'config', 'http.receivepack', 'true')
    requests = []
    intervene = [False]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.dispatch()
        def do_POST(self):
            self.dispatch()
        def dispatch(self):
            parts = urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            requests.append((self.command, self.path))
            if intervene[0] and self.command == 'POST' and parts.path.endswith('/git-receive-pack'):
                git(remote, 'update-ref', '-d', 'refs/heads/reviewed')
                intervene[0] = False
            environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/nonexistent',
                'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                'GIT_PROJECT_ROOT': str(tmp_path / 'http'), 'GIT_HTTP_EXPORT_ALL': '1',
                'REQUEST_METHOD': self.command, 'PATH_INFO': parts.path,
                'QUERY_STRING': parts.query, 'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                'CONTENT_LENGTH': str(len(body)), 'REMOTE_USER': 'fixture', 'REMOTE_ADDR': '127.0.0.1',
                'HTTP_GIT_PROTOCOL': self.headers.get('Git-Protocol', '')}
            process = subprocess.run([str(backend)], input=body, capture_output=True, env=environment,
                                     timeout=10, check=True)
            headers, payload = process.stdout.split(b'\r\n\r\n', 1)
            fields = [line.decode().split(':', 1) for line in headers.split(b'\r\n')]
            status = next((int(value.strip().split()[0]) for name, value in fields if name.lower() == 'status'), 200)
            self.send_response(status)
            for name, value in fields:
                if name.lower() not in {'status', 'content-length'}:
                    self.send_header(name, value.strip())
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Only this fixture replaces the TLS/public-address connection. Production
    # uses the existing pinned public HTTPS implementation with no such input.
    def connect(host, timeout):
        assert host == 'git.example.invalid'
        return http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=timeout)
    monkeypatch.setattr(transport, '_PinnedPublicHTTPS', connect)
    broker = transport.ScopedGitHTTP(transport.RemoteRepository('https://git.example.invalid/owner/repo.git'))
    try:
        pack = git(local, 'pack-objects', '--stdout', '--revs', data=(head + '\n').encode())
        update = transport.RefUpdate('refs/heads/reviewed', '0' * len(head), head)
        broker.send_push(update, pack)
        assert git(remote, 'rev-parse', 'refs/heads/reviewed').decode().strip() == head
        before = len(requests)
        with pytest.raises(PermissionError):
            broker.send_push(update, pack)
        assert len(requests) == before + 1  # stale CAS denied before POST
        fetched = broker.fetch_pack('refs/heads/reviewed', head)
        quarantine = tmp_path / 'quarantine'
        git(local, 'init', '-q', '--bare', '--object-format=' + algorithm, str(quarantine))
        git(quarantine, 'index-pack', '--stdin', '--strict', data=fetched)
        assert git(quarantine, 'cat-file', '-t', head).strip() == b'commit'
        (local / 'ordinary').write_text('next approved test data')
        git(local, 'commit', '-qam', 'second')
        second = git(local, 'rev-parse', 'HEAD').decode().strip()
        next_pack = git(local, 'pack-objects', '--stdout', '--revs', data=(second + '\n').encode())
        intervene[0] = True
        with pytest.raises(ResourceCleanupError):
            broker.send_push(transport.RefUpdate('refs/heads/reviewed', head, second), next_pack)
        assert subprocess.run(['/usr/bin/git', 'show-ref', '--verify', '--quiet', 'refs/heads/reviewed'],
                              cwd=remote, env=_ENV).returncode != 0  # preserve the owner's concurrent deletion
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
