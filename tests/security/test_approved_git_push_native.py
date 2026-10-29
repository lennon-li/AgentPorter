"""Signed backend interoperability with native receive-pack, never real remotes."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import threading
from urllib.parse import urlsplit

import pytest

from agentporter import git_remote_policy, git_smart_http
from agentporter.git_approvals import issue_git_approval
from agentporter.git_push_recovery import recover_push
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox import workspace_recovery
from tests.security.test_approved_git_push import configured
from tests.security.test_git_admission import count
from tests.security.test_git_approval_state import metadata
from tests.security.test_git_smart_http_native import git, _ENV

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='Native BCC sandbox required')


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_signed_push_and_lost_result_reconciliation_with_native_git(tmp_path, monkeypatch, algorithm):
    root, service, sandbox, key, manager, _, _ = configured(tmp_path, monkeypatch)
    monkeypatch.setattr(git_remote_policy, 'ScopedGitHTTP', git_smart_http.ScopedGitHTTP)
    if algorithm == 'sha256':
        shutil.rmtree(root / '.git')
        git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
        git(root, 'config', 'user.name', 'Fixture')
        git(root, 'config', 'user.email', 'fixture@example.invalid')
        git(root, 'add', 'ordinary')
        git(root, 'commit', '-qm', 'initial')
    remote = tmp_path / 'http/owner/repo.git'
    remote.parent.mkdir(parents=True)
    git(root, 'init', '-q', '--bare', '--object-format=' + algorithm, str(remote))
    git(remote, 'config', 'http.receivepack', 'true')
    backend = Path(subprocess.check_output(['/usr/bin/git', '--exec-path'], env=_ENV).decode().strip()) / 'git-http-backend'
    if not backend.is_file():
        pytest.skip('Native Git HTTP CGI unavailable')
    requests = []
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
            env = dict(_ENV, GIT_PROJECT_ROOT=str(tmp_path / 'http'), GIT_HTTP_EXPORT_ALL='1',
                REQUEST_METHOD=self.command, PATH_INFO=parts.path, QUERY_STRING=parts.query,
                CONTENT_TYPE=self.headers.get('Content-Type', ''), CONTENT_LENGTH=str(len(body)),
                REMOTE_USER='fixture', REMOTE_ADDR='127.0.0.1')
            process = subprocess.run([str(backend)], input=body, capture_output=True, env=env,
                                     timeout=10, check=True)
            headers, payload = process.stdout.split(b'\r\n\r\n', 1)
            fields = [line.decode().split(':', 1) for line in headers.split(b'\r\n')]
            status = next((int(v.strip().split()[0]) for n, v in fields if n.lower() == 'status'), 200)
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
    def connection(host, timeout):
        assert host == 'example.com'
        return http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=timeout)
    monkeypatch.setattr(git_smart_http, '_PinnedPublicHTTPS', connection)
    try:
        before = metadata(root)
        request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
        service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
        assert metadata(root) == before  # no local metadata writes, even during pack generation
        assert git(remote, 'rev-parse', 'refs/heads/reviewed').decode().strip() == request.to_payload()['expected_head']
        git(remote, 'fsck', '--strict', '--no-reflogs')
        (root / 'ordinary').write_text('second reviewed fixture edit')
        git(root, 'add', 'ordinary')
        git(root, 'commit', '-qm', 'second')
        request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
        original = git_smart_http.ScopedGitHTTP.send_push
        def lose_result(self, update, pack):
            original(self, update, pack)
            raise ResourceCleanupError('Synthetic lost host-side result after native publication')
        monkeypatch.setattr(git_smart_http.ScopedGitHTTP, 'send_push', lose_result)
        with pytest.raises(ResourceCleanupError):
            service.push('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
        assert count(manager) == 1
        assert git(remote, 'rev-parse', 'refs/heads/reviewed').decode().strip() == request.to_payload()['expected_head']
        sent = sum(method == 'POST' for method, _ in requests)
        sandbox.state_dir.chmod(0o700)
        monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
        plan = recover_push(service, 'repo')
        assert plan['observed_state'] == 'approved_tip'
        recover_push(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
        assert count(manager) == 0 and sum(method == 'POST' for method, _ in requests) == sent == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
