"""Synthetic fresh Chrome profile: persistence, trusted review, and real signing."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_approvals import GitApprovalVerifier
from tests.security.test_approved_git_commit import backend
from tests.security.test_git_approval_state import git

CHROME = shutil.which('google-chrome') or shutil.which('chromium')
NODE = shutil.which('node')
ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(CHROME is None or NODE is None or not Path('/opt/agentporter-bcc/bin/bwrap').is_file(),
                               reason='Native owner signing/commit test requires Chrome, Node, and installed BCC sandbox')


class Assets(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()


@pytest.mark.parametrize('operation', ['commit', 'push'])
def test_device_browser_review_signing_and_key_persistence(tmp_path, monkeypatch, operation):
    assets = ROOT / 'src/agentporter/owner_approval'
    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Assets, directory=str(assets)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = 'http://127.0.0.1:' + str(server.server_address[1])
    profile = tmp_path / 'synthetic-browser-profile'
    profile.mkdir(mode=0o700)
    screenshot = tmp_path / 'owner-approval-phone.png'
    command = [CHROME, '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
        '--disable-extensions', '--disable-domain-reliability', '--metrics-recording-only',
        '--password-store=basic', '--use-mock-keychain', '--no-proxy-server',
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1',
        '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + str(profile)]
    browser = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port_file = profile / 'DevToolsActivePort'
        deadline = time.monotonic() + 15
        while not port_file.exists() and time.monotonic() < deadline:
            assert browser.poll() is None, 'Fresh browser failed to start with its OS sandbox enabled'
            time.sleep(.03)
        assert port_file.exists(), 'Browser debugging endpoint did not arrive'
        port = port_file.read_text().splitlines()[0]
        gateway = tmp_path / 'synthetic-gateway'
        gateway.mkdir()
        driver = subprocess.Popen([NODE, str(ROOT / 'tests/owner_approval_browser.mjs'), port, origin,
            str(screenshot), '--exchange-key'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        public_key = json.loads(driver.stdout.readline())['publicKey']
        if operation == 'push':
            from tests.security.test_approved_git_push import configured
            from agentporter.git_remote_policy import load_owner_git_remotes
            from agentporter.git_pushes import ApprovedGitPushes
            root, original, sandbox, _, manager, remote, policy = configured(gateway, monkeypatch)
            data = json.loads(policy.read_text())
            data['verification_key'] = public_key
            policy.write_text(json.dumps(data))
            authority = load_owner_git_remotes(policy.parent, original.registry, sandbox.state_dir)
            service = ApprovedGitPushes(original.registry, sandbox, authority, manager)
            scope = service.prepare('repo', 'origin', 'refs/heads/reviewed')
        else:
            root, service, _, _ = backend(gateway)
        (root / 'ordinary').write_text('device-reviewed edit')
        git(root, 'add', 'ordinary')
        message = 'Reviewed Ω <img src="https://invalid.example/secret">'
        timestamp = int(time.time())
        if operation == 'commit':
            service.verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)),
                                                   tmp_path / 'owner/claims.db')
            scope = service.prepare('repo', message, timestamp)
        data = {'request': scope.to_payload(), 'request_sha256': scope.digest}
        output, errors = driver.communicate(json.dumps(data), timeout=45)
        assert driver.returncode == 0, errors
        observed = json.loads(output)
        for field in ('persisted', 'privateExportDenied', 'noInjectedElements', 'initiallyDisabled',
                      'syntheticClickDenied', 'changedProposalInvalidated', 'malformedLinkDenied',
                      'linkedProposalRequiresReview'):
            assert observed[field] is True, (field, observed)
        assert observed['externalRequests'] == []
        assert observed['publicKey'] == public_key
        if operation == 'commit':
            commit = service.commit('repo', message, timestamp, observed['receipt'])
            assert commit == git(root, 'rev-parse', 'HEAD')
            assert git(root, 'show', 'HEAD:ordinary') == 'device-reviewed edit'
        else:
            # Regenerate after the common test edit changed the staged tree.
            # The signed proposal was deliberately captured before that change.
            # Restore the index to its proposal state, preserving worktree edit.
            git(root, 'reset', '--mixed', 'HEAD')
            result = service.push('repo', 'origin', 'refs/heads/reviewed', observed['receipt'])
            assert result == git(root, 'rev-parse', 'HEAD') and len(remote['sent']) == 1
            details = observed['reviewedDetails']
            for value in ('https://example.com/owner/repo.git', 'refs/heads/reviewed',
                          scope.to_payload()['parameters']['pack_sha256'], 'Fast-forward-only'):
                assert value in details
        assert screenshot.stat().st_size > 1000
    finally:
        if 'driver' in locals() and driver.poll() is None:
            driver.kill()
            driver.communicate(timeout=5)
        browser.terminate()
        try:
            browser.wait(timeout=10)
        except subprocess.TimeoutExpired:
            browser.kill()
            browser.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
