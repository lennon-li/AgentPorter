import os
from pathlib import Path
import json
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agentporter import git_remote_policy
from agentporter.git_approvals import GitApprovalRequest, issue_git_approval
from agentporter.git_fetches import ApprovedGitFetches
from agentporter.git_smart_http import Advertisement, validate_pack
from agentporter.git_fetches import _promote_quarantine, _write_fetch_guard
from agentporter.resources import ResourceCleanupError
from tests.security.test_approved_git_push import configured
from tests.security.test_git_approval_state import git


def _layout(tmp_path):
    metadata = tmp_path / '.git'
    canonical = metadata / 'objects'
    quarantine_root = tmp_path / 'quarantine'
    quarantine = quarantine_root / 'objects' / 'pack'
    canonical.mkdir(parents=True)
    quarantine.mkdir(parents=True)
    digest = 'a' * 40
    (quarantine / f'pack-{digest}.pack').write_bytes(b'validated-pack-bytes')
    (quarantine / f'pack-{digest}.idx').write_bytes(b'validated-index-bytes')
    fd = os.open(metadata, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return metadata, quarantine_root, digest, fd


def test_promote_quarantine_installs_pack_and_index_without_overwrite(tmp_path):
    metadata, quarantine, digest, fd = _layout(tmp_path)
    try:
        _promote_quarantine(fd, quarantine, digest)
        _promote_quarantine(fd, quarantine, digest)
    finally:
        os.close(fd)
    target = metadata / 'objects' / 'pack'
    assert (target / f'pack-{digest}.pack').read_bytes() == b'validated-pack-bytes'
    assert (target / f'pack-{digest}.idx').read_bytes() == b'validated-index-bytes'
    assert not list(target.glob('.agentporter-fetch-*'))


def test_promote_quarantine_rejects_conflicting_canonical_pack(tmp_path):
    metadata, quarantine, digest, fd = _layout(tmp_path)
    target = metadata / 'objects' / 'pack'
    target.mkdir()
    (target / f'pack-{digest}.pack').write_bytes(b'different-pack-content')
    try:
        with pytest.raises(PermissionError, match='Conflicting canonical Git pack'):
            _promote_quarantine(fd, quarantine, digest)
    finally:
        os.close(fd)
    assert (target / f'pack-{digest}.pack').read_bytes() == b'different-pack-content'
    assert not list(target.glob('.agentporter-fetch-*'))


def test_fetch_guard_is_durable_atomic_and_never_overwritten(tmp_path):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    path = directory / 'workspace.git-pending.json'
    record = {'version': 2, 'request_sha256': 'a' * 64}
    _write_fetch_guard(path, record)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == record
    with pytest.raises(FileExistsError):
        _write_fetch_guard(path, {'version': 2, 'request_sha256': 'b' * 64})
    assert json.loads(path.read_text()) == record
    assert not list(directory.glob('.git-fetch-pending-*'))


@pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='Native BCC sandbox required')
@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('failure_stage', ['before_index', 'after_ref_update'])
def test_signed_fetch_indexes_quarantine_and_advances_only_exact_tracking_ref(
        tmp_path, monkeypatch, algorithm, failure_stage):
    root, push_service, sandbox, key, manager, _, policy_path = configured(tmp_path, monkeypatch)
    if algorithm == 'sha256':
        shutil.rmtree(root / '.git')
        git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
        git(root, 'config', 'user.name', 'Fixture')
        git(root, 'config', 'user.email', 'fixture@example.invalid')
        git(root, 'add', 'ordinary')
        git(root, 'commit', '-qm', 'initial sha256 fixture')
    policy = json.loads(policy_path.read_text())
    policy['grants'][0]['operations'] = ['fetch']
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o600)

    remote = tmp_path / 'remote.git'
    git(root, 'init', '-q', '--bare', '--object-format=' + algorithm, str(remote))
    git(root, 'remote', 'add', 'fixture', str(remote))
    git(root, 'push', '-q', 'fixture', 'HEAD:refs/heads/reviewed')
    git(root, f'--git-dir={remote}', 'symbolic-ref', 'HEAD', 'refs/heads/reviewed')
    old_oid = git(root, 'rev-parse', 'HEAD')
    checkout = tmp_path / 'remote-worktree'
    subprocess.run(['/usr/bin/git', 'clone', '-q', str(remote), str(checkout)], check=True)
    git(checkout, 'config', 'user.name', 'Fixture')
    git(checkout, 'config', 'user.email', 'fixture@example.invalid')
    (checkout / 'ordinary').write_text('signed fetch content')
    git(checkout, 'add', 'ordinary')
    git(checkout, 'commit', '-qm', 'remote update')
    remote_oid = git(checkout, 'rev-parse', 'HEAD')
    git(checkout, 'push', '-q', 'origin', 'HEAD:refs/heads/reviewed')
    pack = subprocess.run(['/usr/bin/git', f'--git-dir={remote}', 'pack-objects', '--stdout', '--revs'],
        input=f'{remote_oid}\n^{old_oid}\n'.encode(), stdout=subprocess.PIPE, check=True).stdout
    validate_pack(pack, algorithm)

    class Broker:
        def __init__(self, *args, **kwargs):
            pass
        def discover(self, service):
            assert service == 'git-upload-pack'
            return Advertisement({'refs/heads/reviewed': remote_oid}, frozenset({'side-band-64k'}), algorithm)
        def fetch_pack(self, ref, expected_oid):
            assert ref == 'refs/heads/reviewed' and expected_oid == remote_oid
            return pack

    monkeypatch.setattr(git_remote_policy, 'ScopedGitHTTP', Broker)
    authority = git_remote_policy.load_owner_git_remotes(policy_path.parent, push_service.registry, sandbox.state_dir)
    service = ApprovedGitFetches(push_service.registry, sandbox, authority, manager)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed')
    parameters = request.to_payload()['parameters']
    assert parameters['old_oid'] == '0' * len(remote_oid) and parameters['remote_oid'] == remote_oid
    assert subprocess.run(['/usr/bin/git', 'rev-parse', '--verify', '--quiet',
        'refs/remotes/origin/reviewed'], cwd=root, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode != 0
    from agentporter import git_fetches
    receipt_attempts = []
    if failure_stage == 'after_ref_update':
        original_write = git_fetches._write_private
        def fail_success_receipt(path, document):
            if Path(path).parent.name == 'git-fetch-receipts':
                receipt_attempts.append(Path(path))
                raise OSError('synthetic interruption after tracking ref update')
            return original_write(path, document)
        monkeypatch.setattr(git_fetches, '_write_private', fail_success_receipt)
    else:
        original_run = sandbox._run_command
        def fail_quarantine(**kwargs):
            if kwargs.get('workspace_transaction') is not None:
                return {'exit_code': 1, 'stdout': '', 'stderr': 'synthetic interruption before indexing'}
            return original_run(**kwargs)
        monkeypatch.setattr(sandbox, '_run_command', fail_quarantine)
    with pytest.raises(ResourceCleanupError, match='reconciliation'):
        service.fetch('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request))
    if failure_stage == 'after_ref_update':
        assert receipt_attempts, 'fetch did not reach success receipt after tracking update'
        assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote_oid
    else:
        assert not receipt_attempts
        assert subprocess.run(['/usr/bin/git', 'rev-parse', '--verify', '--quiet',
            'refs/remotes/origin/reviewed'], cwd=root, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode != 0
    assert git(root, 'rev-parse', 'HEAD') == old_oid
    assert (root / 'ordinary').read_text() != 'signed fetch content'
    assert len(list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))) == 1
    from agentporter.sandbox import workspace_recovery
    from agentporter.git_fetch_recovery import recover_fetch
    sandbox.state_dir.chmod(0o700)
    monkeypatch.setattr(workspace_recovery, '_verify_stopped_service', lambda: None)
    plan = recover_fetch(service, 'repo')
    expected_state = 'approved_tip' if failure_stage == 'after_ref_update' else 'original_tip'
    assert plan['observed_state'] == expected_state
    result = recover_fetch(service, 'repo', apply=True, expected_plan_sha256=plan['plan_sha256'])
    assert result['status'] == 'recovered' and Path(result['receipt']).is_file()
    assert not list((sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    assert len(list((sandbox.state_dir / 'git-fetch-recovery-receipts').glob('*.json'))) == 1


@pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='Native BCC sandbox required')
def test_scoped_rest_prepare_and_mcp_execute_use_exact_fetch_receipt(tmp_path, monkeypatch):
    import yaml
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    from agentporter import server
    from agentporter.config import Config
    from agentporter.tools.jobs import JobManager
    from tests.security.test_closeout_client_policy import rpc

    root, push_service, sandbox, key, _, _, policy_path = configured(tmp_path, monkeypatch)
    policy = json.loads(policy_path.read_text())
    policy['grants'][0]['operations'] = ['fetch']
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o600)
    remote = tmp_path / 'api-remote.git'
    git(root, 'init', '-q', '--bare', str(remote))
    git(root, 'remote', 'add', 'api-fixture', str(remote))
    git(root, 'push', '-q', 'api-fixture', 'HEAD:refs/heads/reviewed')
    git(root, f'--git-dir={remote}', 'symbolic-ref', 'HEAD', 'refs/heads/reviewed')
    old_oid = git(root, 'rev-parse', 'HEAD')
    checkout = tmp_path / 'api-remote-worktree'
    subprocess.run(['/usr/bin/git', 'clone', '-q', str(remote), str(checkout)], check=True)
    git(checkout, 'config', 'user.name', 'Fixture')
    git(checkout, 'config', 'user.email', 'fixture@example.invalid')
    (checkout / 'ordinary').write_text('API fetch content')
    git(checkout, 'add', 'ordinary')
    git(checkout, 'commit', '-qm', 'API remote update')
    remote_oid = git(checkout, 'rev-parse', 'HEAD')
    git(checkout, 'push', '-q', 'origin', 'HEAD:refs/heads/reviewed')
    pack = subprocess.run(['/usr/bin/git', f'--git-dir={remote}', 'pack-objects', '--stdout', '--revs'],
        input=f'{remote_oid}\n^{old_oid}\n'.encode(), stdout=subprocess.PIPE, check=True).stdout

    class Broker:
        def __init__(self, *args, **kwargs):
            pass
        def discover(self, service_name):
            assert service_name == 'git-upload-pack'
            return Advertisement({'refs/heads/reviewed': remote_oid}, frozenset({'side-band-64k'}), 'sha1')
        def fetch_pack(self, ref, expected_oid):
            assert (ref, expected_oid) == ('refs/heads/reviewed', remote_oid)
            return pack

    monkeypatch.setattr(git_remote_policy, 'ScopedGitHTTP', Broker)
    public_path = policy_path.parent / 'public-client-policy.yaml'
    public_path.write_text(yaml.safe_dump({'version': 1, 'workspaces': {'repo': {
        'path': str(root), 'operations': ['git_fetch']}}}))
    public_path.chmod(0o600)
    monkeypatch.setenv('AGENTPORTER_API_KEY', 'synthetic-public-fetch-client')
    config = Config(config_dir=policy_path.parent, state_dir=sandbox.state_dir, cache_dir=tmp_path / 'cache')
    config.workspaces = {'repo': {'path': str(root), 'writable': True}}
    config.sandbox.workspace_transactions = True
    config.security.allowed_hosts = ['testserver']
    resources = sandbox.resources
    resources.recover = lambda: None
    runtime = SimpleNamespace(_config=lambda: {'job_resources': {}})
    monkeypatch.setattr(server, 'AgentBroker', lambda *args, **kwargs:
        SimpleNamespace(development_runtime=runtime, list_agents=lambda: []))
    monkeypatch.setattr(server, 'JobResources', lambda settings: resources)
    managers = []
    def manager_factory(*args, **kwargs):
        instance = JobManager(*args, **kwargs)
        managers.append(instance)
        return instance
    monkeypatch.setattr(server, 'JobManager', manager_factory)
    try:
        with TestClient(server.create_asgi_app(config), client=('127.0.0.1', 12345)) as client:
            headers = {'X-AgentPorter-Key': config.api_key}
            request_args = {'branch': 'refs/heads/reviewed', 'prepare_only': True}
            response = client.post('/api/v1/workspaces/repo/git/fetch',
                                   json=request_args, headers=headers)
            assert response.status_code == 200, response.text
            prepared = json.loads(response.json())
            mcp_prepared = rpc(client, config.api_key, 'git_fetch', {
                'workspace_id': 'repo', **request_args})
            assert not mcp_prepared['result'].get('isError'), mcp_prepared
            mcp_proposal = json.loads(mcp_prepared['result']['content'][0]['text'])
            assert mcp_proposal['request_sha256'] == prepared['request_sha256']
            request = GitApprovalRequest.from_payload(mcp_proposal['request'])
            receipt = issue_git_approval(key, request)
            execution = client.post('/api/v1/workspaces/repo/git/fetch',
                json={'branch': 'refs/heads/reviewed', 'approval_receipt': receipt}, headers=headers)
            assert execution.status_code == 200, execution.text
            assert execution.json() == remote_oid
            assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote_oid
            assert git(root, 'rev-parse', 'HEAD') == old_oid
    finally:
        for instance in managers:
            if getattr(instance, '_supervisor_lock', None) is not None:
                os.close(instance._supervisor_lock)
