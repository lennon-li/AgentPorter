"""Real signed/admitted pull acquisition into unpublished private candidates."""
from tests.sandbox_support import BWRAP
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from agentporter import git_remote_policy
from agentporter.git_approvals import issue_git_approval
from agentporter.git_pulls import ApprovedGitPulls
from agentporter.git_smart_http import Advertisement
from agentporter.resources import ResourceCleanupError
from tests.security.test_approved_git_push import configured
from tests.security.test_git_admission import count
from tests.security.test_git_pull_integration import snapshot
from tests.security.test_git_approval_state import git

pytestmark = pytest.mark.skipif(not Path(BWRAP).is_file(),
                               reason='Gateway native overlay sandbox required')


def backend(tmp_path, monkeypatch, algorithm='sha1', divergent=False, conflict=False, owner_file=False):
    root, original, sandbox, key, manager, _, policy_path = configured(tmp_path, monkeypatch)
    if algorithm == 'sha256':
        shutil.rmtree(root / '.git')
        git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
        git(root, 'config', 'user.name', 'Fixture')
        git(root, 'config', 'user.email', 'fixture@example.invalid')
        git(root, 'add', 'ordinary')
        git(root, 'commit', '-qm', 'fixture')
    if owner_file:
        (root / 'owner').write_text('owner base\n')
        git(root, 'add', 'owner')
        git(root, 'commit', '-qm', 'owner base')
    source = tmp_path / 'offline-source'
    subprocess.run(['/usr/bin/git', 'clone', '-q', '--no-hardlinks', str(root), str(source)], check=True)
    git(source, 'config', 'user.name', 'Fixture')
    git(source, 'config', 'user.email', 'fixture@example.invalid')
    (source / 'ordinary').write_text('remote\n')
    git(source, 'add', 'ordinary')
    git(source, 'commit', '-qm', 'remote')
    remote_oid = git(source, 'rev-parse', 'HEAD')
    old = git(root, 'rev-parse', 'HEAD')
    pack = subprocess.run(['/usr/bin/git', 'pack-objects', '--stdout', '--revs'],
        cwd=source, input=(remote_oid + '\n^' + old + '\n').encode(),
        stdout=subprocess.PIPE, check=True).stdout
    if divergent:
        (root / ('ordinary' if conflict else 'local')).write_text('local\n')
        git(root, 'add', 'ordinary' if conflict else 'local')
        git(root, 'commit', '-qm', 'local')
    policy = json.loads(policy_path.read_text())
    policy['grants'][0]['operations'] = ['pull']
    policy_path.write_text(json.dumps(policy))
    state = {'oid': remote_oid, 'pack': pack, 'algorithm': algorithm, 'calls': []}
    class Broker:
        def __init__(self, *args, **kwargs):
            pass
        def discover(self, service):
            assert service == 'git-upload-pack'
            state['calls'].append('discover')
            return Advertisement({'refs/heads/reviewed': state['oid']}, frozenset(), state['algorithm'])
        def fetch_pack(self, ref, oid):
            assert ref == 'refs/heads/reviewed' and oid == state['oid']
            state['calls'].append('fetch_pack')
            return state['pack']
    monkeypatch.setattr(git_remote_policy, 'ScopedGitHTTP', Broker)
    authority = git_remote_policy.load_owner_git_remotes(policy_path.parent, original.registry, sandbox.state_dir)
    return root, ApprovedGitPulls(original.registry, sandbox, authority, manager), key, manager, state


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_real_signed_pull_publishes_one_coherent_endpoint_and_releases_admission(
        tmp_path, monkeypatch, algorithm, mode):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch, algorithm)
    before = snapshot(root)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', mode)
    parameters = request.to_payload()['parameters']
    assert parameters['mode'] == mode
    assert parameters['pack_sha256'] == hashlib.sha256(remote['pack']).hexdigest()
    assert parameters['object_format'] == algorithm
    assert count(manager) == 0
    assert snapshot(root) == before
    # Remote objects were validated in disposable private state, never canonical.
    assert subprocess.run(['/usr/bin/git', 'cat-file', '-e', remote['oid']],
        cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    receipt = issue_git_approval(key, request)
    result = service.pull('repo', 'origin', 'refs/heads/reviewed', receipt, mode)
    assert result['status'] == 'published'
    assert result['candidate_status'] == 'integrated'
    assert result['canonical_published'] is True
    assert result['guard_retained'] is False
    assert count(manager) == 0
    assert git(root, 'rev-parse', 'HEAD') == remote['oid']
    assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote['oid']
    assert (root / 'ordinary').read_text() == 'remote\n'
    assert git(root, 'status', '--porcelain') == ''
    candidate = Path(result['candidate_directory'])
    guard = json.loads((service.sandbox.state_dir / 'pull-guard-custody' / candidate.name / 'captured').read_text())
    assert guard['request_sha256'] == request.digest
    assert guard['tracking_authorization']['approval_nonce'] == guard['approval_nonce']
    assert guard['tracking_authorization']['tracking']['tracking_ref'] == 'refs/remotes/origin/reviewed'
    assert guard['tracking_authorization']['tracking']['old_oid'] == '0' * len(remote['oid'])
    assert guard['tracking_authorization']['tracking']['new_oid'] == remote['oid']
    candidate = Path(result['candidate_directory'])
    assert candidate.is_dir()
    private = candidate / 'git-0/metadata'
    assert git(root, '--git-dir=' + str(private), 'rev-parse', 'HEAD') == remote['oid']
    durable = json.loads((candidate / 'pull-private-result.json').read_text())
    assert durable['request_sha256'] == request.digest
    assert durable['canonical_published'] is False
    service.verifier.assert_consumed(guard['approval_nonce'], request)
    with pytest.raises(PermissionError, match='already consumed'):
        service.verifier.verify_and_consume(receipt, request)


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_signed_divergent_modes_run_real_integration(tmp_path, monkeypatch, mode):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch, divergent=True)
    before = snapshot(root)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', mode)
    result = service.pull('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request), mode)
    assert result['candidate_status'] == ('refused' if mode == 'ff-only' else 'integrated')
    if mode == 'ff-only':
        assert snapshot(root) == before
        assert count(manager) == 1
    else:
        assert result['canonical_published'] is True
        assert (root / 'ordinary').read_text() == 'remote\n'
        assert (root / 'local').read_text() == 'local\n'
        assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote['oid']
        assert git(root, 'status', '--porcelain') == ''
        assert count(manager) == 0


@pytest.mark.parametrize('mode', ['merge', 'rebase'])
def test_signed_conflict_has_retained_nonpublished_evidence(tmp_path, monkeypatch, mode):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch, divergent=True, conflict=True)
    before = snapshot(root)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', mode)
    result = service.pull('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request), mode)
    assert result['candidate_status'] == 'conflict'
    assert result['canonical_published'] is False
    assert snapshot(root) == before
    assert count(manager) == 1


@pytest.mark.parametrize('change', ['mode', 'worktree', 'index', 'head', 'remote', 'pack', 'format', 'policy'])
def test_signed_drift_is_rejected_before_consumption(tmp_path, monkeypatch, change):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request)
    mode = 'merge'
    if change == 'mode':
        mode = 'rebase'
    elif change == 'worktree':
        (root / 'ordinary').write_text('owner drift')
    elif change == 'index':
        git(root, 'update-index', '--assume-unchanged', 'ordinary')
    elif change == 'head':
        git(root, 'commit', '--allow-empty', '-qm', 'owner drift')
    elif change == 'remote':
        remote['oid'] = git(root, 'rev-parse', 'HEAD')
    elif change == 'pack':
        remote['pack'] = remote['pack'][:-1] + bytes([remote['pack'][-1] ^ 1])
    elif change == 'format':
        remote['algorithm'] = 'sha256'
    else:
        service.authority._digest = b'\xff' * 32
    before = snapshot(root)
    with pytest.raises((PermissionError, ValueError)):
        service.pull('repo', 'origin', 'refs/heads/reviewed', receipt, mode)
    assert snapshot(root) == before
    assert count(manager) == 0
    with pytest.raises(PermissionError, match='no matching consumed'):
        service.verifier.assert_consumed('0' * 32, request)
    # Signature mismatch did not spend its nonce: original exact request still verifies.
    service.verifier.verify_and_consume(receipt, request)


def test_invalid_receipt_releases_admission_and_private_candidate(tmp_path, monkeypatch):
    root, service, _, manager, _ = backend(tmp_path, monkeypatch)
    before = snapshot(root)
    with pytest.raises(PermissionError):
        service.pull('repo', 'origin', 'refs/heads/reviewed', '{}', 'merge')
    assert count(manager) == 0
    assert snapshot(root) == before
    assert not list((service.sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))


def test_after_consumption_failure_retains_guard_candidate_and_admission(tmp_path, monkeypatch):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'merge')
    before = snapshot(root)
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic private integration interruption')
    monkeypatch.setattr(service.engine, 'run', fail)
    with pytest.raises(ResourceCleanupError, match='reconciliation'):
        service.pull('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request), 'merge')
    assert count(manager) == 1
    assert snapshot(root) == before
    guards = list((service.sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
    assert len(guards) == 1
    guard = json.loads(guards[0].read_text())
    assert Path(guard['candidate_directory']).is_dir()
    service.verifier.assert_consumed(guard['approval_nonce'], request)


def live_job(service, workspace_id='repo', agent='codex_impl'):
    from agentporter.git_pulls import JobBoundGitPulls
    transaction = service._transaction(workspace_id)
    token = 'c' * 32
    job_id = 'job_private_pull_fixture'
    with service.manager.lock:
        service.manager._job_transactions[job_id] = transaction
    database = service.manager._get_db()
    try:
        with database:
            database.execute('INSERT INTO jobs (job_id,workspace_id,agent,argv,status,workspace_transaction) VALUES (?,?,?,?,?,?)',
                (job_id, workspace_id, agent, json.dumps(['confined-development-worker', agent]), 'running', str(transaction.directory)))
            database.execute('INSERT INTO job_admissions VALUES (?,?,?,?)', (token, job_id, os.getpid(), 0))
    finally:
        database.close()
    return JobBoundGitPulls(service, job_id, workspace_id, agent), transaction


@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_job_bound_pull_reuses_exact_existing_transaction_and_admission(tmp_path, monkeypatch, mode):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch, divergent=True)
    before = snapshot(root)
    adapter, transaction = live_job(service)
    try:
        # Existing private edits belong to this job and differ from canonical.
        (transaction.upper / 'agent-edit').write_text('private existing worker edit')
        request = adapter.prepare('origin', 'refs/heads/reviewed', mode)
        assert count(manager) == 1
        assert request.to_payload()['parameters']['job_context']['admission_token'] == adapter.token
        assert request.to_payload()['parameters']['private_state']['worktree_sha256'] != request.to_payload()['parameters']['canonical_state']['worktree_sha256']
        result = adapter.pull('origin', 'refs/heads/reviewed', issue_git_approval(key, request), mode)
        assert result['canonical_published'] is False
        assert result['candidate_status'] == ('refused' if mode == 'ff-only' else 'integrated')
        assert count(manager) == 1
        assert snapshot(root) == before
        intents = transaction._approved_pull_intents
        assert len(intents) == 1
        assert intents[0].request_sha256 == request.digest
        assert intents[0].mode == mode
        # Ordinary job success must never publish HEAD without tracking.
        from agentporter.resources import ResourceCleanupError
        with pytest.raises(ResourceCleanupError, match='Private approved pull'):
            transaction.publish()
        assert snapshot(root) == before
        assert count(manager) == 1
    finally:
        transaction.close()


def test_successful_job_finalizer_publishes_coherent_pull_before_monitor_releases_admission(tmp_path, monkeypatch):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    before = snapshot(root)
    adapter, transaction = live_job(service)
    try:
        request = adapter.prepare('origin', 'refs/heads/reviewed', 'merge')
        result = adapter.pull('origin', 'refs/heads/reviewed', issue_git_approval(key, request), 'merge')
        stderr = tmp_path / 'stderr.log'
        stderr.write_bytes(b'')
        status, exit_code, cleanup_ok = manager._finalize_workspace_edits(adapter.job_id, 'completed', 0, True, str(stderr))
        assert (status, exit_code, cleanup_ok) == ('completed', 0, True)
        assert count(manager) == 1
        assert Path(result['candidate_directory']).is_dir()
        assert not Path(result['guard']).exists()
        assert (Path(result['candidate_directory'])/'publication-receipt.json').is_file()
        assert snapshot(root) != before
        assert git(root,'status','--porcelain') == ''
    finally:
        transaction.close()


@pytest.mark.parametrize('change', ['agent', 'workspace', 'status', 'transaction', 'admission'])
def test_job_bound_pull_refuses_context_identity_drift(tmp_path, monkeypatch, change):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    adapter, transaction = live_job(service)
    try:
        request = adapter.prepare('origin', 'refs/heads/reviewed', 'merge')
        if change == 'transaction':
            with manager.lock:
                manager._job_transactions.pop(adapter.job_id)
        else:
            database = manager._get_db()
            try:
                with database:
                    if change == 'admission':
                        database.execute('UPDATE job_admissions SET token=? WHERE job_id=?', ('d' * 32, adapter.job_id))
                    elif change == 'agent':
                        database.execute('UPDATE jobs SET agent=? WHERE job_id=?', ('other', adapter.job_id))
                    elif change == 'workspace':
                        database.execute('UPDATE jobs SET workspace_id=? WHERE job_id=?', ('other', adapter.job_id))
                    else:
                        database.execute('UPDATE jobs SET status=? WHERE job_id=?', ('finalizing', adapter.job_id))
            finally:
                database.close()
        before = snapshot(root)
        with pytest.raises(PermissionError):
            adapter.pull('origin', 'refs/heads/reviewed', issue_git_approval(key, request), 'merge')
        assert not getattr(transaction, '_private_pull_pending', False)
        assert snapshot(root) == before
        assert count(manager) == 1
    finally:
        transaction.close()


def test_job_pull_execution_requires_native_publication_blocker(tmp_path, monkeypatch):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    _, service, _, _, _ = backend(tmp_path, monkeypatch)
    adapter, transaction = live_job(service)
    try:
        monkeypatch.setattr(WorkspaceTransaction, '_private_pull_guard_supported', False)
        with pytest.raises(PermissionError, match='publication blocker'):
            adapter.pull('origin', 'refs/heads/reviewed', '{}', 'merge')
    finally:
        transaction.close()


def test_owner_mutation_during_private_acquisition_refuses_before_claim(tmp_path, monkeypatch):
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request)
    original = service._import_pack
    def owner_mutation(transaction, proposal, pack):
        original(transaction, proposal, pack)
        (root / 'owner-later').write_text('preserve later owner file')
    monkeypatch.setattr(service, '_import_pack', owner_mutation)
    with pytest.raises(PermissionError, match='baseline changed|owner state changed'):
        service.pull('repo', 'origin', 'refs/heads/reviewed', receipt, 'merge')
    assert (root / 'owner-later').read_text() == 'preserve later owner file'
    assert count(manager) == 0
    service.verifier.verify_and_consume(receipt, request)


def test_first_guard_failure_retains_durable_consumed_request_and_capacity(tmp_path, monkeypatch):
    from agentporter import git_pulls
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request)
    before = snapshot(root)
    def fail(*args, **kwargs):
        raise OSError('synthetic guard filesystem interruption')
    monkeypatch.setattr(git_pulls, '_write_fetch_guard', fail)
    with pytest.raises(ResourceCleanupError, match='reconciliation'):
        service.pull('repo', 'origin', 'refs/heads/reviewed', receipt, 'merge')
    assert count(manager) == 1
    assert snapshot(root) == before
    retained = list((service.sandbox.state_dir / 'workspace-transactions').glob('*/pull-approved-request.json'))
    assert len(retained) == 1
    saved = json.loads(retained[0].read_text())
    assert saved['request_sha256'] == request.digest
    assert saved['approval_receipt'] == receipt
    with pytest.raises(PermissionError, match='already consumed'):
        service.verifier.verify_and_consume(receipt, request)


def spent_authorization(service, key, *, historical=False):
    from agentporter.git_pulls import _consumed_tracking
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request, **({'now': 1, 'lifetime_seconds': 10} if historical else {}))
    approval = service.verifier.verify_and_consume(receipt, request, **({'now': 2} if historical else {}))
    authorization = _consumed_tracking(request, approval, service.verifier, service.authority, receipt)
    return request, authorization


def test_offline_authorization_validation_proves_only_exact_tracking_ref_and_log(tmp_path, monkeypatch):
    from agentporter.git_pulls import validate_pull_authorization
    root, service, key, _, _ = backend(tmp_path, monkeypatch)
    _, authorization = spent_authorization(service, key)
    document = authorization.to_payload()
    before = snapshot(root)
    ledger_before = service.verifier.ledger_path.read_bytes()
    assert validate_pull_authorization(document, registry=service.registry,
        state_dir=service.sandbox.state_dir, owner_config_dir=service.authority._config_dir) == (
            'refs/remotes/origin/reviewed', 'logs/refs/remotes/origin/reviewed')
    assert service.verifier.ledger_path.read_bytes() == ledger_before
    assert snapshot(root) == before


def test_offline_recovery_accepts_expired_but_actually_spent_approval(tmp_path, monkeypatch):
    from agentporter.git_pulls import validate_pull_authorization
    _, service, key, _, _ = backend(tmp_path, monkeypatch)
    _, authorization = spent_authorization(service, key, historical=True)
    assert validate_pull_authorization(authorization.to_payload(), registry=service.registry,
        state_dir=service.sandbox.state_dir, owner_config_dir=service.authority._config_dir)[0] == 'refs/remotes/origin/reviewed'


@pytest.mark.parametrize('change', ['request', 'nonce', 'signature', 'ledger', 'key', 'tracking', 'metadata', 'policy'])
def test_offline_authorization_refuses_tampered_guard_scope(tmp_path, monkeypatch, change):
    from agentporter.git_pulls import validate_pull_authorization
    _, service, key, _, _ = backend(tmp_path, monkeypatch)
    _, authorization = spent_authorization(service, key)
    document = authorization.to_payload()
    if change == 'request':
        document['request']['parameters']['mode'] = 'rebase'
    elif change == 'nonce':
        document['approval_nonce'] = '0' * 32
    elif change == 'signature':
        envelope = json.loads(document['approval_receipt'])
        envelope['signature'] = 'A' * 86
        document['approval_receipt'] = json.dumps(envelope)
    elif change == 'ledger':
        document['verification_context']['ledger_path'] = str(tmp_path / 'forged-ledger.db')
    elif change == 'key':
        document['verification_context']['verification_key'] = '0' * 64
    elif change == 'tracking':
        document['tracking']['tracking_ref'] = 'refs/remotes/other/reviewed'
    elif change == 'metadata':
        document['tracking']['metadata_inode'] += 1
    else:
        document['verification_context']['policy_sha256'] = '0' * 64
    with pytest.raises(PermissionError):
        validate_pull_authorization(document, registry=service.registry,
            state_dir=service.sandbox.state_dir, owner_config_dir=service.authority._config_dir)


def test_offline_authorization_requires_callers_trusted_policy_root(tmp_path, monkeypatch):
    from agentporter.git_pulls import validate_pull_authorization
    _, service, key, _, _ = backend(tmp_path, monkeypatch)
    _, authorization = spent_authorization(service, key)
    other = tmp_path / 'other-owner'
    other.mkdir(mode=0o700)
    with pytest.raises(PermissionError):
        validate_pull_authorization(authorization.to_payload(), registry=service.registry,
            state_dir=service.sandbox.state_dir, owner_config_dir=other)


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_explicit_coherent_job_candidate_publication_updates_files_head_index_and_exact_tracking(
        tmp_path, monkeypatch, algorithm, mode):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch, algorithm)
    adapter, transaction = live_job(service)
    try:
        request = adapter.prepare('origin', 'refs/heads/reviewed', mode)
        adapter.pull('origin', 'refs/heads/reviewed', issue_git_approval(key, request), mode)
        transaction.publish_approved_pull()
        assert transaction._applied
        assert not transaction._private_pull_pending
        assert git(root, 'rev-parse', 'HEAD') == remote['oid']
        assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote['oid']
        assert (root / 'ordinary').read_text() == 'remote\n'
        assert git(root, 'status', '--porcelain') == ''
        receipt = json.loads((transaction.directory / 'publication-receipt.json').read_text())
        assert receipt['approved_pull']['authorization']['request_sha256'] == request.digest
        assert receipt['endpoint'] == 'after'
        database = manager._get_db()
        try:
            binding = database.execute('SELECT status FROM git_admissions WHERE token=?', (adapter.token,)).fetchone()
            assert binding['status'] == 'resolved'
        finally:
            database.close()
        # The running async job's original admission remains for its monitor.
        assert count(manager) == 1
        assert (service.sandbox.state_dir / 'pull-guard-custody' / transaction.directory.name / 'captured').is_file()
        assert not list((service.sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
        assert not list((service.sandbox.state_dir / 'workspace-transactions').glob('*.pending.json'))
    finally:
        transaction.close()


def test_lifecycle_lock_finalizer_wins_before_pull_claim(tmp_path, monkeypatch):
    import threading
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    adapter, transaction = live_job(service)
    request = adapter.prepare('origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request)
    cached = threading.Event(); release_cached = threading.Event()
    publishing = threading.Event(); release_publication = threading.Event()
    pull_finished = threading.Event()
    errors = []; finalized = []
    original_context = adapter._context
    first = [True]
    def cached_context():
        result = original_context()
        if threading.current_thread().name == 'pull-after-publisher' and first[0]:
            first[0] = False
            cached.set()
            assert release_cached.wait(5)
        return result
    original_prepare = transaction.git_histories['.git'].prepare
    def paused_prepare():
        publishing.set()
        assert release_publication.wait(5)
        return original_prepare()
    monkeypatch.setattr(adapter, '_context', cached_context)
    monkeypatch.setattr(transaction.git_histories['.git'], 'prepare', paused_prepare)
    def pull():
        try:
            adapter.pull('origin', 'refs/heads/reviewed', receipt, 'merge')
        except BaseException as error:
            errors.append(error)
        finally:
            pull_finished.set()
    stderr = tmp_path / 'finalizer-stderr'
    stderr.write_bytes(b'')
    def finalize():
        finalized.append(manager._finalize_workspace_edits(adapter.job_id, 'completed', 0, True, str(stderr)))
    pull_thread = threading.Thread(target=pull, name='pull-after-publisher')
    finalizer = threading.Thread(target=finalize)
    try:
        pull_thread.start()
        assert cached.wait(5)
        finalizer.start()
        assert publishing.wait(5)
        release_cached.set()
        assert not pull_finished.wait(0.05)
        release_publication.set()
        finalizer.join(5); pull_thread.join(5)
        assert not finalizer.is_alive() and not pull_thread.is_alive()
        assert finalized == [('completed', 0, True)]
        assert len(errors) == 1 and isinstance(errors[0], PermissionError)
        assert transaction._closed
        # Claim still succeeds once: blocked pull never spent owner approval.
        service.verifier.verify_and_consume(receipt, request)
    finally:
        release_cached.set(); release_publication.set()
        pull_thread.join(5)
        if finalizer.ident is not None:
            finalizer.join(5)
        transaction.close()


def test_lifecycle_lock_pull_claim_wins_and_finalizer_waits_for_retained_result(tmp_path, monkeypatch):
    import threading
    root, service, key, manager, _ = backend(tmp_path, monkeypatch)
    adapter, transaction = live_job(service)
    request = adapter.prepare('origin', 'refs/heads/reviewed', 'merge')
    receipt = issue_git_approval(key, request)
    integrating = threading.Event(); release_integration = threading.Event(); finalized = threading.Event()
    results = []; errors = []; terminal = []
    original = service.engine.run
    def paused_integration(*args, **kwargs):
        integrating.set()
        assert release_integration.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(service.engine, 'run', paused_integration)
    def pull():
        try:
            results.append(adapter.pull('origin', 'refs/heads/reviewed', receipt, 'merge'))
        except BaseException as error:
            errors.append(error)
    stderr = tmp_path / 'finalizer-stderr'
    stderr.write_bytes(b'')
    def finalize():
        terminal.append(manager._finalize_workspace_edits(adapter.job_id, 'completed', 0, True, str(stderr)))
        finalized.set()
    pull_thread = threading.Thread(target=pull)
    finalizer = threading.Thread(target=finalize)
    before = snapshot(root)
    try:
        pull_thread.start()
        assert integrating.wait(5)
        finalizer.start()
        assert not finalized.wait(0.05)
        release_integration.set()
        pull_thread.join(5); finalizer.join(5)
        assert not finalizer.is_alive() and not pull_thread.is_alive()
        assert terminal == [('cleanup_failed', 1, False)]
        assert count(manager) == 1
        assert transaction._private_pull_pending
        assert snapshot(root) == before
        assert list((service.sandbox.state_dir / 'workspace-transactions').glob('*.git-pending.json'))
        assert errors and isinstance(errors[0], ResourceCleanupError)
        with pytest.raises(PermissionError, match='already consumed'):
            service.verifier.verify_and_consume(receipt, request)
    finally:
        release_integration.set()
        pull_thread.join(5)
        if finalizer.ident is not None:
            finalizer.join(5)
        transaction.close()


@pytest.mark.parametrize('mode', ['ff-only', 'merge'])
@pytest.mark.parametrize('dirty', ['staged', 'unstaged', 'both', 'untracked'])
def test_coherent_publication_preserves_unrelated_owner_worktree_and_staging(tmp_path, monkeypatch, mode, dirty):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch, owner_file=True)
    if dirty in ('staged', 'both'):
        (root / 'owner').write_text('staged owner\n')
        git(root, 'add', 'owner')
    if dirty in ('unstaged', 'both'):
        (root / 'owner').write_text('unstaged owner\n')
    if dirty == 'untracked':
        (root / 'untracked').write_text('untracked owner\n')
    expected_owner = (root / 'owner').read_bytes()
    expected_index_owner = git(root, 'show', ':owner')
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', mode)
    result = service.pull('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request), mode)
    assert result['status'] == 'published'
    assert result['canonical_published'] is True
    assert git(root, 'rev-parse', 'HEAD') == remote['oid']
    assert git(root, 'rev-parse', 'refs/remotes/origin/reviewed') == remote['oid']
    assert (root / 'owner').read_bytes() == expected_owner
    assert git(root, 'show', ':owner') == expected_index_owner
    if dirty == 'untracked':
        assert (root / 'untracked').read_text() == 'untracked owner\n'
    assert count(manager) == 0


def test_coherent_publication_integrates_rename_delete_and_new_directory_tree(tmp_path, monkeypatch):
    root, service, key, manager, remote = backend(tmp_path, monkeypatch)
    source = tmp_path / 'offline-source'
    git(source, 'rm', '-q', 'ordinary')
    (source / 'nested').mkdir()
    (source / 'nested/renamed').write_text('remote\n')
    (source / 'nested/created').write_text('new remote nested content\n')
    git(source, 'add', 'nested')
    git(source, 'commit', '-qm', 'remote rename delete directory')
    remote['oid'] = git(source, 'rev-parse', 'HEAD')
    old = git(root, 'rev-parse', 'HEAD')
    remote['pack'] = subprocess.run(['/usr/bin/git', 'pack-objects', '--stdout', '--revs'], cwd=source,
        input=(remote['oid'] + '\n^' + old + '\n').encode(), stdout=subprocess.PIPE, check=True).stdout
    request = service.prepare('repo', 'origin', 'refs/heads/reviewed', 'ff-only')
    result = service.pull('repo', 'origin', 'refs/heads/reviewed', issue_git_approval(key, request), 'ff-only')
    assert result['status'] == 'published'
    assert not (root / 'ordinary').exists()
    assert (root / 'nested/renamed').read_text() == 'remote\n'
    assert (root / 'nested/created').read_text() == 'new remote nested content\n'
    assert git(root, 'status', '--porcelain') == ''
    assert git(root, 'rev-parse', 'HEAD') == remote['oid']
    assert count(manager) == 0
