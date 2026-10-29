"""Approval requests must come from locked, read-only repository inspection."""
import hashlib
import subprocess

import pytest

from agentporter.git_approval_state import approved_git_request, locked_git_request
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.workspaces.leases import mutation_lease
from agentporter.workspaces.registry import WorkspaceRegistry
from tests._support import BWRAP_USABLE

pytestmark = pytest.mark.skipif(not BWRAP_USABLE, reason='Native sandbox unavailable')


def git(root, *arguments):
    return subprocess.check_output(['git', *arguments], cwd=root).decode().strip()


def setup(tmp_path, *, committed=True):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-q', '-b', 'reviewed')
    git(root, 'config', 'user.name', 'Fixture')
    git(root, 'config', 'user.email', 'fixture@example.invalid')
    (root / 'ordinary').write_text('initial')
    git(root, 'add', 'ordinary')
    if committed:
        git(root, 'commit', '-qm', 'fixture')
    registry = WorkspaceRegistry({'repo': {'path': str(root), 'writable': True}})
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    return root, registry, sandbox


def metadata(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (root / '.git').rglob('*') if p.is_file()}


def test_request_binds_actual_staged_tree_without_changing_metadata(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    (root / 'ordinary').write_text('staged')
    git(root, 'add', 'ordinary')
    before = metadata(root)
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'reviewed'}) as request:
        payload = request.to_payload()
        assert payload['expected_head'] == git(root, 'rev-parse', 'HEAD')
        assert payload['branch'] == 'refs/heads/reviewed'
        assert payload['repository_inode'] == root.stat().st_ino
        assert payload['repository_device'] == root.stat().st_dev
        assert payload['repository_path'] == str(root)
        with pytest.raises(PermissionError, match='active mutation'):
            with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
                pytest.fail('Request inspection lost its workspace lock')
    assert metadata(root) == before
    assert payload['expected_tree'] == git(root, 'write-tree')


def test_unborn_repository_has_no_head_but_binds_index(tmp_path):
    root, registry, sandbox = setup(tmp_path, committed=False)
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'initial'}) as request:
        payload = request.to_payload()
    assert payload['expected_head'] is None
    assert payload['expected_tree'] == git(root, 'write-tree')


def test_changed_index_changes_request_digest(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'same'}) as first:
        pass
    (root / 'ordinary').write_text('changed')
    git(root, 'add', 'ordinary')
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'same'}) as second:
        pass
    assert first.digest != second.digest


def test_repository_helper_cannot_run_during_state_capture(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    git(root, 'config', 'core.fsmonitor', '/bin/sh -c "echo helper-ran >&2; exit 99"')
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'reviewed'}) as request:
        assert request.to_payload()['expected_head'] == git(root, 'rev-parse', 'HEAD')


def test_readonly_workspace_cannot_request_publication(tmp_path):
    root, _, sandbox = setup(tmp_path)
    registry = WorkspaceRegistry({'repo': {'path': str(root), 'writable': False}})
    with pytest.raises(PermissionError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('Read-only workspace authorized mutation')


def test_external_git_directory_is_refused(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    (root / '.git').rename(tmp_path / 'outside.git')
    (root / '.git').symlink_to(tmp_path / 'outside.git', target_is_directory=True)
    with pytest.raises(PermissionError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('External Git metadata accepted')


def test_transaction_enabled_inspection_preserves_resource_cleanup(tmp_path):
    from tests.security.test_workspace_transactions import RecordingResources
    root, registry, initial = setup(tmp_path)
    sandbox = BubblewrapSandbox(initial.state_dir, transactional_writes=True)
    sandbox.resources = RecordingResources()
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'reviewed'}) as request:
        assert request.to_payload()['expected_head'] == git(root, 'rev-parse', 'HEAD')
        assert sandbox.resources.lease.closed


def test_pending_publication_blocks_approval_inspection(tmp_path):
    from agentporter.resources import ResourceCleanupError
    from agentporter.workspaces.leases import workspace_key
    root, registry, sandbox = setup(tmp_path)
    state = sandbox.state_dir / 'workspace-transactions'
    state.mkdir(mode=0o700)
    (state / (workspace_key(root.stat()) + '.pending.json')).write_text('{}')
    with pytest.raises(ResourceCleanupError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('Pending publication did not block approval request')


def test_initial_empty_repository_without_index(tmp_path):
    root, registry, sandbox = setup(tmp_path, committed=False)
    (root / '.git/index').unlink()
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'empty'}) as request:
        state = request.to_payload()
    assert state['expected_head'] is None
    assert state['expected_tree'] == git(root, 'write-tree')


def test_split_index_is_inspected_without_changing_it(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    git(root, 'update-index', '--split-index')
    before = metadata(root)
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'split'}) as request:
        tree = request.to_payload()['expected_tree']
    assert metadata(root) == before
    assert tree == git(root, 'write-tree')


def test_sha256_repository_is_supported(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    import shutil
    shutil.rmtree(root / '.git')
    git(root, 'init', '-q', '-b', 'reviewed', '--object-format=sha256')
    git(root, 'add', 'ordinary')
    with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'sha256'}) as request:
        state = request.to_payload()
    assert len(state['expected_tree']) == 64
    assert state['expected_tree'] == git(root, 'write-tree')


@pytest.mark.parametrize('kind', ['symlink-index', 'corrupt-index', 'corrupt-head'])
def test_untrusted_metadata_fails_closed(tmp_path, kind):
    root, registry, sandbox = setup(tmp_path)
    before = git(root, 'rev-parse', 'HEAD')
    if kind == 'symlink-index':
        (root / '.git/index').rename(tmp_path / 'index')
        (root / '.git/index').symlink_to(tmp_path / 'index')
    elif kind == 'corrupt-index':
        (root / '.git/index').write_bytes(b'invalid index')
    else:
        (root / '.git/HEAD').write_text('invalid HEAD\n')
    with pytest.raises(PermissionError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('Invalid repository state was approved')
    assert (root / '.git/refs/heads/reviewed').read_text().strip() == before


def test_changed_repository_root_is_rejected(tmp_path, monkeypatch):
    root, registry, sandbox = setup(tmp_path)
    run = sandbox._run_command
    def replace_root(**options):
        result = run(**options)
        root.rename(root.with_name('original'))
        root.mkdir()
        return result
    monkeypatch.setattr(sandbox, '_run_command', replace_root)
    with pytest.raises(PermissionError, match='identity changed'):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('Replaced repository was approved')


def test_deleted_repository_root_is_rejected(tmp_path, monkeypatch):
    root, registry, sandbox = setup(tmp_path)
    run = sandbox._run_command
    def remove_root_name(**options):
        result = run(**options)
        root.rename(root.with_name('original'))
        return result
    monkeypatch.setattr(sandbox, '_run_command', remove_root_name)
    with pytest.raises(PermissionError, match='identity changed'):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'denied'}):
            pytest.fail('Missing repository was approved')


def approval_setup(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agentporter.git_approvals import GitApprovalVerifier, issue_git_approval
    root, registry, sandbox = setup(tmp_path)
    key = Ed25519PrivateKey.generate()
    verifier = GitApprovalVerifier(key.public_key(), tmp_path / 'owner/claims.db')
    parameters = {'message': 'reviewed'}
    with locked_git_request(registry, sandbox, 'repo', 'commit', parameters) as request:
        receipt = issue_git_approval(key, request)
    return root, registry, sandbox, verifier, parameters, receipt


def test_signed_request_is_consumed_under_the_workspace_lock(tmp_path):
    root, registry, sandbox, verifier, parameters, receipt = approval_setup(tmp_path)
    with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
        with pytest.raises(PermissionError, match='active mutation'):
            with mutation_lease(root, sandbox.state_dir / 'workspace-transactions'):
                pytest.fail('Authorization released the repository lock')
    with pytest.raises(PermissionError, match='already consumed'):
        with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
            pytest.fail('Consumed approval was replayed')


def test_stale_staged_tree_cannot_consume_signed_request(tmp_path):
    root, registry, sandbox, verifier, parameters, receipt = approval_setup(tmp_path)
    (root / 'ordinary').write_text('unreviewed')
    git(root, 'add', 'ordinary')
    with pytest.raises(PermissionError, match='receipt rejected'):
        with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
            pytest.fail('Stale staged-tree approval accepted')
    git(root, 'reset', '--quiet', 'HEAD', '--', 'ordinary')
    with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
        pass


def test_failure_after_claim_does_not_restore_approval(tmp_path):
    _, registry, sandbox, verifier, parameters, receipt = approval_setup(tmp_path)
    with pytest.raises(RuntimeError, match='operation failed'):
        with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
            raise RuntimeError('operation failed')
    with pytest.raises(PermissionError, match='already consumed'):
        with approved_git_request(registry, sandbox, verifier, 'repo', 'commit', parameters, receipt):
            pytest.fail('Failed operation restored consumed approval')


def test_index_with_missing_blob_cannot_be_approved(tmp_path):
    root, registry, sandbox = setup(tmp_path)
    git(root, 'update-index', '--cacheinfo', '100644,' + '1' * 40 + ',ordinary')
    with pytest.raises(PermissionError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'broken'}):
            pytest.fail('Approval bound a tree containing a missing object')


@pytest.mark.parametrize('kind', ['missing', 'blob'])
def test_head_must_identify_an_existing_commit(tmp_path, kind):
    root, registry, sandbox = setup(tmp_path)
    head = '1' * 40 if kind == 'missing' else git(root, 'hash-object', 'ordinary')
    (root / '.git/refs/heads/reviewed').write_text(head + '\n')
    with pytest.raises(PermissionError):
        with locked_git_request(registry, sandbox, 'repo', 'commit', {'message': 'broken'}):
            pytest.fail('Approval accepted a missing or non-commit HEAD')
