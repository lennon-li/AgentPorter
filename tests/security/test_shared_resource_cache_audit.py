"""Independent adversarial cache audit; only inert synthetic public resources."""
import json
from unittest.mock import Mock

import pytest

from agentporter.agents.development import DevelopmentRuntime
from agentporter.workspaces.registry import WorkspaceRegistry
from test_shared_toolkit_validation_cache import toolkit  # noqa: F401


def rewrite_manifest(fixture):
    fixture.manifest.chmod(0o644)
    fixture.manifest.write_text(json.dumps(fixture.document))
    fixture.manifest.chmod(0o444)


def test_audit_nonroot_package_owner_cannot_seed_success(toolkit):
    toolkit.wrong_owners.add(toolkit.payload)
    with pytest.raises(PermissionError):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.runtime._toolkit_cache is None


def test_audit_matching_manifest_cannot_admit_package_symlink_escape(toolkit, tmp_path):
    external = tmp_path / 'outside-package'
    external.write_bytes(b'inert external resource')
    alias = toolkit.package / 'alias'
    toolkit.package.chmod(0o755)
    alias.unlink()
    alias.symlink_to(external)
    toolkit.package.chmod(0o555)
    toolkit.document['package_admissions']['npm']['files']['alias'] = {'link': str(external)}
    rewrite_manifest(toolkit)
    with pytest.raises(PermissionError, match='symlink'):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.runtime._toolkit_cache is None


def test_audit_special_package_file_rejected_without_opening_fifo(toolkit):
    import os

    toolkit.package.chmod(0o755)
    fifo = toolkit.package / 'fifo'
    os.mkfifo(fifo, 0o444)
    toolkit.package.chmod(0o555)
    toolkit.document['package_admissions']['npm']['files']['fifo'] = {'sha256': '0' * 64, 'executable': False}
    rewrite_manifest(toolkit)
    with pytest.raises(PermissionError, match='Special'):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.runtime._toolkit_cache is None


def test_audit_manifest_change_after_full_scan_never_publishes_cache(toolkit, monkeypatch):
    original = toolkit.runtime._validate_toolkit_contents

    def change_after_validation(path, document):
        result = original(path, document)
        toolkit.manifest.chmod(0o644)
        toolkit.manifest.write_text(toolkit.manifest.read_text() + '\n')
        toolkit.manifest.chmod(0o444)
        return result

    monkeypatch.setattr(toolkit.runtime, '_validate_toolkit_contents', change_after_validation)
    with pytest.raises(PermissionError, match='changed during validation'):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.runtime._toolkit_cache is None


def test_audit_manifest_digest_invalidates_even_if_metadata_identity_is_frozen(toolkit, monkeypatch):
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    original_identity = toolkit.runtime._resource_identity
    before = toolkit.manifest.lstat()
    old_identity = original_identity(before)

    def frozen_manifest_identity(info):
        if (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino):
            return old_identity
        return original_identity(info)

    monkeypatch.setattr(toolkit.runtime, '_resource_identity', frozen_manifest_identity)
    toolkit.document['package_admissions']['npm']['files']['payload']['sha256'] = '0' * 64
    rewrite_manifest(toolkit)
    with pytest.raises(PermissionError, match='digest mismatch'):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.validation.call_count == 2
    assert toolkit.runtime._toolkit_cache is None


def test_audit_success_cache_is_not_shared_with_another_runtime(toolkit, tmp_path, monkeypatch):
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    other = DevelopmentRuntime(toolkit.config_file.parent, tmp_path / 'other-state', None)
    monkeypatch.setattr(other, '_RELEASES', toolkit.runtime._RELEASES)
    validator = Mock(wraps=other._validate_toolkit_contents)
    monkeypatch.setattr(other, '_validate_toolkit_contents', validator)
    other._shared_toolkit_source(toolkit.config)
    assert validator.call_count == 1


def test_audit_unvalidated_mutable_top_level_node_cannot_be_cached(toolkit):
    toolkit.root.chmod(0o755)
    extra = toolkit.root / 'unadmitted-mutable-node'
    extra.write_bytes(b'inert unadmitted resource')
    extra.chmod(0o644)
    toolkit.root.chmod(0o555)
    try:
        toolkit.runtime._shared_toolkit_source(toolkit.config)
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    except PermissionError:
        pass
    assert toolkit.runtime._toolkit_cache is None


def test_audit_discovered_leaf_cannot_expand_explicit_operator_scope(tmp_path):
    umbrella = tmp_path / 'repositories'
    approved, unexpected = umbrella / 'approved', umbrella / 'unapproved-project'
    approved.mkdir(parents=True)
    unexpected.mkdir()
    registry = WorkspaceRegistry({'umbrella': {
        'path': str(umbrella), 'writable': True, 'allow_execute': True,
        'allow_agent_dispatch': True, 'auto_discover': True,
    }})
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'state', registry)
    config = {'workers': {}, 'allowed_workspace_roots': [{'path': str(approved), 'writable': True}]}
    assert registry.get('unapproved-project').allow_agent_dispatch
    with pytest.raises(PermissionError, match='operator development allowlist'):
        runtime._workspace(str(unexpected), True, config)
    assert runtime._workspace(str(approved), True, config) == approved


@pytest.mark.parametrize('operator_writable,registry_writable', [(False, True), (True, False)])
def test_audit_write_scope_is_intersection_of_both_authorities(tmp_path, operator_writable, registry_writable):
    workspace = tmp_path / 'approved'
    workspace.mkdir()
    registry = WorkspaceRegistry({'approved': {
        'path': str(workspace), 'writable': registry_writable,
        'allow_execute': True, 'allow_agent_dispatch': True,
    }})
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'state', registry)
    config = {'workers': {}, 'allowed_workspace_roots': [{'path': str(workspace), 'writable': operator_writable}]}
    assert runtime._workspace(str(workspace), False, config) == workspace
    with pytest.raises(PermissionError, match='read-only'):
        runtime._workspace(str(workspace), True, config)


def test_audit_allowlist_cannot_bypass_registry_execute_denial(tmp_path):
    workspace = tmp_path / 'approved'
    workspace.mkdir()
    registry = WorkspaceRegistry({'approved': {
        'path': str(workspace), 'writable': True,
        'allow_execute': False, 'allow_agent_dispatch': True,
    }})
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'state', registry)
    config = {'workers': {}, 'allowed_workspace_roots': [{'path': str(workspace), 'writable': True}]}
    with pytest.raises(PermissionError, match='not authorized'):
        runtime._workspace(str(workspace), False, config)


def test_audit_workspace_authority_revision_invalidates_toolkit_success(toolkit, tmp_path):
    toolkit.config['allowed_workspace_roots'] = [{'path': str(tmp_path), 'writable': True}]
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    toolkit.config['allowed_workspace_roots'][0]['writable'] = False
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.validation.call_count == 2
