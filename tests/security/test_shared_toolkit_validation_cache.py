"""Immutable-release cache contracts using only synthetic public resources."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from agentporter.agents.development import DevelopmentRuntime


@pytest.fixture
def toolkit(tmp_path, monkeypatch):
    prefix = tmp_path / 'versions'
    release = prefix / '20261020T223443.649130Z'
    root = release / 'shared/toolkit'
    package = root / 'packages/npm'
    package.mkdir(parents=True)
    (root / 'bin').mkdir()
    executable = root / 'bin/fixture-tool'
    executable.write_bytes(b'\x7fELFsynthetic public executable')
    executable.chmod(0o555)
    wrapper = root / 'bin/npm'
    wrapper.write_bytes(b'#!/bin/sh\nexit 0\n')
    wrapper.chmod(0o555)
    payload = package / 'payload'
    payload.write_bytes(b'synthetic public package data')
    payload.chmod(0o444)
    (package / 'alias').symlink_to('payload')
    manifest = root / 'manifest.json'
    document = {'bundled_elf': {'fixture-tool': hashlib.sha256(executable.read_bytes()).hexdigest()},
                'bundled_scripts': {'npm': hashlib.sha256(wrapper.read_bytes()).hexdigest()},
                'package_admissions': {'npm': {'files': {
                    'payload': {'sha256': hashlib.sha256(payload.read_bytes()).hexdigest(), 'executable': False},
                    'alias': {'link': 'payload'},
                }}}}
    manifest.write_text(json.dumps(document))
    manifest.chmod(0o444)
    for location, _, _ in os.walk(release):
        Path(location).chmod(0o555)
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    configuration = {'shared_toolkit': str(root), 'profile': 'development'}
    config_file = config_dir / 'development-runtime.yaml'
    config_file.write_text(json.dumps(configuration))
    runtime = DevelopmentRuntime(config_dir, tmp_path / 'state', None)
    monkeypatch.setattr(runtime, '_RELEASES', prefix)
    original_lstat, original_fstat = Path.lstat, os.fstat
    wrong_owners = set()

    def metadata(info, path):
        values = {name: getattr(info, name) for name in (
            'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        values['st_uid'] = 1000 if path in wrong_owners else 0
        if not path.is_relative_to(prefix) or path == prefix:
            # Model the immutable deployment's root-owned ancestors, not the
            # host test directory's public /tmp ownership/mode.
            values['st_mode'] &= ~0o022
            # Concurrent host jobs legitimately change /tmp directory metadata.
            # These synthetic ancestors model stable immutable deployment roots.
            if stat.S_ISDIR(info.st_mode):
                for name in ('st_size', 'st_mtime_ns', 'st_ctime_ns'):
                    values[name] = 0
        return SimpleNamespace(**values)

    def root_lstat(path, *args, **kwargs):
        return metadata(original_lstat(path, *args, **kwargs), path)

    def root_fstat(fd):
        return metadata(original_fstat(fd), Path(os.readlink(f'/proc/self/fd/{fd}')))

    # Ownership alone is simulated. Contents, inode/timestamps, chmod changes,
    # symlinks, descriptor reads, hashes and thread coordination remain real.
    monkeypatch.setattr(Path, 'lstat', root_lstat)
    monkeypatch.setattr(os, 'fstat', root_fstat)
    validation = Mock(wraps=runtime._validate_toolkit_contents)
    monkeypatch.setattr(runtime, '_validate_toolkit_contents', validation)
    result = SimpleNamespace(runtime=runtime, config=configuration, config_file=config_file,
                             release=release, root=root, manifest=manifest, document=document,
                             package=package, payload=payload, validation=validation, wrong_owners=wrong_owners)
    try:
        yield result
    finally:
        for location, _, _ in os.walk(tmp_path):
            Path(location).chmod(0o700)


def test_full_validation_runs_once_across_agents_and_probe_cache_expiry(toolkit, monkeypatch):
    calls = Mock(wraps=hashlib.file_digest)
    monkeypatch.setattr(hashlib, 'file_digest', calls)
    for agent in ('jax', 'liz', 'prof', 'ming', 'wei', 'phil', 'argie'):
        toolkit.runtime._cache[agent] = (0, 'expired confinement probe signature')
        assert toolkit.runtime._shared_toolkit_source(toolkit.config) == toolkit.root
    assert toolkit.validation.call_count == 1
    assert calls.call_count == 1  # the package file is fully hashed initially


def test_concurrent_first_use_validates_once(toolkit):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: toolkit.runtime._shared_toolkit_source(toolkit.config), range(8)))
    assert results == [toolkit.root] * 8
    assert toolkit.validation.call_count == 1


@pytest.mark.parametrize('change', ['root', 'package', 'manifest', 'executable', 'payload'])
def test_owner_writable_resources_are_never_cached(toolkit, change):
    target = {'root': toolkit.root, 'package': toolkit.package, 'manifest': toolkit.manifest,
              'executable': toolkit.root / 'bin/fixture-tool', 'payload': toolkit.payload}[change]
    target.chmod(stat.S_IMODE(target.stat().st_mode) | 0o200)
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.validation.call_count == 2
    assert toolkit.runtime._toolkit_cache is None


@pytest.mark.parametrize('change', ['config_content', 'allowlist_revision', 'config_revision', 'manifest_revision', 'release_version'])
def test_revision_changes_force_full_validation(toolkit, change):
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    if change == 'config_content':
        toolkit.config['parallel_search_enabled'] = True
    elif change == 'allowlist_revision':
        toolkit.config['allowed_workspace_roots'] = [{'path': str(toolkit.release), 'writable': False}]
    elif change == 'config_revision':
        toolkit.config_file.write_text(toolkit.config_file.read_text() + '\n')
    elif change == 'manifest_revision':
        toolkit.manifest.chmod(0o644)
        toolkit.manifest.write_text(json.dumps(toolkit.document, indent=2))
        toolkit.manifest.chmod(0o444)
    else:
        new_release = toolkit.release.with_name('20261020T223444.649131Z')
        shutil.copytree(toolkit.release, new_release, symlinks=True)
        toolkit.config['shared_toolkit'] = str(new_release / 'shared/toolkit')
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.validation.call_count == 2


@pytest.mark.parametrize('change', ['manifest_digest', 'mutable_top', 'wrong_owner', 'manifest_symlink'])
def test_warm_cache_does_not_hide_changed_manifest_or_trust_boundary(toolkit, change):
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    if change == 'manifest_digest':
        toolkit.manifest.chmod(0o644)
        document = json.loads(toolkit.manifest.read_text())
        document['package_admissions']['npm']['files']['payload']['sha256'] = '0' * 64
        toolkit.manifest.write_text(json.dumps(document))
        toolkit.manifest.chmod(0o444)
    elif change == 'mutable_top':
        (toolkit.root / 'packages').chmod(0o777)
    elif change == 'wrong_owner':
        toolkit.wrong_owners.add(toolkit.root)
    else:
        toolkit.root.chmod(0o755)
        toolkit.manifest.rename(toolkit.root / 'saved-manifest.json')
        toolkit.manifest.symlink_to('saved-manifest.json')
        toolkit.root.chmod(0o555)
    with pytest.raises((PermissionError, OSError)):
        toolkit.runtime._shared_toolkit_source(toolkit.config)


def test_first_digest_failure_does_not_populate_cache(toolkit):
    toolkit.payload.chmod(0o644)
    toolkit.payload.write_bytes(b'unreviewed replacement')
    toolkit.payload.chmod(0o444)
    with pytest.raises(PermissionError, match='digest mismatch'):
        toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.runtime._toolkit_cache is None


def test_unversioned_release_fully_revalidates(toolkit):
    renamed = toolkit.release.with_name('mutable-development')
    toolkit.release.rename(renamed)
    toolkit.config['shared_toolkit'] = str(renamed / 'shared/toolkit')
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    toolkit.runtime._shared_toolkit_source(toolkit.config)
    assert toolkit.validation.call_count == 2
