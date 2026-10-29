"""Owner-only CRAN opt-in: exact semantic delta, backups and guarded rollback."""
import importlib.util
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


def load(name, filename):
    path = Path(__file__).parents[2] / 'scripts' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


@pytest.fixture
def operator():
    return load('cran_policy_operator', 'enable-a7dev-all-cran-paths.py')


@pytest.fixture
def setup(operator, tmp_path):
    storage = load('cran_policy_storage', 'authorize-a7dev-project-delegation.py')
    calls = []
    storage.quiet_and_stopped = lambda: calls.append('quiet')
    config = tmp_path / 'config'; config.mkdir(mode=0o700)
    state = tmp_path / 'state'; state.mkdir(mode=0o700)
    source = Path('docs/examples/a7dev-cranary-acquisition-https.yaml').read_bytes()
    target = config / 'public-https.yaml'; target.write_bytes(source); target.chmod(0o600)
    return operator, storage, config, state, source, calls


def with_fds(fixture, fn):
    h, s, config, state, _, _ = fixture
    conf = s.open_directory(config, os.getuid()); recovery = s.open_directory(state, os.getuid())
    try:
        return fn(h, s, conf, recovery, state)
    finally:
        os.close(conf); os.close(recovery)


RELEASE = '20261022T000000.000000Z'


def get_plan(fixture):
    return with_fds(fixture, lambda h, s, conf, _, state: h.plan(s, conf, state, RELEASE))


def apply(fixture, expected):
    return with_fds(fixture, lambda h, s, conf, recovery, state:
        h.apply(s, conf, recovery, state, RELEASE, expected))


def rollback(fixture, expected):
    return with_fds(fixture, lambda h, s, conf, recovery, state:
        h.rollback(s, conf, recovery, state, RELEASE, expected))


def test_proposal_changes_only_owner_opt_in(setup):
    h, _, config, state, before, _ = setup
    plan, original, proposed = get_plan(setup)
    a = yaml.safe_load(before); b = yaml.safe_load(proposed)
    assert original == before and (config / 'public-https.yaml').read_bytes() == before
    a['workspaces']['cranary']['downloads']['cran_all_paths'] = True
    assert b == a
    assert plan['before_sha256'] == h.digest(before)
    assert plan['after_sha256'] == h.digest(proposed)
    assert not list(state.iterdir())


def test_apply_and_rollback_are_exact_and_backups_are_private(setup):
    h, _, config, state, original, calls = setup
    plan, _, proposed = get_plan(setup); expected = h.digest(h.canonical(plan))
    result = apply(setup, expected)
    assert calls == ['quiet', 'quiet'] and result['applied']
    assert (config / 'public-https.yaml').read_bytes() == proposed
    assert (config / 'public-https.yaml').stat().st_mode & 0o777 == 0o600
    backup = state / ('cran-' + expected)
    assert backup.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in backup.iterdir())
    assert (backup / 'before.yaml').read_bytes() == original
    assert rollback(setup, expected)['rolled_back']
    assert (config / 'public-https.yaml').read_bytes() == original
    assert rollback(setup, expected)['already_restored']
    assert calls == ['quiet', 'quiet', 'quiet', 'quiet']


def test_wrong_plan_hash_does_not_write_or_create_backup(setup):
    _, _, config, state, original, _ = setup
    with pytest.raises(RuntimeError, match='plan changed'):
        apply(setup, '0' * 64)
    assert (config / 'public-https.yaml').read_bytes() == original and not list(state.iterdir())


def test_active_service_refuses_mutation(setup):
    _, storage, config, state, original, _ = setup
    plan, _, _ = get_plan(setup)
    storage.quiet_and_stopped = lambda: (_ for _ in ()).throw(RuntimeError('service active'))
    with pytest.raises(RuntimeError, match='service active'):
        apply(setup, setup[0].digest(setup[0].canonical(plan)))
    assert (config / 'public-https.yaml').read_bytes() == original and not list(state.iterdir())


def test_already_enabled_does_not_rewrite_owner_policy(setup):
    h, _, config, state, _, _ = setup
    _, _, proposed = get_plan(setup); target = config / 'public-https.yaml'; target.write_bytes(proposed)
    identity = target.stat()
    plan, _, _ = get_plan(setup)
    assert apply(setup, h.digest(h.canonical(plan)))['already_enabled']
    current = target.stat()
    assert (current.st_ino, current.st_mtime_ns, current.st_ctime_ns, current.st_mode) == (
        identity.st_ino, identity.st_mtime_ns, identity.st_ctime_ns, identity.st_mode)
    assert not list(state.iterdir())


def test_changed_policy_between_plan_and_apply_is_preserved(setup):
    h, _, config, state, original, _ = setup
    plan, _, _ = get_plan(setup)
    changed = original + b'\n# owner change\n'; (config / 'public-https.yaml').write_bytes(changed)
    with pytest.raises(RuntimeError, match='plan changed'):
        apply(setup, h.digest(h.canonical(plan)))
    assert (config / 'public-https.yaml').read_bytes() == changed and not list(state.iterdir())


def test_rollback_refuses_newer_policy(setup):
    h, _, config, _, _, _ = setup
    plan, _, _ = get_plan(setup); expected = h.digest(h.canonical(plan)); apply(setup, expected)
    target = config / 'public-https.yaml'; changed = target.read_bytes() + b'\n# newer owner update\n'
    target.write_bytes(changed)
    with pytest.raises(RuntimeError, match='Newer'):
        rollback(setup, expected)
    assert target.read_bytes() == changed


def test_corrupt_backup_refuses_rollback(setup):
    h, _, config, state, _, _ = setup
    plan, _, _ = get_plan(setup); expected = h.digest(h.canonical(plan)); apply(setup, expected)
    current = (config / 'public-https.yaml').read_bytes()
    (state / ('cran-' + expected) / 'before.yaml').write_bytes(b'corrupted')
    with pytest.raises((RuntimeError, ValueError)):
        rollback(setup, expected)
    assert (config / 'public-https.yaml').read_bytes() == current


@pytest.mark.parametrize('field,value', [('max_response_bytes', 16777217), ('timeout_seconds', 61),
    ('directory', 'src/downloads'), ('cran_all_paths', 'true'), ('hosts', ['evil.example'])])
def test_invalid_owner_policy_is_not_repaired_implicitly(setup, field, value):
    _, _, config, state, original, _ = setup
    doc = yaml.safe_load(original); doc['workspaces']['cranary']['downloads'][field] = value
    changed = yaml.safe_dump(doc).encode(); (config / 'public-https.yaml').write_bytes(changed)
    with pytest.raises((PermissionError, ValueError, RuntimeError)):
        get_plan(setup)
    assert (config / 'public-https.yaml').read_bytes() == changed and not list(state.iterdir())


def test_missing_cran_host_does_not_expand_host_list(setup):
    _, _, config, state, original, _ = setup
    doc = yaml.safe_load(original); doc['workspaces']['cranary']['downloads']['hosts'] = ['packagemanager.posit.co']
    changed = yaml.safe_dump(doc).encode(); (config / 'public-https.yaml').write_bytes(changed)
    with pytest.raises((PermissionError, ValueError, RuntimeError)):
        get_plan(setup)
    assert (config / 'public-https.yaml').read_bytes() == changed and not list(state.iterdir())


def test_service_recheck_failure_preserves_policy_and_backup(setup):
    h, s, config, state, before, _ = setup
    admission, _, _ = get_plan(setup); expected = h.digest(h.canonical(admission))
    count = 0
    def quiet():
        nonlocal count
        count += 1
        if count == 2:
            raise RuntimeError('service changed')
    s.quiet_and_stopped = quiet
    with pytest.raises(RuntimeError, match='service changed'):
        apply(setup, expected)
    assert (config / 'public-https.yaml').read_bytes() == before
    assert (state / ('cran-' + expected) / 'before.yaml').read_bytes() == before
    assert rollback(setup, expected)['already_restored']


@pytest.mark.parametrize('suffix', [b'\nversion: 2\n', b'\nunused: &x {key: value}\ncopy: *x\n'])
def test_duplicate_or_alias_policy_is_rejected(setup, suffix):
    _, _, config, state, before, _ = setup
    target = config / 'public-https.yaml'; target.write_bytes(before + suffix)
    with pytest.raises((ValueError, RuntimeError, yaml.YAMLError)):
        get_plan(setup)
    assert target.read_bytes() == before + suffix and not list(state.iterdir())


@pytest.mark.parametrize('expected', ['../escape', '', 'g' * 64])
def test_rollback_rejects_non_digest_paths(setup, expected):
    with pytest.raises(RuntimeError):
        rollback(setup, expected)


def test_root_and_nonisolated_invocations_are_refused(operator, monkeypatch):
    monkeypatch.setattr(operator.os, 'getuid', lambda: 0)
    with pytest.raises(RuntimeError, match='service UID'):
        operator.dependencies()


@pytest.mark.parametrize('status,accepted', [('completed', True), ('failed', True),
    ('cancelled', True), ('timed_out', True), ('output_limit_exceeded', True),
    ('interrupted', True), ('running', False), ('queued', False), ('unknown', False), (None, False)])
def test_job_gate_allows_only_known_terminal_states(operator, tmp_path, status, accepted):
    path = tmp_path / 'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE jobs(status TEXT)'); db.execute('INSERT INTO jobs VALUES (?)', (status,))
    if accepted:
        operator.strict_jobs(path)
    else:
        with pytest.raises(RuntimeError, match='unresolved'):
            operator.strict_jobs(path)


def test_unresolved_admissions_block_policy_mutation(operator, tmp_path):
    path = tmp_path / 'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE jobs(status TEXT)')
        db.execute('CREATE TABLE job_admissions(id TEXT)'); db.execute("INSERT INTO job_admissions VALUES ('pending')")
    with pytest.raises(RuntimeError, match='admissions'):
        operator.strict_jobs(path)
