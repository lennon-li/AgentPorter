import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


@pytest.fixture
def migration(tmp_path, monkeypatch):
    script = Path(__file__).parents[2] / 'scripts/migrate-production-workspace-policy.py'
    spec = importlib.util.spec_from_file_location('production_migration_test', script)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    home = tmp_path / 'owner'; home.mkdir(mode=0o700)
    worker = tmp_path / 'worker'; worker.mkdir(mode=0o700)
    central = tmp_path / 'central'
    for name in ['.config/agentporter', '.local/state/agentporter', '.cache/agentporter',
                 '.local/share/agentporter', '.local/libexec/agentporter-production-20261028']:
        (home / name).mkdir(mode=0o700, parents=True)
    (worker / 'config').mkdir(mode=0o700)
    for directory in home.rglob('*'):
        if directory.is_dir(): directory.chmod(0o700)
    release = tmp_path / 'releases'; release.mkdir()
    libexec = tmp_path / 'libexec'; libexec.mkdir()
    monkeypatch.setattr(module, 'CENTRAL', central)
    monkeypatch.setattr(module, 'POLICY', central / 'production-workspace-policy.yaml')
    monkeypatch.setattr(module, 'WORKER', worker)
    monkeypatch.setattr(module, 'WORKER_RELEASE', release)
    monkeypatch.setattr(module, 'LIBEXEC', libexec)
    monkeypatch.setattr(module, 'ROOT_UID', os.getuid())
    monkeypatch.setattr(module, 'ROOT_GID', os.getgid())
    identity = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    monkeypatch.setattr(module, 'inspect', lambda _, **kwargs: (identity, identity))
    rows = {}
    for index in range(11):
        root = tmp_path / f'project-{index}'; root.mkdir()
        rows[f'project-{index}'] = {'path': str(root), 'writable': index % 2 == 0,
                                   'allow_agent_dispatch': index == 0}
    rows['project-0']['allow_scinet_training'] = True
    cfg = home / '.config/agentporter'; wc = worker / 'config'
    docs = {
        cfg / 'workspaces.yaml': {'workspaces': rows},
        cfg / 'public-client-policy.yaml': {'version': 1, 'workspaces': {
            name: {'path': row['path'], 'operations': ['read']} for name, row in rows.items()}},
        cfg / 'delegation-upstream.yaml': {'version': 1, 'host': '127.0.0.1', 'port': 8876,
                                           'workspaces': ['project-0']},
        wc / 'workspaces.yaml': {'workspaces': {'project-0': rows['project-0']}},
        wc / 'public-client-policy.yaml': {'version': 1, 'workspaces': {'project-0': ['read']}},
        wc / 'delegation-relay-scope.yaml': {'version': 1, 'workspaces': {'project-0': rows['project-0']['path']}},
        wc / 'development-runtime.yaml': {'service_unit': 'agentporter-worker.service',
                                         'allowed_workspace_roots': [], 'production_relay_agents': []},
    }
    for path, document in docs.items():
        path.write_text(yaml.safe_dump(document)); path.chmod(0o600)
    return module, home, docs


def test_plan_is_read_only_and_unifies_only_ordinary_capabilities(migration):
    module, home, docs = migration
    before = {p: p.read_bytes() for p in docs}
    changes = module.build(home)
    assert all(p.read_bytes() == value for p, value in before.items())
    assert not module.CENTRAL.exists()
    policy = yaml.safe_load(changes[str(module.POLICY)]['after'][0])
    assert len(policy['workspaces']) == 11
    assert all(policy['workspace_defaults'].values())
    assert policy['workspace_overrides'] == {}
    assert policy['workspaces']['project-0']['allow_scinet_training'] is True
    assert all('allow_scinet_training' not in row for name, row in policy['workspaces'].items()
               if name != 'project-0')
    assert 'agentporter-development' not in json.dumps(list(changes))


def test_runtime_repair_preserves_existing_shared_controls_and_rollback(migration):
    module, home, _ = migration
    initial = module.fingerprint(module.build(home))
    module.apply(home, initial, attempt_id='initial')
    changes = module.build(home)
    assert changes and all(row['before'] == row['after'] for row in changes.values())
    contents = {path: Path(path).read_bytes() for path in changes}
    repair = module.fingerprint(changes)
    module.apply(home, repair, attempt_id='runtime-repair')
    assert all(Path(path).read_bytes() == body for path, body in contents.items())
    module.rollback(home, repair, attempt_id='runtime-repair')
    assert all(Path(path).read_bytes() == body for path, body in contents.items())


def test_runtime_repair_rejects_mixed_shared_references(migration):
    module, home, _ = migration
    module.apply(home, module.fingerprint(module.build(home)), attempt_id='initial')
    control = module.WORKER / 'config/public-client-policy.yaml'
    control.write_text(yaml.safe_dump({'version': 2, 'policy_file': '/wrong-policy'}))
    with pytest.raises(ValueError, match='Mixed or unexpected'):
        module.build(home)



def test_wrong_plan_hash_never_mutates(migration):
    module, home, docs = migration
    before = {p: p.read_bytes() for p in docs}
    with pytest.raises(ValueError): module.apply(home, '0' * 64)
    assert all(p.read_bytes() == value for p, value in before.items())
    assert not module.CENTRAL.exists()


def test_apply_and_rollback_preserve_every_original_control(migration):
    module, home, docs = migration
    before = {p: (p.read_bytes(), p.stat().st_mode) for p in docs}
    plan = module.fingerprint(module.build(home))
    module.apply(home, plan)
    assert all(yaml.safe_load(p.read_text())['version'] == 2 for p in docs if p.name != 'development-runtime.yaml')
    module.rollback(home, plan)
    assert all((p.read_bytes(), p.stat().st_mode) == value for p, value in before.items())
    assert not module.POLICY.exists()


def test_changed_controls_block_apply_and_rollback(migration):
    module, home, docs = migration
    plan = module.fingerprint(module.build(home))
    target = next(iter(docs)); target.write_text(target.read_text() + '# changed\n')
    with pytest.raises(ValueError): module.apply(home, plan)
    new_plan = module.fingerprint(module.build(home)); module.apply(home, new_plan)
    target.write_text('version: 2\npolicy_file: /different\n')
    with pytest.raises(ValueError): module.rollback(home, new_plan)


def test_partial_config_failure_restores_exact_originals(migration, monkeypatch):
    module, home, docs = migration
    before = {p: p.read_bytes() for p in docs}
    original = module.atomic; calls = 0
    def fail_once(path, value):
        nonlocal calls
        calls += 1
        if calls == 4: raise OSError('fixture failure')
        return original(path, value)
    monkeypatch.setattr(module, 'atomic', fail_once)
    with pytest.raises(OSError): module.apply(home, module.fingerprint(module.build(home)))
    assert all(p.read_bytes() == value for p, value in before.items())


def test_existing_trusted_central_directory_preserves_mode_and_unrelated_files(migration):
    module, home, docs = migration
    module.CENTRAL.mkdir(mode=0o755)
    unrelated = module.CENTRAL / 'existing-approval.pub'
    unrelated.write_text('existing public key')
    plan = module.fingerprint(module.build(home, require_stopped=False))
    module.apply(home, plan)
    assert module.CENTRAL.stat().st_mode & 0o777 == 0o755
    module.rollback(home, plan)
    assert unrelated.read_text() == 'existing public key'
    assert module.CENTRAL.stat().st_mode & 0o777 == 0o755


def test_unsafe_existing_central_directory_fails_during_read_only_plan(migration):
    module, home, docs = migration
    module.CENTRAL.mkdir(); module.CENTRAL.chmod(0o777)
    before = {p: p.read_bytes() for p in docs}
    with pytest.raises(ValueError): module.build(home, require_stopped=False)
    assert all(p.read_bytes() == value for p, value in before.items())


def test_online_preflight_keeps_idle_and_identity_checks_but_skips_service_stop_gate(migration, monkeypatch):
    module, home, docs = migration
    calls = []
    def inspect(_, *, require_stopped=True):
        calls.append(require_stopped)
        identity = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        return identity, identity
    monkeypatch.setattr(module, 'inspect', inspect)
    module.build(home, require_stopped=False)
    module.build(home)
    assert calls == [False, True]


def test_precondition_diagnostics_identify_code_location_without_values(migration):
    module, _, _ = migration
    with pytest.raises(ValueError, match=r'precondition failed: test_precondition_diagnostics_identify_code_location_without_values:\d+'):
        module.require(False)


def test_retry_after_rollback_preserves_prior_journals_and_selects_exact_attempt(migration):
    module, home, docs = migration
    before = {p: p.read_bytes() for p in docs}
    plan = module.fingerprint(module.build(home))
    # Reproduce the journal from the older installer, then two new attempts.
    module.apply(home, plan)
    legacy = module.recovery_path(plan) / 'snapshot.json'
    legacy_body = legacy.read_bytes()
    module.rollback(home, plan)
    module.apply(home, plan, attempt_id='installation-one')
    first = module.recovery_path(plan, 'installation-one') / 'snapshot.json'
    first_body = first.read_bytes()
    module.rollback(home, plan, attempt_id='installation-one')
    assert module.fingerprint(module.build(home)) == plan
    module.apply(home, plan, attempt_id='installation-two')
    with pytest.raises(ValueError): module.rollback(home, plan, attempt_id='installation-one')
    module.rollback(home, plan, attempt_id='installation-two')
    assert legacy.read_bytes() == legacy_body and first.read_bytes() == first_body
    assert all(p.read_bytes() == body for p, body in before.items())


def test_recovery_attempt_cannot_be_reused_or_escape_central_directory(migration):
    module, home, docs = migration
    plan = module.fingerprint(module.build(home))
    module.apply(home, plan, attempt_id='installation-one')
    module.rollback(home, plan, attempt_id='installation-one')
    before = {p: p.read_bytes() for p in docs}
    with pytest.raises(FileExistsError): module.apply(home, plan, attempt_id='installation-one')
    with pytest.raises(ValueError): module.apply(home, plan, attempt_id='../outside')
    assert all(p.read_bytes() == body for p, body in before.items())
