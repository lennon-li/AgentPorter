"""Sequential workspace grants must retain independent private rollback history."""
import importlib.util
import os
from pathlib import Path
import stat

import pytest
import yaml


@pytest.fixture
def helper(tmp_path, monkeypatch):
    source = Path(__file__).parents[2] / 'scripts/authorize-a7dev-writable-delegation.py'
    spec = importlib.util.spec_from_file_location('writable_recovery', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = tmp_path / 'config'
    config.mkdir(mode=0o700)
    roots = {name: str(tmp_path / name) for name in ('agentporter-dev', 'Qman')}
    for path in roots.values():
        Path(path).mkdir()
    monkeypatch.setattr(module.storage, 'EXPECTED_ROOTS', roots)
    monkeypatch.setattr(module.storage, 'CONFIG', config)
    registry = {'workspaces': {name: {'path': path, 'writable': True,
        'allow_execute': True, 'allow_agent_dispatch': True} for name, path in roots.items()}}
    policy = {'version': 1, 'workspaces': {name: {'path': path,
        'operations': ['read', 'write', 'dispatch']} for name, path in roots.items()}}
    runtime = {'enabled': True, 'profile': 'development', 'allowed_workspace_roots': [
        {'path': path, 'writable': name == 'agentporter-dev'} for name, path in roots.items()]}
    for name, data in zip(module.storage.FILES, (policy, registry, runtime)):
        target = config / name
        target.write_text(yaml.safe_dump(data))
        target.chmod(0o600)
    (config / module.storage.HTTPS).write_bytes(b'private unchanged HTTPS policy')
    (config / module.storage.HTTPS).chmod(0o600)
    legacy = config / 'writable-delegation-recovery-v1'
    legacy.mkdir(mode=0o700)
    (legacy / 'receipt.json').write_bytes(b'legacy record must remain byte-identical')
    return module, config, legacy


def read_inputs(helper, fd):
    return {name: helper.storage.private_read(fd, name, os.getuid())
            for name in helper.storage.FILES + (helper.storage.HTTPS,)}


def apply(helper, fd, workspace):
    inputs = read_inputs(helper, fd)
    output, plan = helper.transform(inputs, Path('/fixture/release'), [workspace])
    expected = helper.storage.digest(helper.storage.canonical(plan))
    helper.apply_plan(fd, os.getuid(), inputs, output, plan, expected)
    return expected, inputs, output


def test_sequential_grants_keep_legacy_and_independent_private_backups(helper):
    module, config, legacy = helper
    legacy_bytes = (legacy / 'receipt.json').read_bytes()
    fd = module.storage.open_directory(config, os.getuid())
    try:
        original = read_inputs(module, fd)
        first, _, _ = apply(module, fd, 'agentporter-dev')
        second, second_before, _ = apply(module, fd, 'Qman')
        assert first != second
        assert module.recovery_name(first) != module.recovery_name(second)
        for expected in (first, second):
            recovery = config / module.recovery_name(expected)
            assert stat.S_IMODE(recovery.stat().st_mode) == 0o700
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in recovery.iterdir())
        assert (legacy / 'receipt.json').read_bytes() == legacy_bytes
        # An old grant cannot undo the newer, independently authorized grant.
        with pytest.raises(RuntimeError, match='Newer state'):
            module.rollback_plan(fd, os.getuid(), first)
        module.rollback_plan(fd, os.getuid(), second)
        assert read_inputs(module, fd) == second_before
        policy = yaml.safe_load((config / module.storage.FILES[0]).read_bytes())
        assert 'dispatch_write' in policy['workspaces']['agentporter-dev']['operations']
        assert 'dispatch_write' not in policy['workspaces']['Qman']['operations']
        module.rollback_plan(fd, os.getuid(), first)
        assert read_inputs(module, fd) == original
        assert (legacy / 'receipt.json').read_bytes() == legacy_bytes
    finally:
        os.close(fd)


@pytest.mark.parametrize('digest', ['', '../escape', 'a' * 63, 'A' * 64, 'g' * 64])
def test_recovery_namespace_rejects_unsafe_or_noncanonical_hash(helper, digest):
    module, _, _ = helper
    with pytest.raises(RuntimeError, match='Invalid recovery'):
        module.recovery_name(digest)


def test_plan_hash_mismatch_cannot_create_recovery_record(helper):
    module, config, _ = helper
    fd = module.storage.open_directory(config, os.getuid())
    try:
        inputs = read_inputs(module, fd)
        output, plan = module.transform(inputs, Path('/fixture/release'), ['Qman'])
        with pytest.raises(RuntimeError, match='SHA mismatch'):
            module.apply_plan(fd, os.getuid(), inputs, output, plan, '0' * 64)
        assert read_inputs(module, fd) == inputs
        assert sorted(path.name for path in config.glob('writable-delegation-recovery-*')) == ['writable-delegation-recovery-v1']
    finally:
        os.close(fd)


def test_all_eligible_selects_exact_admitted_leaves_and_reports_parent_blocker(helper):
    module, config, _ = helper
    fd = module.storage.open_directory(config, os.getuid())
    try:
        inputs = read_inputs(module, fd)
        registry = yaml.safe_load(inputs[module.storage.FILES[1]])
        policy = yaml.safe_load(inputs[module.storage.FILES[0]])
        runtime = yaml.safe_load(inputs[module.storage.FILES[2]])
        # A readonly registered parent cannot become one worker's write mount.
        parent = str(Path(module.storage.EXPECTED_ROOTS['Qman']).parent)
        module.storage.EXPECTED_ROOTS['parent'] = parent
        registry['workspaces']['parent'] = {'path': parent, 'writable': True,
            'allow_execute': True, 'allow_agent_dispatch': True}
        policy['workspaces']['parent'] = {'path': parent, 'operations': ['read', 'write', 'dispatch']}
        runtime['allowed_workspace_roots'].append({'path': parent, 'writable': False})
        # A protected root never joins the writable delegation grant.
        registry['workspaces']['obsidian'] = {'path': parent + '/protected', 'writable': True,
            'allow_execute': True, 'allow_agent_dispatch': True}
        policy['workspaces']['obsidian'] = {'path': parent + '/protected', 'operations': ['read', 'write', 'dispatch']}
        inputs.update({name: yaml.safe_dump(value).encode() for name, value in
                       zip(module.storage.FILES, (policy, registry, runtime))})
        selected, report = module.select_eligible(inputs, Path('/fixture/release'))
        assert selected == ['Qman', 'agentporter-dev']
        assert report['selected_count'] == 2 and report['blocked_count'] == 1
        assert report['excluded'] == [{'workspace': 'obsidian', 'reason': 'protected_project'}]
        assert report['blocked'][0]['workspace'] == 'parent'
        assert 'parent' in report['blocked'][0]['reason']
        output, _ = module.transform(inputs, Path('/fixture/release'), selected)
        updated_runtime = yaml.safe_load(output[module.storage.FILES[2]])
        assert updated_runtime['allowed_workspace_roots'][-1] == {'path': parent, 'writable': False}
        assert updated_runtime['allowed_workspace_roots'][1]['writable'] is True
    finally:
        os.close(fd)


def test_all_eligible_does_not_expand_public_read_or_registry_readonly_scopes(helper):
    module, config, _ = helper
    fd = module.storage.open_directory(config, os.getuid())
    try:
        inputs = read_inputs(module, fd)
        registry = yaml.safe_load(inputs[module.storage.FILES[1]])
        policy = yaml.safe_load(inputs[module.storage.FILES[0]])
        registry['workspaces']['Qman']['writable'] = False
        policy['workspaces']['agentporter-dev']['operations'].remove('dispatch')
        inputs[module.storage.FILES[0]] = yaml.safe_dump(policy).encode()
        inputs[module.storage.FILES[1]] = yaml.safe_dump(registry).encode()
        selected, report = module.select_eligible(inputs, Path('/fixture/release'))
        assert selected == []
        assert report['blocked'] == []
        assert {row['reason'] for row in report['excluded']} == {
            'registry_read_only', 'public_write_and_dispatch_not_admitted'}
    finally:
        os.close(fd)


def test_private_parser_diagnostics_do_not_expose_config_values(helper):
    module, _, _ = helper
    inputs = {name: b'synthetic-private-value: [' for name in module.storage.FILES}
    with pytest.raises(RuntimeError) as error:
        module.documents(inputs)
    assert str(error.value) == 'Invalid private delegation configuration YAML'
    assert 'synthetic-private-value' not in str(error.value)


def test_all_eligible_reports_actual_metadata_guard_failure_as_blocker(helper):
    module, config, _ = helper
    fd = module.storage.open_directory(config, os.getuid())
    try:
        def probe(release, path):
            if path == module.storage.EXPECTED_ROOTS['Qman']:
                raise RuntimeError('Writable confinement metadata/hardlink/protected-layout preflight failed')
        selected, report = module.select_eligible(read_inputs(module, fd), Path('/fixture/release'), probe)
        assert selected == ['agentporter-dev']
        assert report['blocked_count'] == 1
        assert report['blocked'][0]['workspace'] == 'Qman'
        assert 'hardlink' in report['blocked'][0]['reason']
    finally:
        os.close(fd)


def test_metadata_probe_never_emits_private_worker_diagnostics(helper, monkeypatch, capsys):
    from types import SimpleNamespace
    module, _, _ = helper
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stderr='private filename or credential reference'))
    with pytest.raises(RuntimeError) as error:
        module.probe_writable_workspace(Path('/immutable/release'), '/approved/project')
    assert 'private' not in str(error.value)
    assert capsys.readouterr().out == capsys.readouterr().err == ''


def test_concurrent_operator_mutation_fails_before_config_or_recovery_changes(helper):
    module, config, _ = helper
    fd = module.storage.open_directory(config, os.getuid())
    try:
        inputs = read_inputs(module, fd)
        output, plan = module.transform(inputs, Path('/fixture/release'), ['Qman'])
        expected = module.storage.digest(module.storage.canonical(plan))
        with module.mutation_lock(fd, os.getuid()):
            with pytest.raises(RuntimeError, match='Another writable delegation mutation'):
                module.apply_plan(fd, os.getuid(), inputs, output, plan, expected)
        assert read_inputs(module, fd) == inputs
        assert not (config / module.recovery_name(expected)).exists()
    finally:
        os.close(fd)
