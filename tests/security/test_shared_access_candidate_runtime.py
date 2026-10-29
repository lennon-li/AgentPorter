"""Candidate preparation must preserve pinned active runtime semantics privately."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


@pytest.fixture
def prep(monkeypatch):
    source = Path(__file__).parents[2] / 'scripts/prepare-a7dev-shared-access-repair.py'
    spec = importlib.util.spec_from_file_location('shared_access_candidate', source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    monkeypatch.setattr(helper.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=1000))
    return helper


@pytest.fixture
def runtime():
    return {'enabled': True, 'profile': 'development', 'gateway_user': 'agentporter-dev',
            'production_uid': 1000, 'workers': {name: {} for name in ('jax', 'liz', 'prof', 'ming', 'wei', 'phil', 'argie')},
            'allowed_workspace_roots': [{'path': '/approved/project', 'writable': True}],
            'network_enabled': False, 'limits': [True, 17, None, 'unchanged']}


def test_explicit_active_runtime_is_parsed_without_semantic_changes(prep, runtime):
    assert prep.parse_active_runtime(yaml.safe_dump(runtime)) == runtime
    assert prep.parse_active_runtime(json.dumps(runtime)) == runtime


@pytest.mark.parametrize('extra', ['\nprofile: development\n', '\nworkers: {}\n'])
def test_duplicate_runtime_keys_reject_even_same_value(prep, runtime, extra):
    with pytest.raises(ValueError, match='duplicate'):
        prep.parse_active_runtime(yaml.safe_dump(runtime) + extra)


def test_duplicate_nested_key_rejects(prep, runtime):
    body = yaml.safe_dump(runtime).replace('jax: {}', 'jax:\n    executable: first\n    executable: second')
    with pytest.raises(ValueError, match='duplicate'):
        prep.parse_active_runtime(body)


def test_yaml_aliases_reject(prep):
    with pytest.raises(ValueError, match='aliases'):
        prep.parse_active_runtime('x: &ref {}\ny: *ref\n')


@pytest.mark.parametrize('key,value', [('enabled', False), ('profile', 'production'),
    ('gateway_user', 'yeli'), ('production_uid', True), ('production_uid', 0),
    ('workers', {'liz': {}}), ('allowed_workspace_roots', []),
    ('allowed_workspace_roots', [{'path': '/approved/project', 'writable': 'true'}]),
    ('allowed_workspace_roots', [{'path': 'relative', 'writable': True}])])
def test_invalid_or_production_runtime_refused_without_value_disclosure(prep, runtime, key, value):
    runtime[key] = value
    with pytest.raises(ValueError) as error:
        prep.parse_active_runtime(yaml.safe_dump(runtime))
    assert 'yeli' not in str(error.value)
    assert '/approved' not in str(error.value)


def test_release_relocation_changes_values_only_and_is_reversible(prep, runtime):
    old, new = '/opt/agentporter-development/versions/old', '/opt/agentporter-development/versions/new'
    runtime['workers']['liz'] = {'executable': old + '/cli/codex',
                                'credentials': {'auth': '/private/credential-reference'},
                                'unusual_key_' + old: 'retained'}
    runtime['limits'].extend([old, 'embedded ' + old + '/bin'])
    relocated = prep.relocate_runtime(runtime, old, new)
    assert relocated['workers']['liz']['executable'] == new + '/cli/codex'
    assert relocated['workers']['liz']['credentials'] == runtime['workers']['liz']['credentials']
    assert 'unusual_key_' + old in relocated['workers']['liz']
    assert relocated['limits'][-2] == old
    assert prep.relocate_runtime(relocated, new, old) == runtime
    assert runtime['workers']['liz']['executable'] == old + '/cli/codex'


def test_safe_drift_count_contains_no_values(prep):
    assert prep.changed_leaves({'a': [1, 2], 'b': 'private-old'}, {'a': [1, 3, 4], 'b': 'private-new'}) == 3


@pytest.mark.parametrize('missing', ['--runtime', '--runtime-sha256'])
def test_cli_requires_both_explicit_runtime_and_pin(prep, monkeypatch, tmp_path, missing):
    import sys
    args = ['prep', '--base', str(tmp_path / 'base'), '--input-pins', str(tmp_path / 'pins'),
            '--output', str(tmp_path / 'output'), '--extract-to', str(tmp_path / 'extract'),
            '--report', str(tmp_path / 'report'), '--version', '20261022T170000.000000Z']
    if missing != '--runtime':
        args += ['--runtime', str(tmp_path / 'private-runtime')]
    if missing != '--runtime-sha256':
        args += ['--runtime-sha256', '0' * 64]
    monkeypatch.setattr(sys, 'argv', args)
    with pytest.raises(SystemExit) as error:
        prep.main()
    assert error.value.code == 2
    assert not (tmp_path / 'output').exists()


def test_yaml_diagnostic_does_not_disclose_runtime_contents(prep):
    private = 'synthetic-private-runtime-value'
    with pytest.raises(ValueError) as error:
        prep.parse_active_runtime('workers: [' + private)
    assert str(error.value) == 'Invalid active runtime YAML'
    assert private not in str(error.value)


def test_default_acl_derivative_is_pinned_to_current_reviewed_release(prep):
    assert prep.BASE_SHA == '3f35441c59a392c6ca940915309fe26511eb17adfe09ba8a1b1674f95202c78d'
    assert prep.OLD_VERSION == '20261022T165047.488565Z'
    prep.validate_baseline_metadata({'version': prep.OLD_VERSION, 'profile': 'development'})
    with pytest.raises(ValueError, match='Unexpected baseline'):
        prep.validate_baseline_metadata({'version': '20261022T015212.581522Z', 'profile': 'development'})
    with pytest.raises(ValueError, match='Unexpected baseline'):
        prep.validate_baseline_metadata({'version': prep.OLD_VERSION, 'profile': 'production'})


def manifests(prep):
    relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
    before = {name: {'sha256': 'old', 'executable': False}
              for name in prep.MODULES | relocations | {'src/agentporter/server.py'}}
    after = {name: dict(value) for name, value in before.items()}
    for name in relocations | {'src/agentporter/workspaces/shared_access.py'}:
        after[name]['sha256'] = 'new'
    return before, after, relocations


def test_acl_only_change_with_other_modules_unchanged_is_admitted(prep):
    before, after, relocations = manifests(prep)
    changed = prep.validate_release_delta(before, after, relocations)
    assert set(changed) == relocations | {'src/agentporter/workspaces/shared_access.py'}
    after['operator-plan/validation/test_shared_workspace_access.py'] = {'sha256': 'new-test', 'executable': False}
    assert 'operator-plan/validation/test_shared_workspace_access.py' in prep.validate_release_delta(before, after, relocations)


@pytest.mark.parametrize('mutation', ['no_core_acl_change', 'missing_relocation', 'unrelated_source', 'removed_module'])
def test_delta_guard_rejects_missing_fix_or_unrelated_changes(prep, mutation):
    before, after, relocations = manifests(prep)
    if mutation == 'no_core_acl_change':
        after['src/agentporter/workspaces/shared_access.py'] = before['src/agentporter/workspaces/shared_access.py']
    elif mutation == 'missing_relocation':
        after['venv/pyvenv.cfg'] = before['venv/pyvenv.cfg']
    elif mutation == 'unrelated_source':
        after['src/agentporter/server.py']['sha256'] = 'unrelated-edit'
    else:
        del after['src/agentporter/client_policy.py']
    with pytest.raises(ValueError, match='Unexpected release payload delta'):
        prep.validate_release_delta(before, after, relocations)
