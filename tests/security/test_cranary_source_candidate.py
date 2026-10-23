"""Code-only CRAN derivative must preserve its exact installed baseline."""
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def candidate():
    path = Path(__file__).parents[2] / 'scripts/prepare-a7dev-cranary-source-repair.py'
    spec = importlib.util.spec_from_file_location('cranary_source_candidate_tests', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_uses_exact_active_release_and_single_code_module(candidate):
    p = candidate.load_preparer()
    assert p.OLD_VERSION == '20261022T181133.685266Z'
    assert p.BASE_SHA == 'ce546675f17f6e6e70a39d196ac763b3bbe155de67ad39f24af057e95e22d5b9'
    assert p.MODULES == {'src/agentporter/scoped_https.py'}
    assert all(path.startswith('operator-plan/') for path in p.INERT.values())
    assert 'docs/examples/a7dev-cranary-all-cran-paths-https.yaml' in p.INERT
    assert p.INERT['scripts/enable-a7dev-all-cran-paths.py'] == 'operator-plan/enable-a7dev-all-cran-paths.py'


def manifests(p):
    before = {name: {'sha256': 'old'} for name in p.MODULES | {'unrelated', 'venv/pyvenv.cfg'}}
    after = {name: dict(value) for name, value in before.items()}
    for name in p.MODULES | {'venv/pyvenv.cfg'}:
        after[name] = {'sha256': 'new'}
    for name in p.INERT.values():
        after[name] = {'sha256': 'inert'}
    return before, after


def test_exact_code_and_inert_delta_is_admitted(candidate):
    p = candidate.load_preparer()
    before, after = manifests(p)
    changed = p.validate_release_delta(before, after, {'venv/pyvenv.cfg'})
    assert set(changed) == p.MODULES | {'venv/pyvenv.cfg'} | set(p.INERT.values())


@pytest.mark.parametrize('mode', ['delete', 'extra_code', 'modify_unrelated', 'missing_code', 'missing_relocation'])
def test_unreviewed_payload_deltas_fail(candidate, mode):
    p = candidate.load_preparer()
    before, after = manifests(p)
    if mode == 'delete':
        del after['unrelated']
    elif mode == 'extra_code':
        after['src/agentporter/unsafe.py'] = {'sha256': 'new'}
    elif mode == 'modify_unrelated':
        after['unrelated'] = {'sha256': 'new'}
    elif mode == 'missing_code':
        after['src/agentporter/scoped_https.py'] = before['src/agentporter/scoped_https.py']
    else:
        after['venv/pyvenv.cfg'] = before['venv/pyvenv.cfg']
    with pytest.raises(ValueError, match='payload delta'):
        p.validate_release_delta(before, after, {'venv/pyvenv.cfg'})


@pytest.mark.parametrize('version,profile', [('20261022T165047.488565Z', 'development'),
    ('20261022T181133.685266Z', 'production')])
def test_wrong_baseline_identity_fails(candidate, version, profile):
    p = candidate.load_preparer()
    with pytest.raises(ValueError, match='baseline'):
        p.validate_baseline_metadata({'version': version, 'profile': profile})


def test_changed_preparer_is_rejected_before_execution(candidate, tmp_path):
    source = tmp_path / 'preparer.py'
    source.write_text("raise AssertionError('must not execute')")
    with pytest.raises(ValueError, match='SHA256'):
        candidate.load_preparer(source)
