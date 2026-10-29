"""Diagnostic preparation must preserve the currently installed CRAN release."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / 'scripts/prepare-a7dev-posit-redirect-diagnostic.py'


def preparer():
    spec = importlib.util.spec_from_file_location('posit_diagnostic_preparer', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_preparer()


def test_only_diagnostic_module_and_relocations_are_admitted():
    module = preparer()
    assert module.OLD_VERSION == '20261022T204324.626687Z'
    assert module.MODULES == {'src/agentporter/https_download.py'}
    assert module.INERT == {}
    relocations = {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
    before = {name: 1 for name in module.MODULES | relocations | {'src/agentporter/scoped_https.py'}}
    after = {**before, **{name: 2 for name in module.MODULES | relocations}}
    assert set(module.validate_release_delta(before, after, relocations)) == module.MODULES | relocations
    after['src/agentporter/scoped_https.py'] = 2
    with pytest.raises(ValueError):
        module.validate_release_delta(before, after, relocations)


def test_runtime_relocation_never_retains_old_release_paths():
    module = preparer()
    old = '/opt/agentporter-development/versions/' + module.OLD_VERSION
    new = '/opt/agentporter-development/versions/20261022T230000.000000Z'
    runtime = {'workers': {'prof': {'argv': [old + '/venv/bin/python']}}, 'unchanged': True}
    relocated = module.relocate_runtime(runtime, old, new)
    assert relocated['workers']['prof']['argv'] == [new + '/venv/bin/python']
    assert module.relocate_runtime(relocated, new, old) == runtime
