"""Preinstall private-runtime admission rejects drift without disclosing config."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import yaml


@pytest.fixture
def gate(tmp_path, monkeypatch):
    source = Path(__file__).parents[2] / 'scripts/verify-a7dev-runtime-install-gate.py'
    spec = importlib.util.spec_from_file_location('runtime_gate', source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    runtime = {'profile': 'development', 'enabled': True,
               'workers': {'liz': {'credential': 'synthetic-private-data-not-for-output'}}}
    control = tmp_path / 'runtime.yaml'
    control.write_text(yaml.safe_dump(runtime))
    control.chmod(0o600)
    version = '20261022T015212.581522Z'
    monkeypatch.setattr(helper.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=os.geteuid()))
    monkeypatch.setattr(helper.Path, 'resolve', lambda self, strict=False:
                        Path('/opt/agentporter-development/versions') / version)
    real_open = helper.os.open
    monkeypatch.setattr(helper.os, 'open', lambda name, flags:
                        real_open(control if name == '/var/lib/agentporter-dev/config/development-runtime.yaml' else name, flags))
    digest = hashlib.sha256(json.dumps(runtime, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    monkeypatch.setattr(sys, 'argv', ['gate', '--expected-version', version,
                                    '--expected-canonical-sha256', digest])
    return helper, control, runtime


def test_equivalent_private_yaml_passes_without_content_disclosure(gate, capsys):
    helper, control, runtime = gate
    control.write_text(json.dumps(runtime))
    helper.main()
    output = capsys.readouterr().out
    assert json.loads(output)['runtime_install_gate'] == 'passed'
    assert 'synthetic-private-data' not in output
    assert 'credential' not in output


def test_runtime_policy_drift_refuses_install(gate, capsys):
    helper, control, runtime = gate
    runtime['enabled'] = False
    control.write_text(yaml.safe_dump(runtime))
    with pytest.raises(ValueError, match='differs from candidate baseline'):
        helper.main()
    assert capsys.readouterr().out == ''


def test_release_drift_refuses_install(gate, monkeypatch):
    helper, _, _ = gate
    monkeypatch.setattr(helper.Path, 'resolve', lambda self, strict=False:
                        Path('/opt/agentporter-development/versions/20261023T000000.000000Z'))
    with pytest.raises(ValueError, match='release changed'):
        helper.main()


def test_nonprivate_runtime_refuses_install(gate):
    helper, control, _ = gate
    control.chmod(0o640)
    with pytest.raises(PermissionError, match='Unsafe A7Dev runtime'):
        helper.main()
