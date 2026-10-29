"""Diagnostic activation gates; all service operations are synthetic."""
import os
from pathlib import Path
import re
import subprocess

import pytest

from tests.security import test_cranary_activation_launcher as shared

SCRIPT = Path(__file__).parents[2] / 'scripts/activate-a7dev-posit-redirect-diagnostic.sh'


@pytest.fixture(autouse=True)
def use_diagnostic_launcher(monkeypatch):
    monkeypatch.setattr(shared, 'SCRIPT', SCRIPT)


# Execute the same real shell failure-path scenarios against this launcher.
test_recovery = shared.test_recovery_restarts_only_proven_unchanged_preinstall_state
test_root_refuses = shared.test_root_and_placeholder_runs_refuse_before_privileged_actions


def test_diagnostic_install_is_stopped_and_has_no_policy_mutation():
    body = SCRIPT.read_text().split('trap activation_failed ERR', 1)[1]
    stop = body.index('sudo /usr/bin/systemctl stop "$unit"')
    install_started = body.index('install_started=1')
    install = body.index('"$installer" --artifact')
    start = body.index('sudo /usr/bin/systemctl start "$unit"')
    assert stop < install_started < install < start
    assert body.count('run_gate') >= 2
    assert body.index('pause_discovery') < stop
    assert body.index('quiet_jobs') < stop
    assert body.index('healthy_development', start) < body.index('restore_timer', start)
    assert '--activate' not in body and '--skip' not in body
    assert '--apply' not in body and 'policy_helper=' not in body
    assert '20261022T204324.626687Z' in SCRIPT.read_text()
    assert '8c9a0491c836043dbdb155f7f8dbbd64feddf2a145fee8ba3d868f79ec572842' in SCRIPT.read_text()
    assert '186225cf8c888a2efc4becee7150029d5cc3435777e8306f66d502bca1f5b97e' not in SCRIPT.read_text()


@pytest.mark.parametrize('key,value', [('artifact_sha', 'unprepared'),
    ('new', '/opt/agentporter-development/versions/not-reviewed')])
def test_invalid_candidate_pins_refuse_before_sudo(tmp_path, key, value):
    fake = tmp_path / 'bin'; fake.mkdir()
    identity = fake / 'id'; identity.write_text('#!/bin/sh\nprintf "yeli\\n"\n'); identity.chmod(0o700)
    sudo = fake / 'sudo'; sudo.write_text('#!/bin/sh\nexit 99\n'); sudo.chmod(0o700)
    text, count = re.subn(r'^' + key + r'=.*$', key + '=' + value, SCRIPT.read_text(), flags=re.MULTILINE)
    assert count == 1
    script = tmp_path / 'candidate.sh'; script.write_text(text)
    result = subprocess.run(['/bin/bash', str(script)], capture_output=True, text=True,
        env={**os.environ, 'PATH': str(fake) + ':' + os.environ['PATH']})
    assert result.returncode == 1 and 'pins are not finalized' in result.stderr
