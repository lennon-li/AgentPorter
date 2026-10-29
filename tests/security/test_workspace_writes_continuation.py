"""Continuation must preserve the installed core, grant scope and ACL boundaries."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from tests.security import test_directory_defaults_launcher as lifecycle


SCRIPT = Path(__file__).parents[2] / 'scripts/resume-a7dev-workspace-writes.sh'


@pytest.mark.parametrize('stopped,applied,same_release,same_config,quiet,restart_ok,restart,timer', [
    (0, 0, 1, 1, 1, 1, False, True), (1, 0, 1, 1, 1, 1, True, True),
    (1, 0, 1, 1, 1, 0, True, False), (1, 0, 1, 1, 0, 1, False, False),
    (1, 0, 0, 1, 1, 1, False, False), (1, 0, 1, 0, 1, 1, False, False),
    (1, 1, 1, 1, 1, 1, False, False)])
def test_continuation_failure_recovery_is_bound_to_exact_preapply_state(tmp_path, monkeypatch,
    stopped, applied, same_release, same_config, quiet, restart_ok, restart, timer):
    monkeypatch.setattr(lifecycle, 'SCRIPT', SCRIPT)
    lifecycle.test_only_proven_unchanged_preapply_failure_can_resume_services(tmp_path,
        stopped, applied, same_release, same_config, quiet, restart_ok, restart, timer)


@pytest.mark.parametrize('mode', ['valid', 'mismatch', 'symlink', 'fifo', 'oversized'])
def test_continuation_installs_only_bounded_verified_private_source(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(lifecycle, 'SCRIPT', SCRIPT)
    lifecycle.test_root_helper_source_is_bounded_and_private_until_verified(tmp_path, mode)


@pytest.mark.parametrize('blockers,accepted', [(0, True), (1, False), (-1, False), (False, False)])
def test_unrepairable_nonservice_access_denies_preflight(blockers, accepted):
    result = subprocess.run(['/bin/bash', '-c', 'source "$LAUNCHER"; plan_digest'],
        capture_output=True, text=True, input=json.dumps({'plan_sha256': 'a' * 64,
                                                       'remaining_human_access_blockers': blockers}),
        env={**os.environ, 'LAUNCHER': str(SCRIPT)})
    assert (result.returncode == 0) is accepted


def test_continuation_has_no_core_install_or_grant_and_never_runs_access_helper_as_root():
    body = SCRIPT.read_text()
    assert '--artifact' not in body and 'install-development-artifact' not in body
    assert 'enable-a7dev-workspace-writes.sh' not in body
    assert '20261022T165047.488565Z' not in body
    assert 'len(names)==33' in body
    assert 'sudo /usr/bin/python3 -I -B "$helper"' not in body
    assert body.count('sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper"') == 4
    assert '--all-writable --list-workspaces' in body
    replan = body.index('# All roots must retain their exact plans')
    apply = body.index('  apply_started=1', replan)
    assert '"${plan_shas[index]}"' in body[replan:apply]
    assert body.index('plan_shas=()') < body.index('sudo /usr/bin/systemctl stop "$unit"') < replan < apply
    final = body.split('done\nsudo /usr/bin/systemctl start "$unit"', 1)[1]
    assert final.index('healthy_development') < final.index('"$default_launcher_sha"') < final.index('"$discovery_installer_sha"')


def test_continuation_checks_final_pins():
    body = SCRIPT.read_text()
    for key, name in [('defaults_sha', 'repair-a7dev-shared-directory-defaults.py'),
                      ('default_launcher_sha', 'repair-a7dev-shared-directory-defaults.sh'),
                      ('discovery_installer_sha', 'install-a7dev-autodiscovery.sh')]:
        digest = re.search(r'^' + key + '=([0-9a-f]{64})$', body, re.MULTILINE).group(1)
        assert hashlib.sha256(SCRIPT.with_name(name).read_bytes()).hexdigest() == digest
    helper = re.search(r'^helper_sha=([0-9a-f]{64})$', body, re.MULTILINE)
    assert helper is not None, 'Continuation requires the reviewed helper SHA256'
    assert hashlib.sha256(SCRIPT.with_name('repair-a7dev-service-directory-access.py').read_bytes()).hexdigest() == helper.group(1)


def test_verified_child_failures_are_short_and_do_not_reprint_body(tmp_path):
    source = tmp_path / 'child.sh'
    body = b'# PRIVATE_FIXTURE_DO_NOT_REPEAT\nexit 31\n'
    source.write_bytes(body)
    result = subprocess.run(['/bin/bash', '-c', 'source "$LAUNCHER"; run_verified_child "$CHILD" "$SHA"'],
        capture_output=True, text=True, env={**os.environ, 'LAUNCHER': str(SCRIPT),
            'CHILD': str(source), 'SHA': hashlib.sha256(body).hexdigest()})
    assert result.returncode == 31
    assert 'exit 31' in result.stderr and 'PRIVATE_FIXTURE_DO_NOT_REPEAT' not in result.stderr
    assert 'CalledProcessError' not in result.stderr
