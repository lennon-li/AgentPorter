"""Development activation failure gates without live sudo or systemd calls."""
import os
from pathlib import Path
import re
import subprocess

import pytest

SCRIPT = Path(__file__).parents[2] / 'scripts/activate-a7dev-cranary-source-repair.sh'


@pytest.mark.parametrize('installed,stopped,same,gate,healthy,restart,timer', [
    (0, 1, 1, 1, 1, True, True), (0, 1, 1, 1, 0, True, False),
    (1, 1, 1, 1, 1, False, False), (0, 1, 0, 1, 1, False, False),
    (0, 1, 1, 0, 1, False, False), (0, 0, 1, 1, 1, False, True)])
def test_recovery_restarts_only_proven_unchanged_preinstall_state(tmp_path, installed, stopped,
    same, gate, healthy, restart, timer):
    log = tmp_path / 'commands'
    body = r'''
source "$LAUNCHER"
set +e
install_started="$INSTALLED"; stopped_by_launcher="$STOPPED"
timer_stopped=1; timer_was_active=1
readlink() { if [[ "$SAME" == 1 ]]; then printf '%s\n' "$old"; else printf '/changed\n'; fi; }
run_gate() { [[ "$GATE" == 1 ]]; }
quiet_jobs() { return 0; }
healthy_development() { [[ "$HEALTHY" == 1 ]]; }
sudo() { printf '%s\n' "$*" >> "$COMMAND_LOG"; return 0; }
(exit 29)
activation_failed
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
        env={**os.environ, 'LAUNCHER': str(SCRIPT), 'COMMAND_LOG': str(log),
            'INSTALLED': str(installed), 'STOPPED': str(stopped), 'SAME': str(same),
            'GATE': str(gate), 'HEALTHY': str(healthy)})
    assert result.returncode == 29
    commands = log.read_text() if log.exists() else ''
    assert ('start agentporter-development.service' in commands) is restart
    assert ('start agentporter-dev-autodiscovery.timer' in commands) is timer
    assert 'agentporter.service' not in commands


def test_install_and_policy_change_stay_between_stop_and_start():
    body = SCRIPT.read_text().split('trap activation_failed ERR', 1)[1]
    stop = body.index('sudo /usr/bin/systemctl stop "$unit"')
    installed = body.index('install_started=1')
    install = body.index('"$installer" --artifact')
    policy = body.index('"$policy_helper" --apply')
    start = body.index('sudo /usr/bin/systemctl start "$unit"')
    assert stop < installed < install < policy < start
    assert body.count('run_gate') >= 2
    assert body.index('pause_discovery') < stop
    assert body.index('quiet_jobs') < stop
    assert body.index('healthy_development', start) < body.index('restore_timer', start)
    assert '--activate' not in body and '--skip' not in body


def test_root_and_placeholder_runs_refuse_before_privileged_actions(tmp_path):
    fake = tmp_path / 'bin'; fake.mkdir()
    sudo = fake / 'sudo'; sudo.write_text('#!/bin/sh\nexit 99\n'); sudo.chmod(0o700)
    identity = fake / 'id'; identity.write_text('#!/bin/sh\nprintf "root\\n"\n'); identity.chmod(0o700)
    result = subprocess.run(['/bin/bash', str(SCRIPT)], capture_output=True, text=True,
        env={**os.environ, 'PATH': str(fake) + ':' + os.environ['PATH']})
    assert result.returncode != 99


@pytest.mark.parametrize('key,value', [('artifact_sha', 'unprepared'),
    ('policy_sha', 'bad'), ('new', '/opt/agentporter-development/versions/not-reviewed')])
def test_invalid_final_pins_refuse_before_sudo(tmp_path, key, value):
    fake = tmp_path / 'bin'; fake.mkdir()
    identity = fake / 'id'; identity.write_text('#!/bin/sh\nprintf "yeli\\n"\n'); identity.chmod(0o700)
    sudo = fake / 'sudo'; sudo.write_text('#!/bin/sh\nexit 99\n'); sudo.chmod(0o700)
    text, count = re.subn(r'^' + key + r'=.*$', key + '=' + value, SCRIPT.read_text(), flags=re.MULTILINE)
    assert count == 1
    script = tmp_path / 'candidate.sh'; script.write_text(text)
    result = subprocess.run(['/bin/bash', str(script)], capture_output=True, text=True,
        env={**os.environ, 'PATH': str(fake) + ':' + os.environ['PATH']})
    assert result.returncode == 1 and 'pins are not finalized' in result.stderr
