"""Frozen activation child bytes and failure recovery, without live operations."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

import pytest


SCRIPT = Path(__file__).parents[2] / 'scripts/activate-a7dev-workspace-writes.sh'


@pytest.mark.parametrize('installed,release_same,gate_ok,restart_ok,restart,timer', [
    (0, 1, 1, 1, True, True), (0, 1, 1, 0, True, False),
    (1, 1, 1, 1, False, False), (0, 0, 1, 1, False, False),
    (0, 1, 0, 1, False, False)])
def test_recovery_never_restarts_timer_over_partial_or_unhealthy_install(tmp_path, installed, release_same, gate_ok, restart_ok, restart, timer):
    log = tmp_path / 'commands'
    body = r'''
source "$LAUNCHER"
set +e
stopped_by_launcher=1
install_started="$INSTALLED"
discovery_was_active=1
readlink() { if [[ "$RELEASE_SAME" == 1 ]]; then printf '%s\n' "$old"; else printf /changed; fi; }
development_is_active() { [[ "$RESTART_OK" == 1 ]]; }
sudo() {
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  if [[ "$*" == *runtime-install-gate.py* ]]; then [[ "$GATE_OK" == 1 ]];
  elif [[ "$*" == *'systemctl start agentporter-development.service' ]]; then [[ "$RESTART_OK" == 1 ]];
  else return 0; fi
}
(exit 19)
activation_failed
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'COMMAND_LOG': str(log),
                                 'INSTALLED': str(installed), 'RELEASE_SAME': str(release_same),
                                 'GATE_OK': str(gate_ok), 'RESTART_OK': str(restart_ok)})
    assert result.returncode == 19
    commands = log.read_text() if log.exists() else ''
    assert ('systemctl start agentporter-development.service' in commands) is restart
    assert ('systemctl start agentporter-dev-autodiscovery.timer' in commands) is timer
    assert 'agentporter.service' not in commands


@pytest.mark.parametrize('mode', ['valid', 'mismatch', 'symlink', 'fifo', 'check_only', 'emit'])
def test_children_require_pinned_regular_source_and_execute_only_checked_bytes(tmp_path, mode):
    source, marker = tmp_path / 'child.sh', tmp_path / 'marker'
    approved = b'printf "approved" > "$MARKER"\n'
    source.write_bytes(approved)
    digest = hashlib.sha256(approved).hexdigest()
    if mode == 'mismatch':
        source.write_bytes(b'printf "unreviewed" > "$MARKER"\n')
    elif mode == 'symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(source)
        source = alias
    elif mode == 'fifo':
        source.unlink()
        os.mkfifo(source)
    body = r'''
source "$LAUNCHER"
run_verified_child "$CHILD" "$DIGEST" "$MODE"
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True, timeout=5,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'CHILD': str(source),
                                 'DIGEST': digest, 'MARKER': str(marker),
                                 'MODE': {'check_only': '--check', 'emit': '--emit'}.get(mode, '--run')})
    assert (result.returncode == 0) is (mode in ('valid', 'check_only', 'emit'))
    if mode == 'valid':
        assert marker.read_text() == 'approved'
    else:
        assert not marker.exists()
    if mode == 'emit':
        assert result.stdout.encode() == approved


def test_child_pins_and_early_verification_match_reviewed_scripts():
    body = SCRIPT.read_text()
    for key, name in [('grant_launcher_sha', 'enable-a7dev-workspace-writes.sh'),
                      ('discovery_installer_sha', 'install-a7dev-autodiscovery.sh'),
                      ('directory_repair_launcher_sha', 'repair-a7dev-shared-directory-defaults.sh')]:
        digest = re.search(r'^' + key + r'=([0-9a-f]{64})$', body, re.MULTILINE).group(1)
        assert hashlib.sha256(SCRIPT.with_name(name).read_bytes()).hexdigest() == digest
    assert body.index('"$grant_launcher_sha" --check') < body.index('sudo -v')
    assert body.index('"$discovery_installer_sha" --check') < body.index('sudo -v')
    assert body.index('"$directory_repair_launcher_sha" --check') < body.index('sudo -v')
    run = body.split("echo 'Default-ACL core installed", 1)[1]
    assert run.index('"$grant_launcher_sha"') < run.index('"$directory_repair_launcher_sha"') < run.index('"$discovery_installer_sha"')


def test_failed_verified_child_does_not_print_its_entire_script(tmp_path):
    source = tmp_path / 'child.sh'
    private_marker = 'DO_NOT_REPRINT_ENTIRE_CHILD_BODY'
    body = ('# ' + private_marker + '\nexit 27\n').encode()
    source.write_bytes(body)
    result = subprocess.run(['/bin/bash', '-c', 'source "$LAUNCHER"; run_verified_child "$CHILD" "$SHA"'],
        capture_output=True, text=True, env={**os.environ, 'LAUNCHER': str(SCRIPT),
            'CHILD': str(source), 'SHA': hashlib.sha256(body).hexdigest()})
    assert result.returncode == 27
    assert 'exit 27' in result.stderr and private_marker not in result.stderr
    assert 'CalledProcessError' not in result.stderr


def test_failed_verified_child_inherits_error_handler(tmp_path):
    child, marker = tmp_path / 'child', tmp_path / 'caught'
    child.write_text('unreviewed')
    body = r'''
source "$LAUNCHER"
trap 'printf caught > "$MARKER"' ERR
run_verified_child "$CHILD" "$DIGEST" --check
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'CHILD': str(child),
                                 'DIGEST': '0' * 64, 'MARKER': str(marker)}, timeout=5)
    assert result.returncode != 0
    assert marker.read_text() == 'caught'
