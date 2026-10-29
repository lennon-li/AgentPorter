"""Owner grant lifecycle must restart unchanged service after preapply failure only."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

import pytest


SCRIPT = Path(__file__).parents[2] / 'scripts/enable-a7dev-workspace-writes.sh'


@pytest.mark.parametrize('apply_started,config_same,release_same,restarts', [
    (0, 1, 1, True), (0, 0, 1, False), (0, 1, 0, False), (1, 1, 1, False), (1, 0, 1, False)])
def test_failure_recovery_uses_config_identity_and_apply_boundary(tmp_path, apply_started, config_same, release_same, restarts):
    log = tmp_path / 'commands'
    # Source exposes functions without executing setup, sudo, or live services.
    body = r'''
source "$LAUNCHER"
set +e
stopped_by_launcher=1
apply_started="$APPLY_STARTED"
timer_was_active=1
timer_stopped=1
quiet_stopped() { return 0; }
config_matches_before() { [[ "$CONFIG_SAME" == 1 ]]; }
readlink() { if [[ "$RELEASE_SAME" == 1 ]]; then printf '%s\n' "$live"; else printf '/changed-release\n'; fi; }
sudo() { printf '%s\n' "$*" >> "$COMMAND_LOG"; return 0; }
(exit 17)
grant_failed
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'COMMAND_LOG': str(log),
                                 'APPLY_STARTED': str(apply_started), 'CONFIG_SAME': str(config_same),
                                 'RELEASE_SAME': str(release_same)})
    assert result.returncode == 17
    commands = log.read_text() if log.exists() else ''
    assert ('systemctl start agentporter-development.service' in commands) is restarts
    assert ('systemctl start agentporter-dev-autodiscovery.timer' in commands) is restarts
    assert 'agentporter.service' not in commands
    if apply_started:
        assert 'no partial apply is assumed restored' in result.stderr
    elif restarts:
        assert 'Unchanged A7Dev restarted' in result.stderr


def test_launcher_source_pin_matches_current_reviewed_authorizer():
    source = SCRIPT.read_text()
    expected = re.search(r'^helper_sha=([0-9a-f]{64})$', source, re.MULTILINE).group(1)
    helper = SCRIPT.with_name('authorize-a7dev-writable-delegation.py')
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == expected
    subprocess.run(['/bin/bash', '-n', str(SCRIPT)], check=True)


@pytest.mark.parametrize('matches', [True, False])
@pytest.mark.parametrize('existing', [True, False])
def test_unverified_source_is_private_until_digest_matches(tmp_path, matches, existing):
    source, destination = tmp_path / 'source', tmp_path / 'published'
    source.write_bytes(b'approved helper' if matches else b'synthetic private data')
    if existing:
        destination.write_bytes(b'previous reviewed helper')
    stage = tmp_path / 'staging'
    stage.mkdir()
    body = r'''
source "$LAUNCHER"
helper_dir="$STAGE_ROOT"
sudo() { "$@"; }
publish_pinned "$SOURCE" "$DESTINATION" "$DIGEST"
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'STAGE_ROOT': str(stage),
                                 'SOURCE': str(source), 'DESTINATION': str(destination),
                                 'DIGEST': hashlib.sha256(b'approved helper').hexdigest()})
    if matches:
        assert result.returncode == 0, result.stderr
        assert destination.read_bytes() == b'approved helper'
        assert destination.stat().st_mode & 0o777 == 0o555
        assert not list(stage.iterdir())
    else:
        assert result.returncode != 0
        if existing:
            assert destination.read_bytes() == b'previous reviewed helper'
        else:
            assert not destination.exists()
        private = list(stage.iterdir())
        assert len(private) == 1 and private[0].stat().st_mode & 0o777 == 0o700
        assert (private[0] / 'input').stat().st_mode & 0o777 == 0o600
        assert b'synthetic private data' not in result.stdout.encode() + result.stderr.encode()


@pytest.mark.parametrize('unsafe', ['symlink', 'fifo', 'oversized'])
def test_private_staging_rejects_unsafe_source_before_privileged_publication(tmp_path, unsafe):
    source, destination = tmp_path / 'source', tmp_path / 'published'
    if unsafe == 'fifo':
        os.mkfifo(source)
    elif unsafe == 'oversized':
        source.write_bytes(b'x' * 131073)
    else:
        source.symlink_to(tmp_path / 'missing')
    stage = tmp_path / 'staging'
    stage.mkdir()
    result = subprocess.run(['/bin/bash', '-c', r'''
source "$LAUNCHER"
helper_dir="$STAGE_ROOT"
sudo() { "$@"; }
publish_pinned "$SOURCE" "$DESTINATION" "$DIGEST"
'''], capture_output=True, text=True, timeout=5,
        env={**os.environ, 'LAUNCHER': str(SCRIPT), 'STAGE_ROOT': str(stage),
             'SOURCE': str(source), 'DESTINATION': str(destination),
             'DIGEST': hashlib.sha256(b'approved').hexdigest()})
    assert result.returncode != 0 and not destination.exists()


@pytest.mark.parametrize('timer_state,reconciler_state,accepted,restart', [
    ('active', 'inactive', True, True), ('inactive', 'inactive', True, False),
    ('active', 'active', False, False), ('active', 'activating', False, False),
    ('active', 'deactivating', False, False), ('unknown', 'inactive', False, False)])
def test_discovery_timer_is_drained_before_grants(tmp_path, timer_state, reconciler_state, accepted, restart):
    log = tmp_path / 'commands'
    body = r'''
source "$LAUNCHER"
set +e
sudo() {
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  if [[ "$*" == *show* ]]; then
    if [[ "$*" == *autodiscovery.timer ]]; then printf '%s\n' "$TIMER_STATE";
    else printf '%s\n' "$RECONCILER_STATE"; fi
  fi
}
pause_discovery
code=$?
if [[ "$code" == 0 ]]; then restore_discovery_timer; fi
exit "$code"
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
                            env={**os.environ, 'LAUNCHER': str(SCRIPT), 'COMMAND_LOG': str(log),
                                 'TIMER_STATE': timer_state, 'RECONCILER_STATE': reconciler_state})
    assert (result.returncode == 0) is accepted
    commands = log.read_text()
    assert ('systemctl start agentporter-dev-autodiscovery.timer' in commands) is restart
    assert 'agentporter-development.service' not in commands
    if timer_state != 'unknown':
        assert commands.index('systemctl stop agentporter-dev-autodiscovery.timer') < commands.index('--property=ActiveState agentporter-dev-autodiscovery.service')


def test_launcher_pauses_timer_before_first_scope_plan():
    body = SCRIPT.read_text().split('sudo -v\n', 1)[1]
    assert body.index('pause_discovery') < body.index('plan=$(sudo ')


def test_launcher_admits_only_reviewed_releases_and_uses_selected_storage():
    body = SCRIPT.read_text().split('live=$(readlink -f /opt/agentporter-development/current)', 1)[1]
    assert '20261022T165047.488565Z|/opt/agentporter-development/versions/20261022T181133.685266Z)' in body
    assert 'storage_source="$live/operator-plan/authorize-a7dev-project-delegation.py"' in body
    assert body.index('*) echo') < body.index('storage_source=') < body.index('sha256sum --check')
