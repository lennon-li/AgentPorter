"""Directory-default operator launcher gates; synthetic commands/files only."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

import pytest


SCRIPT = Path(__file__).parents[2] / 'scripts/repair-a7dev-shared-directory-defaults.sh'


@pytest.mark.parametrize('stopped,applied,same_release,same_config,quiet,restart_ok,restart,timer', [
    (0, 0, 1, 1, 1, 1, False, True),  # Failed active preflight keeps service active.
    (1, 0, 1, 1, 1, 1, True, True),
    (1, 0, 1, 1, 1, 0, True, False),
    (1, 0, 1, 1, 0, 1, False, False),
    (1, 0, 0, 1, 1, 1, False, False),
    (1, 0, 1, 0, 1, 1, False, False),
    (1, 1, 1, 1, 1, 1, False, False),
])
def test_only_proven_unchanged_preapply_failure_can_resume_services(tmp_path, stopped, applied, same_release, same_config, quiet, restart_ok, restart, timer):
    log = tmp_path / 'commands'
    body = r'''
source "$LAUNCHER"
set +e
stopped_by_launcher="$STOPPED"
apply_started="$APPLIED"
timer_stopped=1
timer_was_active=1
readlink() { if [[ "$SAME_RELEASE" == 1 ]]; then printf '%s\n' "$live"; else printf /changed; fi; }
config_matches_before() { [[ "$SAME_CONFIG" == 1 ]]; }
quiet_stopped() { [[ "$QUIET" == 1 ]]; }
quiet_jobs() { [[ "$QUIET" == 1 ]]; }
development_is_active() { return 0; }
healthy_development() { [[ "$RESTART_OK" == 1 ]]; }
sudo() {
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  if [[ "$*" == *'start agentporter-development.service' ]]; then [[ "$RESTART_OK" == 1 ]];
  else return 0; fi
}
(exit 23)
repair_failed
'''
    result = subprocess.run(['/bin/bash', '-c', body], capture_output=True, text=True,
        env={**os.environ, 'LAUNCHER': str(SCRIPT), 'COMMAND_LOG': str(log),
             'STOPPED': str(stopped), 'APPLIED': str(applied), 'SAME_RELEASE': str(same_release),
             'SAME_CONFIG': str(same_config), 'QUIET': str(quiet), 'RESTART_OK': str(restart_ok)})
    assert result.returncode == 23
    commands = log.read_text() if log.exists() else ''
    assert ('start agentporter-development.service' in commands) is restart
    assert ('start agentporter-dev-autodiscovery.timer' in commands) is timer
    assert 'agentporter.service' not in commands
    if applied:
        assert 'No automatic rollback or recovery is assumed' in result.stderr


@pytest.mark.parametrize('mode', ['valid', 'mismatch', 'symlink', 'fifo', 'oversized'])
def test_root_helper_source_is_bounded_and_private_until_verified(tmp_path, mode):
    source, target, staging = tmp_path / 'source', tmp_path / 'public', tmp_path / 'staging'
    staging.mkdir()
    approved = b'approved inert fixture'
    source.write_bytes(approved)
    if mode == 'mismatch': source.write_bytes(b'synthetic private content')
    elif mode == 'oversized': source.write_bytes(b'x' * 131073)
    elif mode == 'fifo':
        source.unlink(); os.mkfifo(source)
    elif mode == 'symlink':
        link = tmp_path / 'link'; link.symlink_to(source); source = link
    result = subprocess.run(['/bin/bash', '-c', r'''
source "$LAUNCHER"
helper_dir="$STAGING"
sudo() { "$@"; }
publish_pinned "$SOURCE" "$TARGET" "$SHA"
'''], capture_output=True, text=True, timeout=5,
        env={**os.environ, 'LAUNCHER': str(SCRIPT), 'STAGING': str(staging),
             'SOURCE': str(source), 'TARGET': str(target), 'SHA': hashlib.sha256(approved).hexdigest()})
    assert (result.returncode == 0) is (mode == 'valid')
    if mode == 'valid':
        assert target.read_bytes() == approved and target.stat().st_mode & 0o777 == 0o555
    else:
        assert not target.exists()
        assert all(path.stat().st_mode & 0o777 == 0o700 for path in staging.iterdir())
        assert 'synthetic private content' not in result.stdout + result.stderr


def test_all_workspace_plans_are_checked_before_first_mutation():
    body = SCRIPT.read_text()
    active_plan = body.index('plan_shas=()')
    stop = body.index('sudo /usr/bin/systemctl stop "$unit"')
    replan = body.index('# All roots must retain their exact plans')
    apply = body.index('  apply_started=1', replan)
    assert active_plan < stop < replan < apply
    assert 'for index in "${!workspaces[@]}"' in body[replan:apply]
    assert '"${plan_shas[index]}"' in body[replan:apply]
    assert '--all-writable --list-workspaces' in body and '--all-writable' not in body[active_plan:]
    assert body.index('before_hashes=$(configuration_hashes)') < body.index('inventory=$(sudo ')
    assert body.index('pause_discovery\n') < body.index('inventory=$(sudo ')


def test_final_root_helper_pin_matches_source():
    body = SCRIPT.read_text()
    match = re.search(r'^helper_sha=([0-9a-f]{64})$', body, re.MULTILINE)
    if match is None:
        assert 'helper_sha=HELPER_PENDING' in body
        pytest.skip('Helper worker has not frozen its reviewed final digest yet')
    assert hashlib.sha256(SCRIPT.with_suffix('.py').read_bytes()).hexdigest() == match.group(1)


@pytest.mark.parametrize('blockers,accepted', [(0, True), (1, False), (-1, False), (False, False)])
def test_existing_human_access_blockers_fail_preflight_without_mutation(blockers, accepted):
    import json
    result = subprocess.run(['/bin/bash', '-c', 'source "$LAUNCHER"; plan_digest'],
        capture_output=True, text=True, input=json.dumps({'plan_sha256': 'a' * 64,
                                                       'existing_human_access_blockers': blockers}),
        env={**os.environ, 'LAUNCHER': str(SCRIPT)})
    assert (result.returncode == 0) is accepted
