"""Exercise failure recovery without root, service operations or credentials."""
from pathlib import Path
import subprocess

import pytest


LAUNCHER = Path(__file__).resolve().parents[2] / 'scripts/activate-a7dev-shared-access-repair.sh'


@pytest.mark.parametrize('install_started,release_ok,runtime_ok,restarts', [
    (0, True, True, True),
    (1, True, True, False),
    (0, False, True, False),
    (0, True, False, False),
])
def test_failure_restarts_only_unchanged_preinstall_pair(
        tmp_path, install_started, release_ok, runtime_ok, restarts):
    log = tmp_path / 'calls'
    script = r'''
source "$1"
set +e
stopped_by_launcher=1
install_started="$2"
readlink() {
  printf '%s\n' "$MOCK_RELEASE"
}
sudo() {
  printf '%s\n' "$*" >> "$MOCK_LOG"
  if [[ "$1" == -u ]]; then return "$MOCK_RUNTIME_STATUS"; fi
  return 0
}
false
activation_failed
'''
    # readlink's real arguments contain no test parameters; use environment
    # state so the mocks never invoke actual system binaries.
    import os
    env = dict(os.environ, MOCK_LOG=str(log),
               MOCK_RELEASE='/opt/agentporter-development/versions/' + (
                   '20261022T015212.581522Z' if release_ok else 'unexpected'),
               MOCK_RUNTIME_STATUS='0' if runtime_ok else '1')
    result = subprocess.run(['bash', '-c', script, 'recovery-test', str(LAUNCHER), str(install_started)],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 1
    calls = log.read_text() if log.exists() else ''
    assert ('/usr/bin/systemctl start agentporter-development.service' in calls) is restarts
    assert '/usr/bin/systemctl stop' not in calls
    assert '--artifact' not in calls
    assert 'agentporter.service' not in calls
