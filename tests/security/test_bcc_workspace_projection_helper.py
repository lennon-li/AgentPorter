import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/bcc-workspace-projection.py'


def test_plan_rejects_outside_source_without_creating_state(tmp_path):
    result = subprocess.run([sys.executable, '-I', '-S', str(SCRIPT), '--source', str(tmp_path)], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'canonical directory inside BCC repositories' in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_bcc_plan_is_read_only():
    try:
        owner = pwd.getpwnam('yeli')
    except KeyError:
        pytest.skip('BCC account database required')
    if owner.pw_uid != 2056259175:
        pytest.skip('BCC identity required')
    source = SCRIPT.parents[1]
    result = subprocess.run([sys.executable, '-I', '-S', str(SCRIPT), '--source', str(source)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['action'] == 'PLAN_ONLY'
    assert plan['read_only'] is True
    assert plan['source'] == str(source)
    assert plan['worker_uid'] == 997


def test_apply_requires_owner_sudo_before_any_provisioning():
    if os.getuid() == 0:
        pytest.skip('Unprivileged refusal test')
    try:
        pwd.getpwnam('agentporter-bcc-worker')
    except KeyError:
        pytest.skip('BCC account database required')
    result = subprocess.run([sys.executable, '-I', '-S', str(SCRIPT), '--source', str(SCRIPT.parents[1]), '--apply'], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'requires owner sudo authentication' in result.stderr
