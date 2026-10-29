"""Owner deployment guards recognize recovered jobs, never active finalization."""
from pathlib import Path
import subprocess
import sys
import pytest
from agentporter.tools.jobs import JobManager


@pytest.mark.parametrize('status, allowed', [('recovered', True), ('finalizing', False), ('cleanup_failed', False)])
def test_update_guard_terminal_states(tmp_path, status, allowed):
    manager = JobManager(tmp_path / 'state')
    db = manager._get_db()
    try:
        with db:
            db.execute('INSERT INTO jobs (job_id,status,created_at) VALUES (?,?,0)', ('job_guard', status))
    finally:
        db.close()
    source = (Path(__file__).parents[2] / 'scripts/bcc-stage-update.py.in').read_text()
    program = source.split("GUARD_PROGRAM = r'''", 1)[1].split("'''", 1)[0]
    result = subprocess.run([sys.executable, '-I', '-c', program, str(manager.db_path), 'install', '1' * 32],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    assert (result.returncode == 0) is allowed, result.stderr
