"""Bounded pipe collection must not exhaust memory before truncating."""

import sys
from pathlib import Path

import pytest

from agentporter.sandbox.bubblewrap import BubblewrapSandbox


@pytest.fixture
def collector(tmp_path, monkeypatch):
    # Exercise the real bounded Popen/selector collector independently of
    # Bubblewrap support on the test host. The stub only execs the command
    # occurring after "--"; no auth, sandbox, Git, or network side effects.
    launcher = tmp_path / "fake-bwrap.py"
    launcher.write_text(
        "import os, sys\n"
        "index = sys.argv.index('--')\n"
        "os.execvp(sys.argv[index + 1], sys.argv[index + 1:])\n"
    )
    sandbox = BubblewrapSandbox(tmp_path / "state", max_output_bytes=2048)
    monkeypatch.setattr(
        sandbox, "build_bwrap_args",
        lambda *args, **kwargs: [sys.executable, "-B", str(launcher)],
    )
    return sandbox, tmp_path


def test_short_output_remains_unchanged(collector):
    sandbox, workspace = collector
    result = sandbox.run(
        str(workspace),
        [sys.executable, "-B", "-c", "import sys; print('ok');print('warn',file=sys.stderr)"],
        timeout_seconds=5,
    )
    assert result["exit_code"] == 0
    assert result["stdout"] == "ok\n"
    assert result["stderr"] == "warn\n"
    assert result["truncated"] is False
    assert result["timed_out"] is False


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_noisy_stream_is_killed_at_bounded_byte_limit(collector, stream):
    sandbox, workspace = collector
    code = (
        f"import sys\n"
        f"stream=sys.{stream}\n"
        "while True:\n"
        "    stream.write('z' * 8192)\n"
        "    stream.flush()\n"
    )
    result = sandbox.run(
        str(workspace), [sys.executable, "-B", "-c", code],
        timeout_seconds=8, max_output_bytes=2048,
    )
    assert result["exit_code"] == 125, result
    assert result["truncated"] is True
    assert result["timed_out"] is False
    assert result["duration"] < 7
    assert "PROCESS KILLED AT OUTPUT LIMIT" in result[stream]
    assert len(result[stream].encode("utf-8")) < 2300


def test_timeout_kills_quiet_process_group(collector):
    sandbox, workspace = collector
    result = sandbox.run(
        str(workspace),
        [sys.executable, "-B", "-c", "import time;time.sleep(20)"],
        timeout_seconds=1,
    )
    assert result["exit_code"] == 124
    assert result["timed_out"] is True
    assert result["truncated"] is True
    assert "TIMEOUT" in result["stderr"]
    assert result["duration"] < 5


def test_multibyte_output_limit_uses_bytes_not_characters(collector):
    sandbox, workspace = collector
    result = sandbox.run(
        str(workspace),
        [sys.executable, "-B", "-c", "import sys\nwhile True:\n sys.stdout.write('☃'*2000)\n sys.stdout.flush()\n"],
        timeout_seconds=8,
    )
    assert result["exit_code"] == 125
    assert result["truncated"]
    assert "TRUNCATED" in result["stdout"]
    assert len(result["stdout"].encode("utf-8")) < 2400
