"""Unit tests for agent model provenance extraction."""

from pathlib import Path
from agentporter.provenance import extract_actual_model


def test_provenance_defaults_to_unknown_when_absent(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("Standard execution log without any model specification.")
    stderr.write_text("")

    assert extract_actual_model(str(stdout), str(stderr)) == "unknown"


def test_provenance_extracts_explicit_model(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("Initializing session...\nModel: gpt-5.6-luna\nReady.")
    stderr.write_text("")

    assert extract_actual_model(str(stdout), str(stderr)) == "gpt-5.6-luna"


def test_provenance_extracts_json_model(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text('{"status": "ok", "usage": {"model": "claude-3-7-sonnet"}}\n')
    stderr.write_text("")

    assert extract_actual_model(str(stdout), str(stderr)) == "claude-3-7-sonnet"
