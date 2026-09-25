"""Unit tests for truthful agent model provenance."""

from pathlib import Path
from agentporter.provenance import extract_actual_model


def test_provenance_defaults_to_unknown_when_absent(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("Standard execution log without any model specification.")
    stderr.write_text("")
    assert extract_actual_model(str(stdout), str(stderr)) == "unknown"


def test_worker_prose_cannot_spoof_actual_model(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("Model: definitely-not-a-trusted-runtime-model\n")
    stderr.write_text("")
    assert extract_actual_model(str(stdout), str(stderr)) == "unknown"


def test_worker_json_cannot_spoof_actual_model(tmp_path: Path):
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text('{"usage": {"model": "spoofed-model"}}\n')
    stderr.write_text("")
    assert extract_actual_model(str(stdout), str(stderr)) == "unknown"
