from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from agentporter.tools import scinet_training as training
from agentporter.tools.scinet_training import REMOTE_SETUP_RUNNER, create_scinet_training_tool
from tests.unit.test_scinet_training import handoff, identity, registry, settings, stage_receipt


def ok(out=b"", code=0, **extra):
    return {"exit_code": code, "stdout": out, "stderr": b"", "timed_out": False,
            "truncated": False, **extra}


def staged_tool(tmp_path, cfg=None, **kw):
    root = handoff(tmp_path, **kw)
    wsreg = registry(root)
    cfg = cfg or settings()
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    patches = (patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))),
               patch.object(training, "_call"))
    ident, call = patches[0].__enter__(), patches[1].__enter__()
    call.side_effect = stage_receipt
    stage = tool["scinet_stage"]("cranary")
    call.reset_mock()
    call.side_effect = None
    return tool, call, stage, patches


def test_setup_uses_fixed_runner_and_only_ledger_hashes(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "running", "attempt": 1}).encode())
        result = tool["scinet_setup"]("cranary", stage["stage_id"])
        argv = call.call_args.args[2][-1]
        assert result["success"] is True and result["state"] == "running"
        assert stage["stage_id"] in argv and "REMOTE" not in argv
        assert call.call_args.kwargs["timeout"] <= 100
        assert call.call_args.args[2][:2] == ["/bin/bash", "-lc"]
        assert "scinet_login_setup.sh" in argv  # hash map only; never a caller path
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_setup_fails_closed_and_explains_duo_when_auth_missing(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        call.return_value = ok(code=None, error="scinet_auth_required")
        result = tool["scinet_setup"]("cranary", stage["stage_id"])
        assert result["success"] is False and result["error"] == "scinet_auth_required"
        assert "Duo" in result["human_action"]
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("bad", ["../etc", "A" * 32, "0" * 31, "x; rm -rf /", ""])
def test_setup_rejects_arbitrary_stage_ids(tmp_path, bad):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        for name in ("scinet_setup", "scinet_setup_status", "scinet_preflight"):
            with pytest.raises(ValueError):
                tool[name]("cranary", bad)
        call.assert_not_called()
        with pytest.raises(PermissionError):
            tool["scinet_setup"]("cranary", "0" * 32)
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_setup_failed_state_is_reported_and_retry_allowed(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "failed", "exit_code": 1}).encode())
        result = tool["scinet_setup_status"]("cranary", stage["stage_id"])
        assert result["success"] is False and result["error"].startswith("setup_failed")
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def run_runner(action, root, stage_id, files, py312="/bin/true"):
    return subprocess.run(
        [sys.executable, "-c", REMOTE_SETUP_RUNNER, action, str(root), stage_id, py312,
         json.dumps(files), "60"], capture_output=True, text=True, timeout=30)


def test_remote_runner_verifies_hash_runs_once_and_is_idempotent(tmp_path):
    stage_id = "a" * 32
    handoff_dir = tmp_path / "handoff" / stage_id
    handoff_dir.mkdir(parents=True)
    script = b"#!/bin/bash\nmkdir -p \"$CRANARY_SCRATCH/envs/laya-expA/bin\" \"$CRANARY_SCRATCH/pinned\"\n" \
             b"printf '#!/bin/sh\\n' > \"$CRANARY_SCRATCH/envs/laya-expA/bin/python\"\n" \
             b"chmod +x \"$CRANARY_SCRATCH/envs/laya-expA/bin/python\"; echo '{}' > \"$CRANARY_SCRATCH/pinned/pins.json\"\n" \
             b"echo ran-with-$PYTHON312\n"
    (handoff_dir / "scinet_login_setup.sh").write_bytes(script)
    files = {"scinet_login_setup.sh": hashlib.sha256(script).hexdigest()}
    first = run_runner("start", tmp_path, stage_id, files)
    assert first.returncode == 0, first.stderr
    for _ in range(40):
        status = json.loads(run_runner("status", tmp_path, stage_id, files).stdout)
        if status["state"] != "running":
            break
        time.sleep(0.25)
    assert status["state"] == "complete" and status["exit_code"] == 0
    assert "ran-with-/bin/true" in status["log_tail"]
    again = json.loads(run_runner("start", tmp_path, stage_id, files).stdout)
    assert again["state"] == "complete" and again["idempotent"] is True
    assert again["attempt"] == 1


def test_remote_runner_refuses_tampered_script_and_bad_stage(tmp_path):
    stage_id = "b" * 32
    handoff_dir = tmp_path / "handoff" / stage_id
    handoff_dir.mkdir(parents=True)
    (handoff_dir / "scinet_login_setup.sh").write_bytes(b"echo evil\n")
    files = {"scinet_login_setup.sh": hashlib.sha256(b"echo good\n").hexdigest()}
    refused = run_runner("start", tmp_path, stage_id, files)
    assert refused.returncode == 65 and "staged_file_hash_mismatch" in refused.stdout
    assert not (tmp_path / "runs").exists()
    assert run_runner("start", tmp_path, "../" + "c" * 29, files).returncode == 64
    (handoff_dir / "scinet_login_setup.sh").unlink()
    (handoff_dir / "target").write_bytes(b"x")
    os.symlink(handoff_dir / "target", handoff_dir / "scinet_login_setup.sh")
    assert run_runner("start", tmp_path, stage_id, files).returncode == 65


def preflight_text(codes, pins):
    text = ""
    for name, code in codes.items():
        text += f"@@BEGIN {name}\nout\n@@END {name} {code}\n"
    return (text + "@@BEGIN pins\n" + json.dumps(pins) + "\n@@END pins 0\n").encode()


def test_preflight_reports_missing_approvals_and_never_ready(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        pins = {"pins_sha256": "ab" * 32, "pins": {"compute_approved_by": None}}
        call.return_value = ok(preflight_text(
            {"verify-bundle": 0, "gate-expA": 1, "gate-expB-smoke": 1}, pins))
        result = tool["scinet_preflight"]("cranary", stage["stage_id"])
        assert result["success"] is True and result["ready"] is False
        assert result["approvals"]["smoke_approved_by"]["recorded"] is False
        assert any("never writes" in step for step in result["human_approval_steps"])
        assert call.call_count == 1
        assert "sbatch" not in call.call_args.args[2][-1]
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_preflight_ready_only_with_all_gates_and_human_approvals(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        approvals = {k: "dr-human" for k in training.APPROVAL_FIELDS["laya_smoke"]}
        gates = {"verify-bundle": 0, "gate-expA": 0, "gate-expB-smoke": 0}
        call.return_value = ok(preflight_text(gates, {"pins_sha256": "ab" * 32, "pins": approvals}))
        assert tool["scinet_preflight"]("cranary", stage["stage_id"])["ready"] is True
        approvals["smoke_approved_by"] = "Copilot-agent"
        call.return_value = ok(preflight_text(gates, {"pins_sha256": "ab" * 32, "pins": approvals}))
        result = tool["scinet_preflight"]("cranary", stage["stage_id"])
        assert result["ready"] is False
        assert result["approvals"]["smoke_approved_by"]["suspect_agent_identity"] is True
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_full_runs_disabled_by_default_and_expb_cannot_self_approve(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        for experiment in ("laya_expA", "laya_expB"):
            with pytest.raises(PermissionError, match="not enabled"):
                tool["scinet_submit"]("cranary", stage["stage_id"], experiment)
        with pytest.raises(ValueError):
            tool["scinet_submit"]("cranary", stage["stage_id"], "laya_expC")
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_full_run_bounded_template_and_no_duplicate_submission(tmp_path):
    cfg = settings()
    cfg.training_allow_full_runs, cfg.training_full_walltime = True, "03:00:00"
    root = handoff(tmp_path)
    template = (b"#!/bin/bash\n#SBATCH --account=@SLURM_ACCOUNT@\n#SBATCH --time=@WALLTIME_HH_MM_SS@\n"
                b"#SBATCH --nodes=1\n#SBATCH --gpus-per-node=1\n#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
                b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n")
    (root / "laya_expA.sbatch.template").write_bytes(template)
    sums = (root / "SHA256SUMS").read_text() + f"{hashlib.sha256(template).hexdigest()}  laya_expA.sbatch.template\n"
    (root / "SHA256SUMS").write_text(sums)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        stage = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = [ok(), ok(b"ok"), ok(b"777")]
        result = tool["scinet_submit"]("cranary", stage["stage_id"], "laya_expA")
        assert result["success"] and result["resources"] == {
            "gpus": 1, "walltime": "03:00:00", "account": "def-cranary", "partition": "gpu"}
        rendered = call.call_args_list[1].kwargs["input_bytes"]
        assert b"#SBATCH --time=03:00:00" in rendered and b"@" not in rendered.replace(b"%x", b"")
        gate_cmd = call.call_args_list[0].args[2][-1]
        assert "laya_expA_trainer.py gate" in gate_cmd and "laya_expB_lora.py" not in gate_cmd
        call.reset_mock()
        again = tool["scinet_submit"]("cranary", stage["stage_id"], "laya_expA")
        assert again["error"] == "already_submitted" and again["job_id"] == "777"
        call.assert_not_called()
        call.side_effect = [ok(json.dumps({"files": []}).encode())]
        tool["scinet_job_logs"]("cranary", "777", "all")
        assert call.call_args.args[2][-1].endswith("laya-expA")


def test_config_rejects_bad_full_walltime(tmp_path):
    from agentporter.config import Config
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "config.yaml").write_text("scinet:\n  training_full_walltime: '99:00:00'\n")
    with pytest.raises(ValueError, match="walltime"):
        Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "st")
