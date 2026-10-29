from __future__ import annotations

import hashlib
import json
import os
import shlex
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


FIELDS = training.APPROVAL_FIELDS["laya_smoke"]
GOOD = dict(reviewer="operator", confirmation="I approve all 5", approved_fields=list(FIELDS))


def run_recorder(pins, reviewer="operator", device="cuda", stage="a" * 32):
    proc = subprocess.run(
        [sys.executable, "-c", training.REMOTE_APPROVAL_RECORDER, str(pins), reviewer, device,
         json.dumps(FIELDS), stage, "cranary"], capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])


def write_pins(tmp_path, **kw):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"schema": 1, "device": None, **kw}))
    return path


def test_recorder_writes_only_approved_fields_with_audit_and_is_idempotent(tmp_path):
    pins = write_pins(tmp_path, weights_sha256="ff")
    code, out = run_recorder(pins)
    data = json.loads(pins.read_text())
    assert code == 0 and out["state"] == "recorded" and data["device"] == "cuda"
    assert all(data[f] == "operator" for f in FIELDS) and data["weights_sha256"] == "ff"
    assert out["pins_sha256_before"] != out["pins_sha256"]
    assert out["pins_sha256"] == hashlib.sha256(pins.read_bytes()).hexdigest()
    audit = [json.loads(x) for x in (tmp_path / "approvals.audit.jsonl").read_text().splitlines()]
    assert len(audit) == 1 and audit[0]["reviewer"] == "operator" and audit[0]["time"]
    code, again = run_recorder(pins)
    assert code == 0 and again["state"] == "unchanged" and again["idempotent"] is True
    assert len((tmp_path / "approvals.audit.jsonl").read_text().splitlines()) == 1


@pytest.mark.parametrize("existing", [{"compute_approved_by": "someone"}, {"device": "cpu"}])
def test_recorder_refuses_contradictory_existing_values(tmp_path, existing):
    pins = write_pins(tmp_path, **existing)
    before = pins.read_bytes()
    code, out = run_recorder(pins)
    assert code != 0 and out["error"] == "contradictory_existing_values"
    assert pins.read_bytes() == before and not (tmp_path / "approvals.audit.jsonl").exists()


def test_recorder_refuses_symlink_missing_and_bad_args(tmp_path):
    real = write_pins(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    assert run_recorder(link)[0] != 0
    assert run_recorder(tmp_path / "nope.json")[0] != 0
    assert run_recorder(real, device="cpu")[0] != 0
    assert run_recorder(real, reviewer="x;rm")[0] != 0
    assert run_recorder(real, stage="../x")[0] != 0
    assert json.loads(real.read_text())["device"] is None


def approval_tool(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    return tool, call, stage, patches


def test_record_approvals_success_updates_ledger_and_uses_fixed_runner(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        report = {"state": "recorded", "changed_fields": sorted(FIELDS), "pins_sha256": "ab" * 32,
                  "audit_time": "2026-10-12T00:00:00Z"}
        call.return_value = ok(json.dumps(report).encode())
        result = tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)
        assert result["success"] is True and result["state"] == "recorded"
        argv = call.call_args.args[2][-1]
        assert stage["stage_id"] in argv and "/pinned/pins.json" in argv and "operator" in argv
        assert call.call_args.args[2][:2] == ["/bin/bash", "-lc"]
        approvals = training._Ledger(tmp_path / "state").stage(stage["stage_id"])["approvals"]
        assert approvals[0]["reviewer"] == "operator" and approvals[0]["pins_sha256"] == "ab" * 32
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_approvals_idempotent_does_not_duplicate_ledger(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "unchanged", "idempotent": True}).encode())
        result = tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)
        assert result["success"] is True and result["idempotent"] is True
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(stage["stage_id"])
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("override,exc", [
    ({"confirmation": ""}, PermissionError),
    ({"confirmation": "i approve all 5"}, PermissionError),
    ({"confirmation": "I approve all 5 please"}, PermissionError),
    ({"reviewer": "Copilot-agent"}, PermissionError),
    ({"reviewer": "someone-else"}, PermissionError),
    ({"reviewer": "operator-bot"}, PermissionError),
    ({"approved_fields": ["smoke_approved_by"]}, ValueError),
    ({"approved_fields": list(FIELDS) + ["extra"]}, ValueError),
    ({"device": "cpu"}, ValueError),
    ({"experiment": "laya_expB"}, PermissionError),
    ({"experiment": "laya_expC"}, ValueError),
])
def test_record_approvals_rejects_bad_requests_without_remote_call(tmp_path, override, exc):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        with pytest.raises(exc):
            tool["scinet_record_approvals"]("cranary", stage["stage_id"], **{**GOOD, **override})
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_approvals_rejects_unrelated_or_malformed_stage(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        with pytest.raises(PermissionError):
            tool["scinet_record_approvals"]("cranary", "0" * 32, **GOOD)
        with pytest.raises(ValueError):
            tool["scinet_record_approvals"]("cranary", "../etc", **GOOD)
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize(
    "remote_result, expected",
    [
        ({"exit_code": -9, "stdout": b"", "stderr": b"", "timed_out": True},
         "approval_recording_timeout"),
        ({"exit_code": 0, "stdout": b'{"state":"recorded"}', "stderr": b"",
          "timed_out": True}, "approval_recording_timeout"),
        ({"exit_code": None, "stdout": b"", "stderr": b"",
          "error": "scinet_broker_protocol_error"}, "scinet_broker_protocol_error"),
        ({"exit_code": 255, "stdout": b"", "stderr": b"transport failed"},
         "approval_recording_failed"),
        ({"exit_code": 0, "stdout": b'{"state":"recorded"}', "stderr": b"",
          "truncated": True}, "invalid_approval_receipt"),
        ({"exit_code": 0, "stdout": b"[]", "stderr": b""},
         "invalid_approval_receipt"),
    ],
)
def test_record_approvals_preserves_transport_failures_without_recording_success(
    tmp_path, remote_result, expected
):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = remote_result
        result = tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)
        assert result["success"] is False
        assert result["error"] == expected
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(stage["stage_id"])
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_approvals_surfaces_refusal_auth_and_garbage(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "refused", "error": "contradictory_existing_values"}).encode(), code=73)
        r = tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)
        assert r["success"] is False and r["error"] == "contradictory_existing_values"
        call.return_value = ok(code=None, error="scinet_auth_required")
        assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)["error"] == "scinet_auth_required"
        call.return_value = ok(b"garbage")
        assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)["error"] == "invalid_approval_receipt"
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(stage["stage_id"])
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_configured_reviewer_overrides_default_user(tmp_path):
    cfg = settings()
    cfg.approval_reviewer = "drsmith"
    tool, call, stage, patches = staged_tool(tmp_path, cfg=cfg)
    try:
        with pytest.raises(PermissionError):
            tool["scinet_record_approvals"]("cranary", stage["stage_id"], **GOOD)
        call.return_value = ok(json.dumps({"state": "unchanged"}).encode())
        assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **{**GOOD, "reviewer": "drsmith"})["success"]
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_rest_schema_scopes_approval_fields_to_record_action():
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest
    sid = "a" * 32
    ScinetSetupRequest(action="record_approvals", stage_id=sid, **GOOD)
    for bad in ({"action": "record_approvals", "stage_id": sid},
                {"action": "preflight", "stage_id": sid, "reviewer": "operator"},
                {"action": "record_approvals", "stage_id": sid, **GOOD, "device": "cpu"},
                {"action": "record_approvals", "stage_id": sid, **GOOD, "path": "/x"}):
        with pytest.raises(ValidationError):
            ScinetSetupRequest(**bad)


EXPA_FIELDS = training.APPROVAL_FIELDS["laya_expA"]
EXPA = dict(reviewer="operator", confirmation="I approve laya_expA on 1 H100 GPU for at most 01:00:00",
            approved_fields=list(EXPA_FIELDS), experiment="laya_expA")


def test_record_expa_approvals_writes_only_expa_fields_and_ledgers_limits(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "recorded", "changed_fields": sorted(EXPA_FIELDS),
                                           "pins_sha256": "cd" * 32}).encode())
        result = tool["scinet_record_approvals"]("cranary", stage["stage_id"], **EXPA)
        assert result["success"] and result["approved_limits"]["max_walltime"] == "01:00:00"
        argv = shlex.split(call.call_args.args[2][-1])
        assert argv[-1] == "laya_expA" and json.loads(argv[-4]) == EXPA_FIELDS
        entry = training._Ledger(tmp_path / "state").stage(stage["stage_id"])["approvals"][-1]
        assert entry["experiment"] == "laya_expA"
        assert entry["limits"] == {"gpus": 1, "gpu_type": "H100", "max_walltime": "01:00:00"}
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_expa_unchanged_still_binds_limits_once(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "unchanged", "idempotent": True}).encode())
        for _ in range(2):
            assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **EXPA)["success"]
        approvals = training._Ledger(tmp_path / "state").stage(stage["stage_id"])["approvals"]
        assert len(approvals) == 1 and approvals[0]["limits"]["max_walltime"] == "01:00:00"
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("override,exc", [
    ({"confirmation": "Approved"}, PermissionError),
    ({"confirmation": "I approve all 5"}, PermissionError),
    ({"confirmation": "I approve laya_expA on 2 H100 GPU for at most 01:00:00"}, PermissionError),
    ({"reviewer": "agent7"}, PermissionError),
    ({"reviewer": "someone-else"}, PermissionError),
    ({"approved_fields": list(FIELDS)}, ValueError),
    ({"approved_fields": list(EXPA_FIELDS) + ["experiment_b_approved_by"]}, ValueError),
    ({"approved_fields": list(EXPA_FIELDS)[:2]}, ValueError),
    ({"device": "cpu"}, ValueError),
    ({"experiment": "laya_expB", "approved_fields": ["experiment_b_approved_by"]}, PermissionError),
    ({"experiment": "laya_expC"}, ValueError),
    ({"experiment": "laya_smoke"}, PermissionError),
])
def test_record_expa_rejects_bad_requests_without_remote_call(tmp_path, override, exc):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        with pytest.raises(exc):
            tool["scinet_record_approvals"]("cranary", stage["stage_id"], **{**EXPA, **override})
        with pytest.raises(PermissionError):
            tool["scinet_record_approvals"]("cranary", "0" * 32, **EXPA)
        call.assert_not_called()
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(stage["stage_id"])
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_expb_and_smoke_confirmations_cannot_record_expa_or_expb():
    confirmations = training.APPROVAL_CONFIRMATIONS
    assert len(set(confirmations.values())) == len(confirmations)
    assert "{stage_id}" in confirmations["laya_expB"]
    assert "{stage_id}" not in confirmations["laya_smoke"] + confirmations["laya_expA"]
    assert not set(EXPA_FIELDS) & {"experiment_b_approved_by", "smoke_approved_by"}


def test_recorder_expa_fields_audit_experiment_and_rejects_unknown(tmp_path):
    pins = write_pins(tmp_path)
    run = lambda exp: subprocess.run(
        [sys.executable, "-c", training.REMOTE_APPROVAL_RECORDER, str(pins), "operator", "cuda",
         json.dumps(EXPA_FIELDS), "a" * 32, "cranary", exp], capture_output=True, text=True)
    assert run("laya_expB").returncode != 0 and json.loads(pins.read_text())["device"] is None
    assert run("laya_expA").returncode == 0
    data = json.loads(pins.read_text())
    assert all(data[f] == "operator" for f in EXPA_FIELDS) and data["device"] == "cuda"
    assert "smoke_approved_by" not in data and "experiment_b_approved_by" not in data
    audit = json.loads((tmp_path / "approvals.audit.jsonl").read_text().splitlines()[-1])
    assert audit["experiment"] == "laya_expA"


def _expa_template_tool(tmp_path, walltime):
    cfg = settings()
    cfg.training_allow_full_runs, cfg.training_full_walltime = True, walltime
    root = handoff(tmp_path)
    template = (b"#!/bin/bash\n#SBATCH --account=@SLURM_ACCOUNT@\n#SBATCH --time=@WALLTIME_HH_MM_SS@\n"
                b"#SBATCH --nodes=1\n#SBATCH --gpus-per-node=1\n#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
                b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n")
    (root / "laya_expA.sbatch.template").write_bytes(template)
    sums = (root / "SHA256SUMS").read_text() + f"{hashlib.sha256(template).hexdigest()}  laya_expA.sbatch.template\n"
    (root / "SHA256SUMS").write_text(sums)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    return tool, wsreg


@pytest.mark.parametrize("walltime,allowed", [("01:00:00", True), ("00:45:00", True),
                                              ("01:00:01", False), ("02:00:00", False)])
def test_submit_expa_enforces_approved_walltime_limit(tmp_path, walltime, allowed):
    tool, wsreg = _expa_template_tool(tmp_path, walltime)
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        stage = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = None
        call.return_value = ok(json.dumps({"state": "recorded", "changed_fields": EXPA_FIELDS}).encode())
        assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **EXPA)["success"]
        call.reset_mock()
        call.return_value = None
        if allowed:
            call.side_effect = [ok(), ok(b"ok"), ok(b"888")]
            result = tool["scinet_submit"]("cranary", stage["stage_id"], "laya_expA")
            assert result["success"] and result["resources"]["gpus"] == 1
            assert result["resources"]["walltime"] == walltime
        else:
            with pytest.raises(PermissionError, match="exceeds the human-approved"):
                tool["scinet_submit"]("cranary", stage["stage_id"], "laya_expA")
            call.assert_not_called()


def test_expa_approval_does_not_enable_full_runs(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        call.return_value = ok(json.dumps({"state": "recorded"}).encode())
        assert tool["scinet_record_approvals"]("cranary", stage["stage_id"], **EXPA)["success"]
        call.reset_mock()
        for experiment in ("laya_expA", "laya_expB"):
            with pytest.raises(PermissionError, match="not enabled"):
                tool["scinet_submit"]("cranary", stage["stage_id"], experiment)
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("walltime,ready", [("01:00:00", True), ("02:00:00", False)])
def test_preflight_expa_ready_requires_walltime_within_approved_limit(tmp_path, walltime, ready):
    cfg = settings()
    cfg.training_full_walltime = walltime
    tool, call, stage, patches = staged_tool(tmp_path, cfg=cfg)
    try:
        call.return_value = ok(json.dumps({"state": "recorded"}).encode())
        tool["scinet_record_approvals"]("cranary", stage["stage_id"], **EXPA)
        pins = {"pins_sha256": "ab", "pins": {f: "operator" for f in EXPA_FIELDS}}
        call.return_value = ok(preflight_text({"verify-bundle": 0, "gate-expA": 0}, pins))
        result = tool["scinet_preflight"]("cranary", stage["stage_id"], "laya_expA")
        assert result["ready"] is ready
        assert result["resource_limits"]["within_approved_limits"] is ready
        assert "laya_expB_lora.py" not in call.call_args.args[2][-1]
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_rest_schema_accepts_expa_record_approvals():
    from agentporter.rest.routers.scinet import ScinetSetupRequest
    req = ScinetSetupRequest(action="record_approvals", stage_id="a" * 32, device="cuda", **EXPA)
    assert req.experiment == "laya_expA"


EXPB_FIELDS = ["experiment_b_approved_by"]


def expb_confirmation(stage_id):
    return f"I approve laya_expB for stage {stage_id} on 1 H100 GPU for at most 01:00:00"


def expb(stage_id, **override):
    return {"reviewer": "operator", "confirmation": expb_confirmation(stage_id),
            "approved_fields": list(EXPB_FIELDS), "experiment": "laya_expB", **override}


def test_expb_confirmation_text_is_exact_and_stage_bound():
    sid = "9879564934e94665b71d8947ef74d896"
    assert training._required_confirmation("laya_expB", sid) == (
        "I approve laya_expB for stage 9879564934e94665b71d8947ef74d896 on 1 H100 GPU for at most 01:00:00")
    assert training.APPROVAL_LIMITS["laya_expB"] == {"gpus": 1, "gpu_type": "H100", "max_walltime": "01:00:00"}
    assert training.APPROVAL_FIELDS["laya_expB"] == EXPB_FIELDS
    assert training._required_confirmation("laya_expA", sid) == training.APPROVAL_CONFIRMATIONS["laya_expA"]


def test_record_expb_writes_only_expb_field_and_ledgers_stage_bound_limits(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        sid = stage["stage_id"]
        call.return_value = ok(json.dumps({"state": "recorded", "changed_fields": EXPB_FIELDS,
                                           "pins_sha256": "ef" * 32}).encode())
        result = tool["scinet_record_approvals"]("cranary", sid, **expb(sid))
        assert result["success"] and result["approved_limits"]["max_walltime"] == "01:00:00"
        assert call.call_count == 1
        argv = shlex.split(call.call_args.args[2][-1])
        assert argv[-1] == "laya_expB" and json.loads(argv[-4]) == EXPB_FIELDS and argv[-3] == sid
        entry = training._Ledger(tmp_path / "state").stage(sid)["approvals"][-1]
        assert entry["experiment"] == "laya_expB" and entry["stage_id"] == sid
        assert entry["reviewer"] == "operator" and entry["confirmation"] == expb_confirmation(sid)
        assert entry["limits"] == {"gpus": 1, "gpu_type": "H100", "max_walltime": "01:00:00"}
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("override,exc", [
    (lambda s: {"confirmation": "I approve all 5"}, PermissionError),
    (lambda s: {"confirmation": "I approve laya_expA on 1 H100 GPU for at most 01:00:00"}, PermissionError),
    (lambda s: {"confirmation": training.APPROVAL_CONFIRMATIONS["laya_expB"]}, PermissionError),
    (lambda s: {"confirmation": "I approve laya_expB on 1 H100 GPU for at most 01:00:00"}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation("0" * 32)}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s.upper())}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s).replace("01:00:00", "02:00:00")}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s).replace("1 H100 GPU", "2 H100 GPU")}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s).replace("H100", "A100")}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s) + " "}, PermissionError),
    (lambda s: {"confirmation": expb_confirmation(s).lower()}, PermissionError),
    (lambda s: {"confirmation": "yes"}, PermissionError),
    (lambda s: {"reviewer": "copilot"}, PermissionError),
    (lambda s: {"reviewer": "phil"}, PermissionError),
    (lambda s: {"reviewer": "someone-else"}, PermissionError),
    (lambda s: {"approved_fields": list(FIELDS)}, ValueError),
    (lambda s: {"approved_fields": list(EXPA_FIELDS)}, ValueError),
    (lambda s: {"approved_fields": EXPB_FIELDS + ["smoke_approved_by"]}, ValueError),
    (lambda s: {"approved_fields": EXPB_FIELDS * 2}, ValueError),
    (lambda s: {"approved_fields": []}, ValueError),
    (lambda s: {"approved_fields": "experiment_b_approved_by"}, ValueError),
    (lambda s: {"device": "cpu"}, ValueError),
    (lambda s: {"experiment": "laya_expA"}, PermissionError),
    (lambda s: {"experiment": "laya_smoke"}, PermissionError),
])
def test_record_expb_rejects_bad_requests_without_remote_call(tmp_path, override, exc):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        sid = stage["stage_id"]
        with pytest.raises(exc):
            tool["scinet_record_approvals"]("cranary", sid, **expb(sid, **override(sid)))
        call.assert_not_called()
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(sid)
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_expb_rejects_unknown_or_foreign_stage(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        for bad in ("0" * 32, "../x", stage["stage_id"].upper()):
            with pytest.raises((PermissionError, ValueError)):
                tool["scinet_record_approvals"]("cranary", bad, **expb(bad))
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_record_expb_refusal_or_garbage_does_not_ledger(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        sid = stage["stage_id"]
        for reply in (ok(json.dumps({"state": "refused", "error": "contradictory_existing_values"}).encode(), code=73),
                      ok(b"garbage"), ok(b"", error="scinet_auth_required")):
            call.return_value = reply
            assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"] is False
        assert "approvals" not in training._Ledger(tmp_path / "state").stage(sid)
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def run_recorder_exp(pins, fields, experiment, reviewer="operator"):
    proc = subprocess.run(
        [sys.executable, "-c", training.REMOTE_APPROVAL_RECORDER, str(pins), reviewer, "cuda",
         json.dumps(fields), "a" * 32, "cranary", experiment], capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])


def test_recorder_expb_writes_only_expb_field_with_audit(tmp_path):
    pins = write_pins(tmp_path, compute_approved_by="drA", device="cuda")
    code, out = run_recorder_exp(pins, EXPB_FIELDS, "laya_expB")
    data = json.loads(pins.read_text())
    assert code == 0 and out["state"] == "recorded" and out["changed_fields"] == EXPB_FIELDS
    assert data["experiment_b_approved_by"] == "operator" and data["compute_approved_by"] == "drA"
    assert "smoke_approved_by" not in data and "head_contract_reviewed_by" not in data
    audit = [json.loads(x) for x in (tmp_path / "approvals.audit.jsonl").read_text().splitlines()]
    assert len(audit) == 1 and audit[0]["experiment"] == "laya_expB" and audit[0]["stage_id"] == "a" * 32
    assert run_recorder_exp(pins, EXPB_FIELDS, "laya_expB")[1]["state"] == "unchanged"


@pytest.mark.parametrize("fields,experiment", [
    (EXPA_FIELDS, "laya_expB"), (FIELDS, "laya_expB"), (EXPB_FIELDS + ["device"], "laya_expB"),
    (EXPB_FIELDS, "laya_expA"), (EXPB_FIELDS, "laya_smoke"), (EXPB_FIELDS, "laya_expC"),
])
def test_recorder_refuses_fields_not_matching_experiment(tmp_path, fields, experiment):
    pins = write_pins(tmp_path)
    before = pins.read_bytes()
    code, out = run_recorder_exp(pins, fields, experiment)
    assert code != 0 and out["error"] == "invalid_arguments"
    assert pins.read_bytes() == before and not (tmp_path / "approvals.audit.jsonl").exists()


def test_recorder_expb_refuses_contradictory_existing_approver(tmp_path):
    pins = write_pins(tmp_path, experiment_b_approved_by="someone")
    before = pins.read_bytes()
    code, out = run_recorder_exp(pins, EXPB_FIELDS, "laya_expB")
    assert code != 0 and out["error"] == "contradictory_existing_values"
    assert pins.read_bytes() == before


def _full_template_tool(tmp_path, walltime, experiment, template=None):
    cfg = settings()
    cfg.training_allow_full_runs, cfg.training_full_walltime = True, walltime
    root = handoff(tmp_path)
    template = template or (
        b"#!/bin/bash\n#SBATCH --account=@SLURM_ACCOUNT@\n#SBATCH --time=@WALLTIME_HH_MM_SS@\n"
        b"#SBATCH --nodes=1\n#SBATCH --gpus-per-node=1\n#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
        b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n")
    name = f"{experiment}.sbatch.template"
    (root / name).write_bytes(template)
    sums = (root / "SHA256SUMS").read_text() + f"{hashlib.sha256(template).hexdigest()}  {name}\n"
    (root / "SHA256SUMS").write_text(sums)
    wsreg = registry(root)
    return create_scinet_training_tool(wsreg, cfg, tmp_path / "state"), wsreg


@pytest.mark.parametrize("walltime,allowed", [("01:00:00", True), ("00:30:00", True),
                                              ("01:00:01", False), ("02:00:00", False)])
def test_submit_expb_requires_ledgered_approval_and_enforces_walltime(tmp_path, walltime, allowed):
    tool, wsreg = _full_template_tool(tmp_path, walltime, "laya_expB")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        sid = tool["scinet_stage"]("cranary")["stage_id"]
        call.reset_mock()
        call.side_effect = None
        with pytest.raises(PermissionError, match="requires a human approval"):
            tool["scinet_submit"]("cranary", sid, "laya_expB")
        call.assert_not_called()
        call.return_value = ok(json.dumps({"state": "recorded", "changed_fields": EXPB_FIELDS}).encode())
        assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"]
        call.reset_mock()
        call.return_value = None
        if allowed:
            call.side_effect = [ok(), ok(b"ok"), ok(b"999")]
            result = tool["scinet_submit"]("cranary", sid, "laya_expB")
            assert result["success"] and result["resources"]["gpus"] == 1
            assert result["resources"]["walltime"] == walltime
            rendered = call.call_args_list[1].kwargs["input_bytes"]
            assert b"#SBATCH --gpus-per-node=1" in rendered and f"#SBATCH --time={walltime}".encode() in rendered
            gate_cmd = call.call_args_list[0].args[2][-1]
            assert "laya_expB_lora.py gate" in gate_cmd and "--smoke" not in gate_cmd
            call.reset_mock()
            again = tool["scinet_submit"]("cranary", sid, "laya_expB")
            assert again["error"] == "already_submitted"
            call.assert_not_called()
        else:
            with pytest.raises(PermissionError, match="exceeds the human-approved"):
                tool["scinet_submit"]("cranary", sid, "laya_expB")
            call.assert_not_called()


def test_submit_expb_refuses_when_gate_reports_missing_pins_approval(tmp_path):
    tool, wsreg = _full_template_tool(tmp_path, "01:00:00", "laya_expB")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        sid = tool["scinet_stage"]("cranary")["stage_id"]
        call.side_effect = None
        call.return_value = ok(json.dumps({"state": "unchanged"}).encode())
        assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"]
        call.reset_mock()
        call.return_value = ok(b"gate-expB: experiment_b_approved_by is null", code=2)
        result = tool["scinet_submit"]("cranary", sid, "laya_expB")
        assert result["success"] is False and result["error"] == "approval_or_checksum_gate_failed"
        assert call.call_count == 1 and "sbatch" not in call.call_args.args[2][-1]


@pytest.mark.parametrize("approve", ["none", "smoke", "expA"])
def test_submit_expb_not_unlocked_by_smoke_or_expa_approvals(tmp_path, approve):
    tool, wsreg = _full_template_tool(tmp_path, "01:00:00", "laya_expB")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        sid = tool["scinet_stage"]("cranary")["stage_id"]
        call.side_effect = None
        call.return_value = ok(json.dumps({"state": "recorded"}).encode())
        if approve == "smoke":
            assert tool["scinet_record_approvals"]("cranary", sid, **GOOD)["success"]
        elif approve == "expA":
            assert tool["scinet_record_approvals"]("cranary", sid, **EXPA)["success"]
        call.reset_mock()
        with pytest.raises(PermissionError, match="requires a human approval"):
            tool["scinet_submit"]("cranary", sid, "laya_expB")
        call.assert_not_called()


@pytest.mark.parametrize("tamper", [
    {"stage_id": "0" * 32}, {"confirmation": "I approve all 5"}, {"confirmation": None},
    {"limits": {"gpus": 1, "gpu_type": "H100", "max_walltime": "23:00:00"}}, {"reviewer": None},
])
def test_submit_expb_rejects_tampered_ledger_entry(tmp_path, tamper):
    tool, wsreg = _full_template_tool(tmp_path, "01:00:00", "laya_expB")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        sid = tool["scinet_stage"]("cranary")["stage_id"]
        led = training._Ledger(tmp_path / "state")
        entry = {"reviewer": "operator", "stage_id": sid, "experiment": "laya_expB",
                 "confirmation": expb_confirmation(sid), "limits": dict(training.APPROVAL_LIMITS["laya_expB"])}
        led.update_stage(sid, approvals=[{**entry, **tamper}])
        call.reset_mock()
        with pytest.raises(PermissionError):
            tool["scinet_submit"]("cranary", sid, "laya_expB")
        call.assert_not_called()


def test_expb_approval_does_not_enable_full_runs(tmp_path):
    tool, call, stage, patches = approval_tool(tmp_path)
    try:
        sid = stage["stage_id"]
        call.return_value = ok(json.dumps({"state": "recorded"}).encode())
        assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"]
        call.reset_mock()
        for experiment in ("laya_expA", "laya_expB"):
            with pytest.raises(PermissionError, match="not enabled"):
                tool["scinet_submit"]("cranary", sid, experiment)
        call.assert_not_called()
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


@pytest.mark.parametrize("case,ready", [
    ("ledgered", True), ("no_ledger", False), ("other_approver", False),
    ("pins_null", False), ("gate_fails", False), ("walltime", False), ("agent_name", False),
])
def test_preflight_expb_ready_only_with_ledgered_stage_bound_approval(tmp_path, case, ready):
    cfg = settings()
    cfg.training_full_walltime = "02:00:00" if case == "walltime" else "01:00:00"
    if case == "agent_name":
        cfg.approval_reviewer = "operator"
    tool, call, stage, patches = staged_tool(tmp_path, cfg=cfg)
    try:
        sid = stage["stage_id"]
        if case != "no_ledger":
            call.return_value = ok(json.dumps({"state": "recorded"}).encode())
            assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"]
        approver = {"other_approver": "drsmith", "pins_null": None, "agent_name": "copilot"}.get(case, "operator")
        pins = {"pins_sha256": "ab", "pins": {"experiment_b_approved_by": approver}}
        gates = {"verify-bundle": 0, "gate-expB": 1 if case == "gate_fails" else 0}
        call.return_value = ok(preflight_text(gates, pins))
        result = tool["scinet_preflight"]("cranary", sid, "laya_expB")
        assert result["success"] is True and result["ready"] is ready
        assert result["ledgered_approval"]["recorded"] is (case != "no_ledger")
        assert any(repr(expb_confirmation(sid)) in step for step in result["human_approval_steps"])
        cmd = call.call_args.args[2][-1]
        assert "laya_expB_lora.py gate" in cmd and "--smoke" not in cmd and "sbatch" not in cmd
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_preflight_expa_unaffected_by_expb_ledger_requirement(tmp_path):
    tool, call, stage, patches = staged_tool(tmp_path)
    try:
        pins = {"pins_sha256": "ab", "pins": {f: "operator" for f in EXPA_FIELDS}}
        call.return_value = ok(preflight_text({"verify-bundle": 0, "gate-expA": 0}, pins))
        result = tool["scinet_preflight"]("cranary", stage["stage_id"], "laya_expA")
        assert result["ready"] is True and "ledgered_approval" not in result
    finally:
        for p in reversed(patches):
            p.__exit__(None, None, None)


def test_rest_schema_accepts_stage_bound_expb_confirmation():
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest
    sid = "9879564934e94665b71d8947ef74d896"
    req = ScinetSetupRequest(action="record_approvals", stage_id=sid, device="cuda", **expb(sid))
    assert req.experiment == "laya_expB" and req.confirmation == expb_confirmation(sid)
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action="record_approvals", stage_id=sid, **expb(sid, confirmation="x" * 129))


EXPB_HEADER = (b"#!/bin/bash\n#SBATCH --job-name=laya-expB\n#SBATCH --account=@SLURM_ACCOUNT@\n"
               b"#SBATCH --nodes=1\n#SBATCH --gpus-per-node=1\n#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
               b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n")
EXPB_SOFT_BUDGET = (EXPB_HEADER.replace(b"#SBATCH --nodes=1\n", b"#SBATCH --time=@WALLTIME_HH_MM_SS@\n#SBATCH --nodes=1\n")
                    + b"set -euo pipefail\nWALLTIME=\"@WALLTIME_HH_MM_SS@\"\n"
                    b"\"$CRANARY_PYTHON\" laya_expB_lora.py train --walltime \"$WALLTIME\"\n")


def _approved_expb_submit(tool, wsreg, call_side_effect):
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        sid = tool["scinet_stage"]("cranary")["stage_id"]
        call.side_effect = None
        call.return_value = ok(json.dumps({"state": "recorded", "changed_fields": EXPB_FIELDS}).encode())
        assert tool["scinet_record_approvals"]("cranary", sid, **expb(sid))["success"]
        call.reset_mock()
        call.return_value = None
        call.side_effect = call_side_effect
        return tool["scinet_submit"]("cranary", sid, "laya_expB"), call


def test_submit_expb_accepts_soft_trainer_budget_with_same_walltime(tmp_path):
    assert EXPB_SOFT_BUDGET.count(b"@WALLTIME_HH_MM_SS@") == 2
    tool, wsreg = _full_template_tool(tmp_path, "01:00:00", "laya_expB", EXPB_SOFT_BUDGET)
    result, call = _approved_expb_submit(tool, wsreg, [ok(), ok(b"ok"), ok(b"4242")])
    assert result["success"] and result["resources"]["walltime"] == "01:00:00"
    rendered = call.call_args_list[1].kwargs["input_bytes"]
    assert rendered.count(b"#SBATCH --time=01:00:00\n") == 1 and rendered.count(b"#SBATCH --time") == 1
    assert b'WALLTIME="01:00:00"\n' in rendered and b"@WALLTIME" not in rendered
    assert not training.PLACEHOLDER_RE.findall(rendered.decode())


@pytest.mark.parametrize("template", [
    EXPB_HEADER + b'WALLTIME="@WALLTIME_HH_MM_SS@"\n',
    EXPB_HEADER.replace(b"#SBATCH --nodes=1\n", b"#SBATCH --time=01:00:00\n#SBATCH --nodes=1\n")
    + b'WALLTIME="@WALLTIME_HH_MM_SS@"\n',
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --nodes=1\n", b"#SBATCH --time=@WALLTIME_HH_MM_SS@\n#SBATCH --nodes=1\n"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --nodes=1\n", b"#SBATCH -t 48:00:00\n#SBATCH --nodes=1\n"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --nodes=1\n", b"#SBATCH --time-min=02:00:00\n#SBATCH --nodes=1\n"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --nodes=1\n", b"#SBATCH --begin=now+@WALLTIME_HH_MM_SS@\n#SBATCH --nodes=1\n"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --time=@WALLTIME_HH_MM_SS@", b"#SBATCH --time=@WALLTIME_HH_MM_SS@,02:00:00"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --time=@WALLTIME_HH_MM_SS@", b"#SBATCH --time @WALLTIME_HH_MM_SS@"),
    EXPB_SOFT_BUDGET.replace(b"#SBATCH --time=@WALLTIME_HH_MM_SS@", b" #SBATCH --time=@WALLTIME_HH_MM_SS@"),
], ids=["no-directive", "literal-directive", "duplicate-directive", "rogue-short-t", "rogue-time-min",
        "placeholder-in-other-directive", "suffixed-directive", "space-form", "indented-directive"])
def test_submit_expb_rejects_invalid_walltime_templates_without_remote_call(tmp_path, template):
    tool, wsreg = _full_template_tool(tmp_path, "01:00:00", "laya_expB", template)
    with pytest.raises(ValueError, match="Full-run template must have exactly one"):
        _approved_expb_submit(tool, wsreg, [])
