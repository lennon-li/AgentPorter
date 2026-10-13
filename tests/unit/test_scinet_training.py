from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentporter.tools import scinet_training as training
from agentporter.tools.scinet_training import create_scinet_training_tool
from agentporter.workspaces.registry import WorkspaceRegistry


def settings():
    return SimpleNamespace(
        host="trillium-gpu.alliancecan.ca",
        user="yeli",
        control_socket="/home/yeli/.ssh/cm-yeli@trillium-gpu.alliancecan.ca:22",
        machine="asgard",
        training_remote_root="/scratch/project/cranary-laya",
        training_account="def-cranary",
        training_partition="gpu",
        training_python="/scratch/project/cranary-laya/envs/laya/bin/python",
        training_bootstrap_python="/usr/bin/python3",
        training_cpus_per_task=4,
        training_max_stage_bytes=1024 * 1024,
    )


def handoff(tmp_path: Path, partition_placeholder: bool = False, renderer: bool = False) -> Path:
    root = tmp_path / "data-raw" / "cran-history" / "training" / "trillium" / "handoff-out"
    root.mkdir(parents=True)
    files = {
        "cranary-laya-bundle.tar.gz": b"bundle",
        "HANDOFF.json": b"{}",
        "laya_smoke.sbatch.template": (
            b"#!/bin/bash\n"
            b"#SBATCH --job-name=cranary-laya-smoke\n"
            b"#SBATCH --account=@SLURM_ACCOUNT@\n"
            b"#SBATCH --time=00:15:00\n"
            b"#SBATCH --nodes=1\n#SBATCH --ntasks=1\n#SBATCH --gpus-per-node=1\n"
            b"#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
            b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n"
            b"#SBATCH --error=@SCRATCH_LOG_DIR@/%x-%j.err\n"
        ),
    }
    if partition_placeholder:
        files["laya_smoke.sbatch.template"] = files["laya_smoke.sbatch.template"].replace(
            b"#SBATCH --time", b"#SBATCH --partition=@SLURM_PARTITION@\n#SBATCH --time")
    if renderer:
        files["render_sbatch.py"] = b"print('render')\n"
    sums = []
    for name, data in files.items():
        (root / name).write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (root / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return root


def registry(root: Path) -> WorkspaceRegistry:
    return WorkspaceRegistry({
        "cranary": {
            "path": str(root.parents[4]),
            "allow_execute": True,
            "allow_scinet_training": True,
        }
    })


def identity(ws):
    return SimpleNamespace(pw_dir="/home/yeli"), ws


def stage_receipt(*args, **kwargs):
    match = __import__("re").search(r"[a-f0-9]{32}", args[2][-1])
    assert match
    return {
        "exit_code": 0,
        "stdout": json.dumps({"success": True, "transfer_id": match.group(0)}).encode(),
        "stderr": b"",
        "timed_out": False,
        "truncated": False,
    }


def test_stage_validates_handoff_hashes_and_uses_fixed_remote_root(tmp_path):
    root = handoff(tmp_path)
    wsreg = registry(root)
    cfg = settings()
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        response = tool["scinet_stage"]("cranary")
        assert response["success"] is True
    assert "PYTHON312=/usr/bin/python3" in response["setup_command"]
    assert response["remote_handoff"].startswith("/scratch/project/cranary-laya/handoff/")
    assert all(item["sha256"] for item in response["files"])
    payload = call.call_args.kwargs["input_bytes"]
    assert b"bundle" in payload
    remote_command = call.call_args.args[2][-1]
    assert "/scratch/project/cranary-laya/handoff" in remote_command
    assert response["stage_id"] in remote_command


def test_stage_rejects_checksum_mismatch(tmp_path):
    root = handoff(tmp_path)
    (root / "HANDOFF.json").write_bytes(b"changed")
    tool = create_scinet_training_tool(registry(root), settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(registry(root).get("cranary"))), \
         patch.object(training, "_call") as call:
        with pytest.raises(ValueError, match="SHA-256"):
            tool["scinet_stage"]("cranary")
    call.assert_not_called()


def test_submit_is_smoke_bounded_and_runs_preflight_before_sbatch(tmp_path):
    root = handoff(tmp_path)
    wsreg = registry(root)
    cfg = settings()
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = [
            {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"ok", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"12345", "stderr": b"", "timed_out": False, "truncated": False},
        ]
        result = tool["scinet_submit"]("cranary", staged["stage_id"])
    assert result["success"] is True
    assert result["resources"]["gpus"] == 1
    assert result["resources"]["walltime"] == "00:15:00"
    rendered = call.call_args_list[1].kwargs["input_bytes"]
    assert b"#SBATCH --partition=gpu" in rendered
    assert b"#SBATCH --gpus-per-node=1" in rendered
    assert b"#SBATCH --time=00:15:00" in rendered
    assert b"/runs/" in rendered
    assert b"/envs/laya-expA/bin/python" in rendered
    assert b"@SLURM_ACCOUNT@" not in rendered


def test_submit_stops_before_script_publish_when_gate_fails(tmp_path):
    root = handoff(tmp_path)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = None
        call.return_value = {"exit_code": 1, "stdout": b"approval missing", "stderr": b"",
                             "timed_out": False, "truncated": False}
        result = tool["scinet_submit"]("cranary", staged["stage_id"])
    assert result["success"] is False
    assert result["error"] == "approval_or_checksum_gate_failed"
    assert call.call_count == 1


def test_job_ownership_and_log_kind_are_restricted(tmp_path):
    root = handoff(tmp_path)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.side_effect = [
            {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"ok", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"12345", "stderr": b"", "timed_out": False, "truncated": False},
        ]
        tool["scinet_submit"]("cranary", staged["stage_id"])
        with pytest.raises(PermissionError):
            tool["scinet_job_status"]("cranary", "99999")
        with pytest.raises(ValueError):
            tool["scinet_job_logs"]("cranary", "12345", "arbitrary")



def run_submit(tmp_path, **kw):
    root = handoff(tmp_path, **kw)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = [
            {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"ok", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"12345", "stderr": b"", "timed_out": False, "truncated": False},
        ]
        result = tool["scinet_submit"]("cranary", staged["stage_id"])
    return staged, result, call


def test_stage_and_submit_with_render_sbatch_and_partition_placeholder(tmp_path):
    staged, result, call = run_submit(tmp_path, partition_placeholder=True, renderer=True)
    assert "render_sbatch.py" in [f["name"] for f in staged["files"]]
    assert result["success"] is True
    rendered = call.call_args_list[1].kwargs["input_bytes"]
    assert rendered.count(b"--partition") == 1
    assert b"#SBATCH --partition=gpu" in rendered
    assert b"@" not in rendered.replace(b"%x", b"")
    assert b"#SBATCH --cpus-per-task=4" in rendered


def test_unlisted_handoff_file_is_not_staged(tmp_path):
    root = handoff(tmp_path, renderer=True)
    (root / "evil.py").write_bytes(b"x")
    tool = create_scinet_training_tool(registry(root), settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(registry(root).get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
    assert "evil.py" not in [f["name"] for f in staged["files"]]


def test_submit_rejects_unknown_placeholder_and_duplicate_partition(tmp_path):
    root = handoff(tmp_path, partition_placeholder=True)
    t = root / "laya_smoke.sbatch.template"
    t.write_bytes(t.read_bytes() + b"#SBATCH --partition=@SLURM_PARTITION@\n")
    (root / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                for p in root.iterdir() if p.name != "SHA256SUMS"), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate partition"):
        run_submit_existing(root, tmp_path)


REAL_STYLE_TEMPLATE = (
    b"#!/bin/bash\n"
    b"# Rendered by AgentPorter: replaces @SLURM_ACCOUNT@-style tokens. Contact: ops@example.org\n"
    b"#SBATCH --job-name=cranary-laya-smoke\n"
    b"#SBATCH --account=@SLURM_ACCOUNT@\n"
    b"#SBATCH --time=00:15:00\n"
    b"#SBATCH --nodes=1\n#SBATCH --ntasks=1\n#SBATCH --gpus-per-node=1\n"
    b"#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
    b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n"
    b"#SBATCH --error=@SCRATCH_LOG_DIR@/%x-%j.err\n"
    b"set -euo pipefail\n"
    b"args=(a b); echo \"${args[@]}\" \"$@\"  # user@host, $CRANARY_SCRATCH\n"
)


def _rewrite_template(root, data):
    (root / "laya_smoke.sbatch.template").write_bytes(data)
    (root / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                for p in root.iterdir() if p.name != "SHA256SUMS"), encoding="utf-8")


def test_submit_allows_bare_at_signs_but_fills_all_tokens(tmp_path):
    root = handoff(tmp_path)
    _rewrite_template(root, REAL_STYLE_TEMPLATE)
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.reset_mock()
        call.side_effect = [
            {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"ok", "stderr": b"", "timed_out": False, "truncated": False},
            {"exit_code": 0, "stdout": b"12345", "stderr": b"", "timed_out": False, "truncated": False},
        ]
        result = tool["scinet_submit"]("cranary", staged["stage_id"])
    assert result["success"] is True
    rendered = call.call_args_list[1].kwargs["input_bytes"]
    assert b"ops@example.org" in rendered and b'"$@"' in rendered
    assert b"--account=def-cranary" in rendered
    assert b"#SBATCH --partition=gpu" in rendered
    assert not training.PLACEHOLDER_RE.search(rendered.decode())


def test_submit_rejects_unknown_strict_token(tmp_path):
    root = handoff(tmp_path)
    _rewrite_template(root, REAL_STYLE_TEMPLATE + b"echo @MYSTERY_TOKEN@\n")
    with pytest.raises(ValueError, match="unfilled placeholder: @MYSTERY_TOKEN@"):
        run_submit_existing(root, tmp_path)


def run_submit_existing(root, tmp_path):
    wsreg = registry(root)
    tool = create_scinet_training_tool(wsreg, settings(), tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.side_effect = [
            {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False}]
        return tool["scinet_submit"]("cranary", staged["stage_id"])


def slurm_validate(script: bytes) -> list[str]:
    """Mimic sbatch: shebang first, all #SBATCH before the first executable statement."""
    lines = script.decode().splitlines()
    assert lines[0].startswith("#!")
    directives, seen_exec = [], False
    for n, line in enumerate(lines[1:], 2):
        if line.lstrip().startswith("#SBATCH"):
            assert not seen_exec, f"#SBATCH on line {n} after first executable statement"
            directives.append(line.strip())
        elif line.strip() and not line.lstrip().startswith("#"):
            seen_exec = True
    return directives


REAL_TEMPLATE = (
    b"#!/bin/bash\n"
    b"#SBATCH --job-name=cranary-laya-smoke\n"
    b"#SBATCH --account=@SLURM_ACCOUNT@\n"
    b"#SBATCH --partition=@SLURM_PARTITION@\n"
    b"#SBATCH --time=00:15:00\n"
    b"#SBATCH --nodes=1\n#SBATCH --ntasks=1\n#SBATCH --gpus-per-node=1\n"
    b"#SBATCH --cpus-per-task=@CPUS_PER_TASK@\n"
    b"#SBATCH --output=@SCRATCH_LOG_DIR@/%x-%j.out\n"
    b"#SBATCH --error=@SCRATCH_LOG_DIR@/%x-%j.err\n"
    b"\nset -euo pipefail\necho start\n"
)


def submit_with_template(tmp_path, data):
    root = handoff(tmp_path)
    _rewrite_template(root, data)
    wsreg = registry(root)
    cfg = settings()
    cfg.training_account, cfg.training_partition = "def-yeli", "compute"
    tool = create_scinet_training_tool(wsreg, cfg, tmp_path / "state")
    with patch.object(training, "_identity", return_value=identity(wsreg.get("cranary"))), \
         patch.object(training, "_call") as call:
        call.side_effect = stage_receipt
        staged = tool["scinet_stage"]("cranary")
        call.reset_mock()
        ok = {"exit_code": 0, "stdout": b"", "stderr": b"", "timed_out": False, "truncated": False}
        call.side_effect = [ok, ok, {**ok, "stdout": b"12345"}]
        try:
            result = tool["scinet_submit"]("cranary", staged["stage_id"])
        except ValueError as exc:
            return None, call, exc
    return result, call, None


def test_rendered_script_passes_slurm_validator_with_exports_after_directives(tmp_path):
    result, call, _ = submit_with_template(tmp_path, REAL_TEMPLATE)
    assert result["success"] is True
    rendered = call.call_args_list[1].kwargs["input_bytes"]
    directives = slurm_validate(rendered)
    logs = "/scratch/project/cranary-laya"
    assert "#SBATCH --account=def-yeli" in directives
    assert "#SBATCH --partition=compute" in directives
    assert "#SBATCH --gpus-per-node=1" in directives
    assert "#SBATCH --time=00:15:00" in directives
    assert any(d.startswith("#SBATCH --output=") and "/logs/%x-%j.out" in d for d in directives)
    assert any(d.startswith("#SBATCH --error=") and "/logs/%x-%j.err" in d for d in directives)
    assert all("/home/" not in d for d in directives) and logs
    text = rendered.decode()
    assert text.index("export CRANARY_SCRATCH=") > text.rindex("#SBATCH")
    assert text.index("set -euo pipefail") > text.index("export CRANARY_PYTHON=")
    # gate and approval preflight still ran before publish/sbatch
    assert call.call_args_list[0].args[2][0] == "/bin/bash"
    assert "verify-bundle" in call.call_args_list[0].args[2][2]


def test_submit_rejects_directives_after_executable_statement(tmp_path):
    bad = REAL_TEMPLATE.replace(b"#SBATCH --nodes=1\n", b"echo hi\n#SBATCH --nodes=1\n")
    result, call, exc = submit_with_template(tmp_path, bad)
    assert exc is not None and "precede executable" in str(exc)
    assert call.call_count == 0
