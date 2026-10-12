"""Fail-closed Laya staging and Slurm control through the existing SciNet master.

Only the bounded Laya smoke workflow is exposed. Remote setup, model fetching,
and human approvals remain interactive and are never automated here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import socket
import tempfile
from typing import Literal
import uuid

from agentporter.tools.scinet import _socket_available, control_socket, run_scinet_bytes
from agentporter.tools.scinet_broker import broker_socket_available

ScinetExperiment = Literal["laya_smoke"]
ScinetLogKind = Literal["all", "stdout", "stderr", "metrics", "manifests", "checkpoints"]

MAX_REMOTE_OUTPUT = 256 * 1024
MAX_LOG_OUTPUT = 4 * 1024 * 1024
JOB_ID_RE = re.compile(r"^[0-9]+$")
ID_RE = re.compile(r"^[a-f0-9]{32}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
HANDOFF_FILES = frozenset({
    "cranary-laya-bundle.tar.gz", "requirements-laya.in", "requirements-laya.lock",
    "scinet_login_setup.sh", "pins.template.json", "laya_smoke.sbatch.template",
    "laya_expA.sbatch.template", "laya_expB.sbatch.template", "staging_manifest.json",
    "SMOKE_HANDOFF.md", "HANDOFF.json", "SHA256SUMS", "render_sbatch.py",
})
REQUIRED_HANDOFF_FILES = frozenset({"cranary-laya-bundle.tar.gz", "HANDOFF.json", "SHA256SUMS"})

REMOTE_STAGE_RECEIVER = r'''
import hashlib, json, os, shutil, sys
root, transfer_id = sys.argv[1:3]
if not transfer_id.isalnum() or len(transfer_id) != 32:
    raise SystemExit(64)
header = json.loads(sys.stdin.buffer.readline())
files = header.get("files", [])
if not isinstance(files, list) or not files or len(files) > 32:
    raise SystemExit(64)
os.makedirs(root, mode=0o700, exist_ok=True)
final = os.path.join(root, transfer_id)
try:
    os.mkdir(final, 0o700)
except FileExistsError:
    print(json.dumps({"success": False, "error": "destination_exists"}))
    raise SystemExit(73)
received = []
try:
    for item in files:
        name, size, want = item["name"], int(item["size"]), item["sha256"]
        if not name or os.path.basename(name) != name or name.startswith("."):
            raise ValueError("invalid file name")
        path = os.path.join(final, name)
        digest = hashlib.sha256()
        remaining = size
        with open(path, "xb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW, 0o600)) as out:
            while remaining:
                chunk = sys.stdin.buffer.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("truncated transfer")
                out.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        if digest.hexdigest() != want:
            raise ValueError("sha256 mismatch")
        received.append({"name": name, "size": size, "sha256": digest.hexdigest()})
    print(json.dumps({"success": True, "transfer_id": transfer_id,
                      "path": final, "files": received}, sort_keys=True))
except Exception as exc:
    shutil.rmtree(final, ignore_errors=True)
    print(json.dumps({"success": False, "error": type(exc).__name__}))
    raise SystemExit(65)
'''

REMOTE_EXCLUSIVE_WRITER = r'''
import hashlib, os, sys
path, want = sys.argv[1:3]
data = sys.stdin.buffer.read()
if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != want:
    raise SystemExit(65)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
try:
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    fd = -1
finally:
    if fd >= 0:
        os.close(fd)
print("ok")
'''

REMOTE_FILE_READER = r'''
import base64, hashlib, json, os, sys
root, job_id, kind = sys.argv[1:4]
job_root, log_root = os.path.join(root, "laya-smoke", job_id), os.path.join(root, "logs")
if kind not in {"all", "stdout", "stderr", "metrics", "manifests", "checkpoints"}:
    raise SystemExit(64)
metrics = {"run.json", "metrics.json", "input-hashes.txt", "pip-freeze.txt"}
manifests = {"bundle_manifest.json", "HANDOFF.json", "SHA256SUMS", "pins.json", "input-hashes.txt"}
files, seen, total = [], set(), 0
for base in (log_root, job_root):
    if not os.path.isdir(base):
        continue
    for current, dirs, entries in os.walk(base, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current, d))]
        for entry in sorted(entries):
            path = os.path.join(current, entry)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            rel = os.path.relpath(path, root)
            checkpoint = entry.endswith((".safetensors", ".npz"))
            textlog = entry.endswith((".out", ".err"))
            ismetric, ismanifest = entry in metrics, entry in manifests
            selected = kind == "all" and (checkpoint or textlog or ismetric or ismanifest)
            selected |= kind == "stdout" and entry.endswith(".out")
            selected |= kind == "stderr" and entry.endswith(".err")
            selected |= kind == "metrics" and ismetric
            selected |= kind == "manifests" and ismanifest
            selected |= kind == "checkpoints" and checkpoint
            if not selected or rel in seen:
                continue
            size, digest, content = os.path.getsize(path), hashlib.sha256(), b""
            with open(path, "rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                if not checkpoint and size <= 262144:
                    stream.seek(0)
                    content = stream.read()
            item = {"path": rel, "size": size, "sha256": digest.hexdigest()}
            if content:
                item["content_base64"] = base64.b64encode(content).decode()
            files.append(item)
            seen.add(rel)
            total += size
            if len(files) >= 64 or total >= 4 * 1024 * 1024:
                break
        if len(files) >= 64 or total >= 4 * 1024 * 1024:
            break
print(json.dumps({"files": files, "truncated": len(files) >= 64 or total >= 4 * 1024 * 1024},
                 sort_keys=True))
'''

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _validate_remote_root(value: str) -> str:
    if not value or not value.startswith("/") or "\x00" in value:
        raise PermissionError("SciNet training remote root is not configured safely")
    if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        raise PermissionError("SciNet training remote root is not configured safely")
    return value.rstrip("/")

def _validate_token(value: str, label: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise PermissionError(f"SciNet training {label} is not configured safely")
    return value

def _validate_python(value: str, label: str) -> str:
    if not value or not value.startswith("/") or "\x00" in value:
        raise PermissionError(f"SciNet training {label} is not configured safely")
    if any(char in value for char in " \t\n;&|" + chr(96)):
        raise PermissionError(f"SciNet training {label} is not configured safely")
    return value


def _runtime_python(runtime_root: str) -> str:
    """Return the venv created by scinet_login_setup.sh for one staged run."""
    return _validate_python(
        runtime_root + "/envs/laya-expA/bin/python", "Python environment"
    )

def _settings_ready(settings) -> None:
    if settings is None:
        raise PermissionError("SciNet training endpoint is not configured for this AgentPorter instance")
    _validate_remote_root(getattr(settings, "training_remote_root", ""))
    _validate_token(getattr(settings, "user", ""), "SSH user")
    _validate_token(getattr(settings, "host", ""), "SSH host")
    _validate_token(getattr(settings, "training_account", ""), "account")
    _validate_token(getattr(settings, "training_partition", ""), "partition")
    _validate_python(getattr(settings, "training_python", ""), "Python environment")
    _validate_python(getattr(settings, "training_bootstrap_python", ""), "bootstrap Python")

def _identity(registry, workspace_id: str, settings):
    _settings_ready(settings)
    ws = registry.get(workspace_id)
    if not ws.allow_execute or not ws.allow_scinet_training:
        raise PermissionError("SciNet training requires explicit workspace execution and training permission")
    user = pwd.getpwuid(os.getuid())
    if user.pw_name != settings.user or socket.gethostname().split(".")[0] != settings.machine:
        raise PermissionError("SciNet training requires the configured Asgard host identity")
    broker_socket = str(getattr(settings, "broker_socket", "") or "").strip()
    if broker_socket:
        if not broker_socket_available(broker_socket):
            raise PermissionError("scinet_broker_unavailable")
    elif not _socket_available(control_socket(settings, user.pw_dir)):
        raise PermissionError("ssh_control_socket_unavailable")
    return user, ws

def _handoff_dir(ws) -> Path:
    root = (Path(ws.path) / "data-raw" / "cran-history" / "training" /
            "trillium" / "handoff-out").resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Laya SciNet handoff-out directory is missing")
    return root

def _handoff_files(ws, max_bytes: int):
    root = _handoff_dir(ws)
    files, hashes, total = {}, {}, 0
    for name in sorted(HANDOFF_FILES):
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or not SAFE_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid handoff file: {name}")
        total += path.stat().st_size
        if total > max_bytes:
            raise ValueError("Laya handoff exceeds the configured stage size limit")
        files[name], hashes[name] = path, _sha256(path)
    missing = REQUIRED_HANDOFF_FILES - files.keys()
    if missing:
        raise ValueError(f"Laya handoff is incomplete: missing {sorted(missing)}")
    expected = {}
    for line in files["SHA256SUMS"].read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        if not name:
            digest, _, name = line.partition(" ")
        name = name.lstrip("*")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or name not in files:
            raise ValueError("Invalid SHA256SUMS entry in Laya handoff")
        expected[name] = digest
    for name, digest in expected.items():
        if hashes[name] != digest:
            raise ValueError(f"Local SHA-256 mismatch for {name}")
    return files, hashes, total

def _payload(files, hashes, total: int) -> bytes:
    header = {"version": 1, "total_bytes": total, "files": [
        {"name": name, "size": path.stat().st_size, "sha256": hashes[name]}
        for name, path in sorted(files.items())]}
    chunks = [json.dumps(header, sort_keys=True, separators=(",", ":")).encode() + b"\n"]
    chunks.extend(path.read_bytes() for _, path in sorted(files.items()))
    return b"".join(chunks)

def _remote_python_command(python: str, script: str, args: list[str]) -> list[str]:
    return ["/bin/bash", "-lc", shlex.join([python, "-c", script, *args])]

def _call(settings, user, remote: list[str], *, input_bytes=None,
          timeout: float = 60, max_output: int = MAX_REMOTE_OUTPUT) -> dict:
    return run_scinet_bytes(
        settings,
        user,
        remote,
        input_bytes=input_bytes,
        max_output=max_output,
        timeout=timeout,
        operation="training",
    )

def _result(result: dict) -> dict:
    stdout, stderr = result.get("stdout", b""), result.get("stderr", b"")
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return {"target": "scinet_training", "exit_code": result.get("exit_code"),
            "stdout": stdout, "stderr": stderr, "timed_out": result.get("timed_out", False),
            "truncated": result.get("truncated", False)}

class _Ledger:
    def __init__(self, state_dir: Path | None):
        self.path = state_dir / "scinet_training.json" if state_dir else None

    def read(self):
        if not self.path or not self.path.is_file():
            return {"stages": {}, "jobs": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"stages": {}, "jobs": {}}
        except (OSError, ValueError):
            return {"stages": {}, "jobs": {}}

    def write(self, value):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".scinet-training-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True)
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def add_stage(self, record):
        value = self.read()
        value.setdefault("stages", {})[record["stage_id"]] = record
        self.write(value)

    def stage(self, stage_id):
        return self.read().get("stages", {}).get(stage_id)

    def latest_stage(self, workspace_id):
        for record in reversed(list(self.read().get("stages", {}).values())):
            if record.get("workspace_id") == workspace_id:
                return record
        return None

    def add_job(self, record):
        value = self.read()
        value.setdefault("jobs", {})[record["job_id"]] = record
        self.write(value)

    def job(self, job_id):
        return self.read().get("jobs", {}).get(job_id)

def create_scinet_training_tool(registry, settings=None, state_dir: Path | None = None):
    ledger = _Ledger(state_dir)

    def scinet_stage(workspace_id: str) -> dict:
        user, ws = _identity(registry, workspace_id, settings)
        files, hashes, total = _handoff_files(ws, int(settings.training_max_stage_bytes))
        stage_id = uuid.uuid4().hex
        payload = _payload(files, hashes, total)
        root = _validate_remote_root(settings.training_remote_root)
        result = _call(settings, user, _remote_python_command(
            settings.training_bootstrap_python, REMOTE_STAGE_RECEIVER,
            [root + "/handoff", stage_id]), input_bytes=payload, timeout=900)
        parsed = _result(result)
        if result.get("exit_code") != 0 or result.get("timed_out") or result.get("truncated"):
            parsed.update({"command": "scinet_stage", "success": False, "error": "stage_remote_failed"})
            return parsed
        try:
            receipt = json.loads(parsed["stdout"])
        except ValueError:
            parsed.update({"command": "scinet_stage", "success": False, "error": "invalid_stage_receipt"})
            return parsed
        if receipt.get("success") is not True or receipt.get("transfer_id") != stage_id:
            parsed.update({"command": "scinet_stage", "success": False,
                           "error": receipt.get("error", "stage_rejected")})
            return parsed
        remote_handoff = root + "/handoff/" + stage_id
        runtime_root = root + "/runs/" + stage_id
        record = {"workspace_id": workspace_id, "stage_id": stage_id,
                  "remote_handoff": remote_handoff, "remote_runtime": runtime_root,
                  "runtime_python": _runtime_python(runtime_root),
                  "files": hashes}
        ledger.add_stage(record)
        return {"target": "scinet_training", "command": "scinet_stage", "success": True,
                "stage_id": stage_id, "remote_handoff": remote_handoff,
                "runtime_root": runtime_root, "setup_required": True,
        "setup_command": "PYTHON312=" + shlex.quote(settings.training_bootstrap_python) +
        " CRANARY_SCRATCH=" + shlex.quote(runtime_root) +
                " bash " + remote_handoff + "/scinet_login_setup.sh " + remote_handoff,
                "files": [{"name": name, "size": path.stat().st_size, "sha256": hashes[name]}
                          for name, path in sorted(files.items())]}

    def scinet_environment_check(workspace_id: str) -> dict:
        user, _ = _identity(registry, workspace_id, settings)
        root = _validate_remote_root(settings.training_remote_root)
        account = _validate_token(settings.training_account, "account")
        partition = _validate_token(settings.training_partition, "partition")
        stage = ledger.latest_stage(workspace_id)
        py = _validate_python(
            (stage.get("runtime_python") or _runtime_python(stage["remote_runtime"]))
            if stage
            else settings.training_python,
            "Python environment",
        )
        script = "set +e; " + "; ".join([
            "printf '[identity]\\n'", "id -un", "hostname",
            "printf '[slurm]\\n'", "command -v sinfo", "sinfo --version",
            shlex.join(["sinfo", "-h", "-p", partition, "-o", "%P|%a|%l|%G|%f"]),
            "printf '[account]\\n'",
            shlex.join(["sacctmgr", "-nP", "show", "assoc", "where",
                        "user=" + settings.user, "account=" + account,
                        "format=Account,Partition,QOS"]) + " || true",
            "printf '[python]\\n'", shlex.join([py, "--version"]),
            "printf '[storage]\\n'", shlex.join(["df", "-Pk", root]),
            "quota -s 2>/dev/null || true",
            "printf '[gpu-driver]\\n'",
            "nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>/dev/null || true",
        ])
        result = _call(settings, user, ["/bin/bash", "-lc", script])
        response = _result(result)
        response.update({"command": "scinet_environment_check",
                         "success": result.get("exit_code") == 0 and not result.get("timed_out"),
                         "configured_account": account, "configured_partition": partition,
                         "configured_remote_root": root})
        return response

    def scinet_submit(workspace_id: str, stage_id: str,
                      experiment: ScinetExperiment = "laya_smoke") -> dict:
        user, ws = _identity(registry, workspace_id, settings)
        if experiment != "laya_smoke":
            raise ValueError("Only the bounded laya_smoke experiment is enabled")
        if not ID_RE.fullmatch(stage_id):
            raise ValueError("Invalid SciNet stage_id")
        record = ledger.stage(stage_id)
        if not record or record.get("workspace_id") != workspace_id:
            raise PermissionError("stage_id was not created by this workspace")
        template = _handoff_dir(ws) / "laya_smoke.sbatch.template"
        if not template.is_file() or _sha256(template) != record.get("files", {}).get(template.name):
            raise ValueError("Smoke template changed after staging")
        account = _validate_token(settings.training_account, "account")
        partition = _validate_token(settings.training_partition, "partition")
        runtime = record["remote_runtime"]
        py = _runtime_python(runtime)
        pins, repo, logs = runtime + "/pinned/pins.json", runtime + "/cranary-bundle", runtime + "/logs"
        script = template.read_text(encoding="utf-8")
        script = script.replace("@SLURM_ACCOUNT@", account).replace("@CPUS_PER_TASK@", str(settings.training_cpus_per_task))
        script = script.replace("@SCRATCH_LOG_DIR@", logs)
        partition_in_template = script.count("@SLURM_PARTITION@")
        if partition_in_template > 1:
            raise ValueError("Smoke template has duplicate partition placeholders")
        script = script.replace("@SLURM_PARTITION@", partition)
        if "@" in script:
            raise ValueError("Smoke template contains an unfilled placeholder")
        lines = script.splitlines()
        insert = next((i + 1 for i, line in enumerate(lines) if line.startswith("#SBATCH --account=")), None)
        if insert is None:
            raise ValueError("Smoke template is missing account directive")
        if partition_in_template:
            if sum(line.startswith("#SBATCH --partition=") for line in lines) != 1 or \
                    f"#SBATCH --partition={partition}" not in lines:
                raise ValueError("Smoke template partition directive is invalid")
        elif any(line.startswith("#SBATCH --partition") for line in lines):
            raise ValueError("Smoke template has an unexpected partition directive")
        else:
            lines.insert(insert, f"#SBATCH --partition={partition}")
        lines[1:1] = [
            "export CRANARY_SCRATCH=" + shlex.quote(runtime),
            "export CRANARY_REPO=" + shlex.quote(repo),
            "export CRANARY_PINS=" + shlex.quote(pins),
            "export CRANARY_PYTHON=" + shlex.quote(py),
        ]
        rendered = ("\n".join(lines) + "\n").encode()
        required = [b"#SBATCH --gpus-per-node=1", b"#SBATCH --time=00:15:00"]
        if rendered.count(required[0]) != 1 or any(item not in rendered for item in required):
            raise ValueError("Smoke job resource bounds are invalid")
        preflight = "set -e; " + " && ".join([
            shlex.join([py, repo + "/code/laya_expA_trainer.py", "verify-bundle", "--out", repo]),
            shlex.join([py, repo + "/code/laya_expA_trainer.py", "gate", "--root", repo,
                        "--pins", pins, "--split-dir", repo + "/data"]),
            shlex.join([py, repo + "/code/laya_expB_lora.py", "gate", "--root", repo,
                        "--pins", pins, "--split-dir", repo + "/data", "--smoke"]),
        ])
        preflight_result = _call(settings, user, ["/bin/bash", "-lc", preflight], timeout=120)
        if preflight_result.get("exit_code") != 0 or preflight_result.get("timed_out"):
            response = _result(preflight_result)
            response.update({"command": "scinet_submit", "success": False,
                             "error": "approval_or_checksum_gate_failed"})
            return response
        script_path = runtime + "/laya_smoke.sbatch"
        write = _call(settings, user, _remote_python_command(
            settings.training_bootstrap_python, REMOTE_EXCLUSIVE_WRITER,
            [script_path, _sha256_bytes(rendered)]), input_bytes=rendered)
        if write.get("exit_code") != 0:
            response = _result(write)
            response.update({"command": "scinet_submit", "success": False, "error": "script_publish_failed"})
            return response
        submit = _call(settings, user, ["/bin/bash", "-lc",
                                        shlex.join(["sbatch", "--parsable", script_path])])
        output = _result(submit)
        match = JOB_ID_RE.fullmatch(output["stdout"].strip()) if output["stdout"] else None
        if submit.get("exit_code") != 0 or not match:
            output.update({"command": "scinet_submit", "success": False, "error": "slurm_submission_failed"})
            return output
        job_id = match.group(0)
        ledger.add_job({"job_id": job_id, "workspace_id": workspace_id,
                        "stage_id": stage_id, "runtime_root": runtime, "experiment": experiment})
        return {"target": "scinet_training", "command": "scinet_submit", "success": True,
                "job_id": job_id, "stage_id": stage_id, "experiment": experiment,
                "resources": {"gpus": 1, "walltime": "00:15:00",
                              "account": account, "partition": partition}}

    def _job(registry, workspace_id: str, job_id: str):
        user, _ = _identity(registry, workspace_id, settings)
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("Invalid Slurm job_id")
        record = ledger.job(job_id)
        if not record or record.get("workspace_id") != workspace_id:
            raise PermissionError("job_id was not created by this workspace")
        return user, record

    def scinet_job_status(workspace_id: str, job_id: str) -> dict:
        user, _ = _job(registry, workspace_id, job_id)
        query = "set +e; " + "; ".join([
            shlex.join(["squeue", "-h", "-j", job_id, "-u", settings.user, "-o", "%i|%T|%M|%R|%b"]),
            "printf '\\n--AGENTPORTER-SACCT--\\n'",
            shlex.join(["sacct", "-n", "-X", "-j", job_id,
                        "-o", "JobIDRaw,State,ExitCode,Elapsed,AllocTRES,Reason", "-P"]),
        ])
        result = _call(settings, user, ["/bin/bash", "-lc", query])
        response = _result(result)
        response.update({"command": "scinet_job_status", "job_id": job_id,
                         "success": result.get("exit_code") == 0 and not result.get("timed_out")})
        if response["success"]:
            current, _, accounting = response["stdout"].partition("--AGENTPORTER-SACCT--")
            current_fields = current.strip().splitlines()[0].split("|") if current.strip() else []
            accounting_fields = accounting.strip().splitlines()[0].split("|") if accounting.strip() else []
            response["job"] = {
                "job_id": job_id,
                "state": current_fields[1] if len(current_fields) > 1 else (accounting_fields[1] if len(accounting_fields) > 1 else "UNKNOWN"),
                "elapsed": current_fields[2] if len(current_fields) > 2 else (accounting_fields[3] if len(accounting_fields) > 3 else ""),
                "reason": current_fields[3] if len(current_fields) > 3 else (accounting_fields[5] if len(accounting_fields) > 5 else ""),
                "allocated_resources": current_fields[4] if len(current_fields) > 4 else (accounting_fields[4] if len(accounting_fields) > 4 else ""),
                "exit_status": accounting_fields[2] if len(accounting_fields) > 2 else None,
            }
        return response

    def scinet_job_logs(workspace_id: str, job_id: str,
                        kind: ScinetLogKind = "all") -> dict:
        user, record = _job(registry, workspace_id, job_id)
        if kind not in {"all", "stdout", "stderr", "metrics", "manifests", "checkpoints"}:
            raise ValueError("Invalid SciNet log kind")
        result = _call(settings, user, _remote_python_command(
            settings.training_bootstrap_python, REMOTE_FILE_READER,
            [record["runtime_root"], job_id, kind]), max_output=MAX_LOG_OUTPUT)
        response = _result(result)
        response.update({"command": "scinet_job_logs", "job_id": job_id, "kind": kind,
                         "success": result.get("exit_code") == 0 and not result.get("timed_out")})
        if response["success"]:
            try:
                response["files"] = json.loads(response.pop("stdout"))
            except ValueError:
                response.update({"success": False, "error": "invalid_log_receipt"})
        return response

    return {
        "scinet_stage": scinet_stage,
        "scinet_submit": scinet_submit,
        "scinet_job_status": scinet_job_status,
        "scinet_job_logs": scinet_job_logs,
        "scinet_environment_check": scinet_environment_check,
    }

