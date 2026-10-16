"""Fail-closed Laya staging and Slurm control through the existing SciNet master.

Fixed actions cover stage, login-node setup, preflight, bounded submission,
status and logs.  Approvals are recorded only by the audited scinet_record_approvals action, which
needs explicit per-experiment human confirmation, a fixed authorized reviewer,
the exact stage and that experiment's exact fields (laya_smoke, laya_expA, and
laya_expB with a stage-bound confirmation); they are never inferred.  Duo is never automated.
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

ScinetExperiment = Literal["laya_smoke", "laya_expA", "laya_expB"]
ScinetLogKind = Literal["all", "stdout", "stderr", "metrics", "manifests", "checkpoints"]

EXPERIMENTS = {
    "laya_smoke": ("laya_smoke.sbatch.template", "laya-smoke"),
    "laya_expA": ("laya_expA.sbatch.template", "laya-expA"),
    "laya_expB": ("laya_expB.sbatch.template", "laya-expB"),
}
WALLTIME_RE = re.compile(r"^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$")
APPROVAL_FIELDS = {
    "laya_smoke": ["head_contract_reviewed_by", "compute_approved_by",
                   "gpu_allocation_approved_by", "experiment_b_approved_by", "smoke_approved_by"],
    "laya_expA": ["head_contract_reviewed_by", "compute_approved_by", "gpu_allocation_approved_by"],
    "laya_expB": ["experiment_b_approved_by"],
}
APPROVAL_CONFIRMATION = "I approve all 5"
# laya_expB's confirmation is stage-bound: {stage_id} is replaced by the exact 32-hex stage id.
APPROVAL_CONFIRMATIONS = {
    "laya_smoke": APPROVAL_CONFIRMATION,
    "laya_expA": "I approve laya_expA on 1 H100 GPU for at most 01:00:00",
    "laya_expB": "I approve laya_expB for stage {stage_id} on 1 H100 GPU for at most 01:00:00",
}
# Resource bounds the human approved together with the experiment; enforced at preflight and submit.
APPROVAL_LIMITS = {
    "laya_expA": {"gpus": 1, "gpu_type": "H100", "max_walltime": "01:00:00"},
    "laya_expB": {"gpus": 1, "gpu_type": "H100", "max_walltime": "01:00:00"},
}
# Experiments that can only be preflight-ready / submitted after an AgentPorter-ledgered approval
# for this exact stage (pins alone are not enough, e.g. smoke also writes experiment_b_approved_by).
LEDGERED_APPROVAL_REQUIRED = frozenset({"laya_expB"})
APPROVAL_DEVICE = "cuda"
AGENT_APPROVER_RE = re.compile(r"agent|copilot|phil|claude|gpt|bot|automat|agentporter", re.I)
SETUP_MAX_ATTEMPTS = 5
SETUP_TIMEOUT_SECONDS = 3600
MAX_REMOTE_OUTPUT = 256 * 1024
MAX_LOG_OUTPUT = 4 * 1024 * 1024
JOB_ID_RE = re.compile(r"^[0-9]+$")
ID_RE = re.compile(r"^[a-f0-9]{32}$")
# Only strict @UPPER_SNAKE@ tokens count as placeholders; bare '@' (emails, "$@", comments) is allowed.
PLACEHOLDER_RE = re.compile(r"@[A-Z][A-Z0-9_]*@")
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

REMOTE_SETUP_RUNNER = r'''
import fcntl, hashlib, json, os, re, subprocess, sys, time
action, root, stage_id, py312, expected_json, timeout_s = sys.argv[1:7]
if action not in {"start", "status"} or not re.fullmatch(r"[a-f0-9]{32}", stage_id):
    raise SystemExit(64)
handoff, runtime = os.path.join(root, "handoff", stage_id), os.path.join(root, "runs", stage_id)
script = os.path.join(handoff, "scinet_login_setup.sh")
env_python = os.path.join(runtime, "envs", "laya-expA", "bin", "python")
pins = os.path.join(runtime, "pinned", "pins.json")
sdir = os.path.join(runtime, "setup")
state_path, exit_path, log_path = (os.path.join(sdir, n) for n in ("state.json", "exit_code", "setup.log"))
def sha(path):
    d = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            d.update(c)
    return d.hexdigest()
def load():
    try:
        with open(state_path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
def alive(pid):
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as f:
            return script.encode() in f.read()
    except (OSError, ValueError, TypeError):
        return False
def report(extra=None):
    st = load()
    out = {"stage_id": stage_id, "attempt": st.get("attempt", 0)}
    if alive(st.get("pid")):
        out["state"] = "running"
    elif os.path.isfile(exit_path):
        try:
            code = int(open(exit_path).read().strip())
        except ValueError:
            code = -1
        done = code == 0 and os.access(env_python, os.X_OK) and os.path.isfile(pins)
        out["state"] = "complete" if done else "failed"
        out["exit_code"] = code
    elif st.get("pid"):
        out["state"] = "interrupted"
    else:
        out["state"] = "not_started"
    out["env_python_present"] = os.access(env_python, os.X_OK)
    out["pins_present"] = os.path.isfile(pins)
    if st.get("started"):
        out["started_epoch"] = st["started"]
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 8192))
            out["log_tail"] = f.read().decode("utf-8", "replace")
    except OSError:
        out["log_tail"] = ""
    out.update(extra or {})
    print(json.dumps(out, sort_keys=True))
if action == "status":
    report()
    raise SystemExit(0)
expected = json.loads(expected_json)
if not isinstance(expected, dict) or "scinet_login_setup.sh" not in expected:
    raise SystemExit(64)
for name, want in expected.items():
    path = os.path.join(handoff, name)
    if os.path.basename(name) != name or os.path.islink(path) or not os.path.isfile(path) or sha(path) != want:
        print(json.dumps({"state": "refused", "error": "staged_file_hash_mismatch", "file": name}))
        raise SystemExit(65)
os.makedirs(sdir, mode=0o700, exist_ok=True)
with open(os.path.join(sdir, "lock"), "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    st = load()
    if alive(st.get("pid")):
        report({"idempotent": True})
        raise SystemExit(0)
    if os.path.isfile(exit_path) and os.access(env_python, os.X_OK) and os.path.isfile(pins) \
            and open(exit_path).read().strip() == "0":
        report({"idempotent": True})
        raise SystemExit(0)
    attempt = int(st.get("attempt", 0)) + 1
    if attempt > 5:
        print(json.dumps({"state": "retry_limit", "attempt": attempt - 1}))
        raise SystemExit(75)
    try:
        os.unlink(exit_path)
    except FileNotFoundError:
        pass
    inner = ('timeout --kill-after=60 "$4" /bin/bash "$0" "$1" >>"$2" 2>&1 </dev/null; '
             'echo $? >"$3.tmp"; mv "$3.tmp" "$3"')
    env = {k: os.environ[k] for k in ("PATH", "HOME", "USER", "LANG") if k in os.environ}
    env.update(PYTHON312=py312, CRANARY_SCRATCH=runtime)
    with open(log_path, "ab") as log:
        log.write(("\n== setup attempt %d at %s ==\n" % (attempt, time.strftime("%FT%TZ", time.gmtime()))).encode())
    proc = subprocess.Popen(["/bin/bash", "-c", inner, script, handoff, log_path, exit_path, timeout_s],
                            env=env, cwd=handoff, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True, close_fds=True)
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"pid": proc.pid, "attempt": attempt, "started": int(time.time())}, f)
    os.replace(tmp, state_path)
time.sleep(1)
report({"launched": True})
'''

PINS_READER = r'''
import hashlib, json, sys
path = sys.argv[1]
raw = open(path, "rb").read(65536)
p = json.loads(raw)
keep = ("schema", "device", "torch_version", "transformers_version", "weights_sha256",
        "weights_source_revision", "trust_remote_code")
out = {k: p.get(k) for k in keep}
out.update({k: v for k, v in p.items() if k.endswith("_by") and isinstance(v, (str, type(None)))})
print(json.dumps({"pins_sha256": hashlib.sha256(raw).hexdigest(), "pins": out}, sort_keys=True))
'''

REMOTE_APPROVAL_RECORDER = r'''
import fcntl, hashlib, json, os, re, sys, tempfile, time
pins, reviewer, device, fields_json, stage_id, workspace_id = sys.argv[1:7]
experiment = sys.argv[7] if len(sys.argv) > 7 else "laya_smoke"
fields = json.loads(fields_json)
EXPECTED = {
    "laya_smoke": ["compute_approved_by", "experiment_b_approved_by", "gpu_allocation_approved_by",
                   "head_contract_reviewed_by", "smoke_approved_by"],
    "laya_expA": ["compute_approved_by", "gpu_allocation_approved_by", "head_contract_reviewed_by"],
    "laya_expB": ["experiment_b_approved_by"],
}
def out(state, code, **extra):
    print(json.dumps(dict(extra, state=state), sort_keys=True))
    raise SystemExit(code)
if not re.fullmatch(r"[a-f0-9]{32}", stage_id) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", reviewer) \
        or device != "cuda" or not isinstance(fields, list) or not fields \
        or experiment not in EXPECTED or sorted(map(str, fields)) != EXPECTED[experiment]:
    out("refused", 64, error="invalid_arguments")
if os.path.islink(pins) or not os.path.isfile(pins) or os.path.islink(os.path.dirname(pins)):
    out("refused", 66, error="pins_missing_or_unsafe")
pdir = os.path.dirname(pins)
with open(os.path.join(pdir, ".approvals.lock"), "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    with open(pins, "rb") as f:
        raw = f.read(1 << 20)
    before = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw)
    except ValueError:
        out("refused", 65, error="pins_not_json")
    if not isinstance(data, dict):
        out("refused", 65, error="pins_not_object")
    desired = dict.fromkeys(fields, reviewer)
    desired["device"] = device
    conflicts = [k for k, v in desired.items() if data.get(k) not in (None, v)]
    if conflicts:
        out("refused", 73, error="contradictory_existing_values", fields=sorted(conflicts))
    changed = sorted(k for k, v in desired.items() if data.get(k) != v)
    if not changed:
        out("unchanged", 0, idempotent=True, pins_sha256=before, changed_fields=[])
    data.update(desired)
    body = json.dumps(data, indent=2, sort_keys=True).encode() + b"\n"
    after = hashlib.sha256(body).hexdigest()
    mode = os.stat(pins).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".pins-", dir=pdir)
    try:
        with os.fdopen(fd, "wb") as t:
            os.fchmod(t.fileno(), mode)
            t.write(body)
            t.flush()
            os.fsync(t.fileno())
        os.replace(tmp, pins)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    entry = {"time": time.strftime("%FT%TZ", time.gmtime()), "stage_id": stage_id,
             "workspace_id": workspace_id, "experiment": experiment,
             "reviewer": reviewer, "changed_fields": changed,
             "pins_sha256_before": before, "pins_sha256_after": after, "via": "agentporter"}
    afd = os.open(os.path.join(pdir, "approvals.audit.jsonl"),
                  os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(afd, "a") as a:
        a.write(json.dumps(entry, sort_keys=True) + "\n")
        a.flush()
        os.fsync(a.fileno())
    out("recorded", 0, changed_fields=changed, pins_sha256_before=before,
        pins_sha256=after, audit_time=entry["time"])
'''

REMOTE_EXCLUSIVE_WRITER = r'''
import hashlib, os, sys
path, want = sys.argv[1:3]
data = sys.stdin.buffer.read()
if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != want:
    raise SystemExit(65)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
except FileExistsError:
    if os.path.islink(path) or hashlib.sha256(open(path, "rb").read()).hexdigest() != want:
        raise SystemExit(73)
    print("ok")
    raise SystemExit(0)
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
exp_dir = sys.argv[4] if len(sys.argv) > 4 else "laya-smoke"
if exp_dir not in {"laya-smoke", "laya-expA", "laya-expB"}:
    raise SystemExit(64)
job_root, log_root = os.path.join(root, exp_dir, job_id), os.path.join(root, "logs")
if kind not in {"all", "stdout", "stderr", "metrics", "manifests", "checkpoints"}:
    raise SystemExit(64)
if not job_id.isdigit():
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
            if entry == "A-extract.time" and current == job_root:
                ismetric = True
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

def _gate_script(py: str, repo: str, pins: str, experiment: str) -> list[list[str]]:
    trainer, lora = repo + "/code/laya_expA_trainer.py", repo + "/code/laya_expB_lora.py"
    split = repo + "/data"
    verify = ("verify-bundle", [py, trainer, "verify-bundle", "--out", repo])
    gate_a = ("gate-expA", [py, trainer, "gate", "--root", repo, "--pins", pins, "--split-dir", split])
    gate_b = ["--root", repo, "--pins", pins, "--split-dir", split]
    if experiment == "laya_smoke":
        return [verify, gate_a, ("gate-expB-smoke", [py, lora, "gate", *gate_b, "--smoke"])]
    if experiment == "laya_expA":
        return [verify, gate_a]
    return [verify, ("gate-expB", [py, lora, "gate", *gate_b])]


def _seconds(walltime: str) -> int:
    h, m, s = (int(x) for x in walltime.split(":"))
    return h * 3600 + m * 60 + s


def _approved_limits(record: dict, experiment: str) -> dict | None:
    """Tightest resource limits recorded with this stage's approvals for experiment."""
    limits = [a.get("limits") for a in record.get("approvals") or []
              if a.get("experiment") == experiment and isinstance(a.get("limits"), dict)]
    if not limits:
        return None
    return min(limits, key=lambda x: _seconds(x["max_walltime"]))


def _required_confirmation(experiment: str, stage_id: str) -> str:
    return APPROVAL_CONFIRMATIONS[experiment].replace("{stage_id}", stage_id)


def _ledgered_approval_reviewers(record: dict, experiment: str, stage_id: str) -> set[str]:
    """Reviewers of AgentPorter-recorded approvals bound to this stage and experiment."""
    return {a.get("reviewer") for a in record.get("approvals") or []
            if a.get("experiment") == experiment and a.get("stage_id") == stage_id
            and a.get("confirmation") == _required_confirmation(experiment, stage_id)
            and a.get("limits") == APPROVAL_LIMITS.get(experiment) and a.get("reviewer")}


def _full_walltime(settings) -> str:
    walltime = str(getattr(settings, "training_full_walltime", "") or "")
    if not WALLTIME_RE.fullmatch(walltime) or walltime == "00:00:00":
        raise PermissionError("SciNet full-run walltime is not configured safely")
    return walltime


FULL_TIME_DIRECTIVE = "#SBATCH --time=@WALLTIME_HH_MM_SS@"


def _validate_full_walltime_placeholders(script: str) -> None:
    """Require one exact Slurm time directive; the placeholder may recur only outside #SBATCH lines."""
    time_directives, placeholder_directives = [], []
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#SBATCH"):
            continue
        args = stripped[len("#SBATCH"):].split()
        if args and (args[0].startswith("--time") or args[0].startswith("-t")):
            time_directives.append(line)
        if "@WALLTIME_HH_MM_SS@" in line:
            placeholder_directives.append(line)
    if time_directives != [FULL_TIME_DIRECTIVE] or placeholder_directives != [FULL_TIME_DIRECTIVE]:
        raise ValueError("Full-run template must have exactly one "
                         f"'{FULL_TIME_DIRECTIVE}' directive and no other Slurm time directive")


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
          timeout: float = 60, max_output: int = MAX_REMOTE_OUTPUT,
          operation: str = "training") -> dict:
    return run_scinet_bytes(
        settings,
        user,
        remote,
        input_bytes=input_bytes,
        max_output=max_output,
        timeout=timeout,
        operation=operation,
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

    def update_stage(self, stage_id, **fields):
        value = self.read()
        record = value.get("stages", {}).get(stage_id)
        if record is not None:
            record.update(fields)
            self.write(value)

    def jobs_for(self, stage_id, experiment):
        return [j for j in self.read().get("jobs", {}).values()
                if j.get("stage_id") == stage_id and j.get("experiment") == experiment]

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

    def _staged(workspace_id: str, stage_id: str):
        user, ws = _identity(registry, workspace_id, settings)
        if not isinstance(stage_id, str) or not ID_RE.fullmatch(stage_id):
            raise ValueError("Invalid SciNet stage_id")
        record = ledger.stage(stage_id)
        if not record or record.get("workspace_id") != workspace_id:
            raise PermissionError("stage_id was not created by this workspace")
        return user, ws, record

    def _setup_call(action: str, workspace_id: str, stage_id: str) -> dict:
        user, _, record = _staged(workspace_id, stage_id)
        root = _validate_remote_root(settings.training_remote_root)
        bootstrap = _validate_python(settings.training_bootstrap_python, "bootstrap Python")
        result = _call(settings, user, _remote_python_command(
            bootstrap, REMOTE_SETUP_RUNNER,
            [action, root, stage_id, bootstrap,
             json.dumps(record.get("files", {}), sort_keys=True, separators=(",", ":")),
             str(SETUP_TIMEOUT_SECONDS)]), timeout=100)
        response = _result(result)
        command = "scinet_setup" if action == "start" else "scinet_setup_status"
        response.update({"command": command, "stage_id": stage_id, "success": False})
        if result.get("error") in {"scinet_auth_required", "scinet_broker_unavailable"}:
            response.update({"error": result["error"], "human_action": (
                "A human must complete the interactive SciNet Duo login on Asgard to "
                "establish the authenticated control master; AgentPorter never automates it.")})
            return response
        try:
            report = json.loads(response["stdout"].strip().splitlines()[-1])
        except (ValueError, IndexError):
            response["error"] = "invalid_setup_receipt"
            return response
        response.pop("stdout", None)
        response.pop("stderr", None)
        state = report.get("state")
        response.update(report)
        response["success"] = state in {"running", "complete", "not_started"} and \
            result.get("exit_code") == 0 and not result.get("timed_out")
        if state == "failed":
            response["error"] = "setup_failed_retry_with_scinet_setup"
        elif result.get("exit_code") not in (0, None) and "error" not in response:
            response["error"] = state or "setup_remote_failed"
        response["runtime_python"] = record.get("runtime_python")
        if state in {"running", "complete", "failed", "interrupted", "not_started"}:
            ledger.update_stage(stage_id, setup_state=state)
        if state == "complete":
            response["next"] = "scinet_preflight, then a human records approvals in pins.json"
        return response

    def scinet_setup(workspace_id: str, stage_id: str) -> dict:
        """Start (or resume/retry) the fixed, SHA-verified login-node setup for a stage."""
        return _setup_call("start", workspace_id, stage_id)

    def scinet_setup_status(workspace_id: str, stage_id: str) -> dict:
        """Read the fixed setup status and bounded log tail for a stage."""
        return _setup_call("status", workspace_id, stage_id)

    def scinet_preflight(workspace_id: str, stage_id: str,
                         experiment: ScinetExperiment = "laya_smoke") -> dict:
        """Read-only gate and human-approval visibility; submits nothing and approves nothing."""
        if experiment not in EXPERIMENTS:
            raise ValueError("Unknown SciNet experiment")
        user, _, record = _staged(workspace_id, stage_id)
        runtime = record["remote_runtime"]
        py = _runtime_python(runtime)
        repo, pins = runtime + "/cranary-bundle", runtime + "/pinned/pins.json"
        parts = ["set +e"]
        for name, argv in _gate_script(py, repo, pins, experiment):
            parts.append(f"printf '@@BEGIN {name}\\n'; " + shlex.join(argv) +
                         f" 2>&1 | tail -c 4000; printf '@@END {name} %s\\n' \"${{PIPESTATUS[0]}}\"")
        parts.append("printf '@@BEGIN pins\\n'; " + shlex.join([
            _validate_python(settings.training_bootstrap_python, "bootstrap Python"),
            "-c", PINS_READER, pins]) + " 2>&1 | tail -c 8000; printf '@@END pins %s\\n' \"${PIPESTATUS[0]}\"")
        result = _call(settings, user, ["/bin/bash", "-lc", "; ".join(parts)], timeout=110)
        response = _result(result)
        response.update({"command": "scinet_preflight", "stage_id": stage_id,
                         "experiment": experiment, "success": False, "ready": False})
        if result.get("error") in {"scinet_auth_required", "scinet_broker_unavailable"} \
                or result.get("exit_code") is None:
            response["error"] = result.get("error", "scinet_unreachable")
            return response
        text = response.pop("stdout")
        response.pop("stderr", None)
        gates, pins_info = [], None
        for name, body, code in re.findall(r"@@BEGIN (\S+)\n(.*?)@@END \1 (\d+)\n", text, re.S):
            if name == "pins":
                if code == "0":
                    try:
                        pins_info = json.loads(body.strip().splitlines()[-1])
                    except (ValueError, IndexError):
                        pass
                continue
            gates.append({"gate": name, "exit_code": int(code), "output": body[-2000:]})
        expected = {name for name, _ in _gate_script(py, repo, pins, experiment)}
        passed = {g["gate"] for g in gates if g["exit_code"] == 0}
        approvals = {}
        for field in APPROVAL_FIELDS[experiment]:
            value = (pins_info or {}).get("pins", {}).get(field)
            approvals[field] = {"recorded": bool(value), "approver": value if value else None,
                                "suspect_agent_identity": bool(value and AGENT_APPROVER_RE.search(str(value)))}
        stage_record = ledger.stage(stage_id)
        limits = _approved_limits(stage_record, experiment)
        resources_ok = True
        if limits is not None:
            walltime = str(getattr(settings, "training_full_walltime", "") or "")
            resources_ok = bool(WALLTIME_RE.fullmatch(walltime)) and walltime != "00:00:00" \
                and _seconds(walltime) <= _seconds(limits["max_walltime"])
            response["resource_limits"] = {
                "approved": limits, "configured_walltime": walltime, "configured_gpus": 1,
                "full_runs_enabled": bool(getattr(settings, "training_allow_full_runs", False)),
                "within_approved_limits": resources_ok}
        if experiment in LEDGERED_APPROVAL_REQUIRED:
            reviewers = _ledgered_approval_reviewers(stage_record, experiment, stage_id)
            bound = bool(reviewers) and limits is not None \
                and all(a["approver"] in reviewers for a in approvals.values())
            resources_ok = resources_ok and bound
            response["ledgered_approval"] = {"required": True, "recorded": bool(reviewers),
                                             "bound_to_pins": bound}
        response.update({
            "gates": gates, "approvals": approvals,
            "pins_sha256": (pins_info or {}).get("pins_sha256"),
            "pins": (pins_info or {}).get("pins"),
            "pins_missing": pins_info is None,
            "ready": expected <= passed and pins_info is not None
            and all(a["recorded"] and not a["suspect_agent_identity"] for a in approvals.values())
            and resources_ok,
            "setup_state": stage_record.get("setup_state"),
            "human_approval_steps": [
                "On a SciNet login node, as yourself, review " + pins + " and the gate output above.",
                "Either edit the null *_by fields with your own name, AgentPorter never writes them without explicit human confirmation via scinet_record_approvals ("
                + repr(_required_confirmation(experiment, stage_id)) + ").",
                "Re-run scinet_preflight and confirm pins_sha256 matches what you reviewed before scinet_submit.",
            ],
        })
        response["success"] = True
        return response

    def scinet_record_approvals(workspace_id: str, stage_id: str, reviewer: str,
                                confirmation: str, approved_fields: list[str],
                                device: str = APPROVAL_DEVICE,
                                experiment: str = "laya_smoke") -> dict:
        """Record explicit human approvals (laya_smoke, laya_expA or stage-bound laya_expB); fail closed."""
        if experiment not in APPROVAL_CONFIRMATIONS:
            raise ValueError("Approvals can only be recorded for laya_smoke, laya_expA or laya_expB")
        user, _, record = _staged(workspace_id, stage_id)
        authorized = str(getattr(settings, "approval_reviewer", "") or settings.user)
        required = _required_confirmation(experiment, stage_id)
        if confirmation != required:
            raise PermissionError("explicit human confirmation is required: " + required)
        if reviewer != authorized or AGENT_APPROVER_RE.search(reviewer):
            raise PermissionError("reviewer is not the authorized human reviewer")
        if device != APPROVAL_DEVICE:
            raise ValueError("device must be cuda")
        fields = APPROVAL_FIELDS[experiment]
        if not isinstance(approved_fields, list) or sorted(approved_fields) != sorted(fields):
            raise ValueError(f"approved_fields must be exactly the {experiment} approval fields: "
                             + ", ".join(fields))
        pins = record["remote_runtime"] + "/pinned/pins.json"
        result = _call(settings, user, _remote_python_command(
            _validate_python(settings.training_bootstrap_python, "bootstrap Python"),
            REMOTE_APPROVAL_RECORDER,
            [pins, reviewer, device, json.dumps(fields), stage_id, workspace_id, experiment]), timeout=60)
        response = _result(result)
        response.update({"command": "scinet_record_approvals", "stage_id": stage_id,
                         "experiment": experiment, "success": False, "reviewer": reviewer})
        if experiment in APPROVAL_LIMITS:
            response["approved_limits"] = APPROVAL_LIMITS[experiment]
        if result.get("error"):
            response["error"] = result["error"]
            return response
        if response["timed_out"]:
            response["error"] = "approval_recording_timeout"
            response["next"] = "run scinet_preflight to check pins before retrying approval recording"
            return response
        if response["truncated"]:
            response["error"] = "invalid_approval_receipt"
            response["reason"] = "approval_receipt_truncated"
            return response
        if result.get("exit_code") != 0 and not response["stdout"].strip():
            response["error"] = "approval_recording_failed"
            return response
        try:
            report = json.loads(response["stdout"].strip().splitlines()[-1])
            if not isinstance(report, dict):
                raise ValueError("approval receipt must be an object")
        except (ValueError, IndexError, KeyError):
            response["error"] = "invalid_approval_receipt"
            return response
        response.pop("stdout", None)
        response.pop("stderr", None)
        response.update(report)
        if report.get("state") in {"recorded", "unchanged"} and result.get("exit_code") == 0:
            response["success"] = True
            limits = APPROVAL_LIMITS.get(experiment)
            # Limits are ledgered even when pins were already set so submit can enforce them.
            if report["state"] == "recorded" or (limits and _approved_limits(record, experiment) is None):
                entry = {"time": report.get("audit_time"), "reviewer": reviewer,
                         "workspace_id": workspace_id, "stage_id": stage_id, "device": device,
                         "experiment": experiment, "confirmation": required,
                         "changed_fields": report.get("changed_fields") or [],
                         "pins_sha256": report.get("pins_sha256")}
                if limits:
                    entry["limits"] = dict(limits)
                ledger.update_stage(stage_id, approvals=(record.get("approvals") or []) + [entry])
            response["next"] = "run scinet_preflight to verify gates against the updated pins"
        else:
            response["error"] = report.get("error", "approval_refused")
        return response

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
        if experiment not in EXPERIMENTS:
            raise ValueError("Unknown SciNet experiment")
        full = experiment != "laya_smoke"
        if full:
            if not getattr(settings, "training_allow_full_runs", False):
                raise PermissionError("Full Laya training submission is not enabled by deployment policy")
            walltime = _full_walltime(settings)
        else:
            walltime = "00:15:00"
        if not ID_RE.fullmatch(stage_id):
            raise ValueError("Invalid SciNet stage_id")
        record = ledger.stage(stage_id)
        if not record or record.get("workspace_id") != workspace_id:
            raise PermissionError("stage_id was not created by this workspace")
        limits = _approved_limits(record, experiment)
        if limits is not None and (limits.get("gpus") != 1 or
                                   _seconds(walltime) > _seconds(limits["max_walltime"])):
            raise PermissionError(f"Configured walltime {walltime} exceeds the human-approved "
                                  f"{experiment} limit of {limits['max_walltime']} on 1 GPU")
        if experiment in LEDGERED_APPROVAL_REQUIRED and (
                limits is None or not _ledgered_approval_reviewers(record, experiment, stage_id)):
            raise PermissionError(f"{experiment} requires a human approval recorded for this stage "
                                  "via scinet_record_approvals")
        if full and ledger.jobs_for(stage_id, experiment):
            return {"target": "scinet_training", "command": "scinet_submit", "success": False,
                    "error": "already_submitted", "job_id": ledger.jobs_for(stage_id, experiment)[-1]["job_id"]}
        template = _handoff_dir(ws) / EXPERIMENTS[experiment][0]
        if not template.is_file() or _sha256(template) != record.get("files", {}).get(template.name):
            raise ValueError("Sbatch template changed after staging")
        account = _validate_token(settings.training_account, "account")
        partition = _validate_token(settings.training_partition, "partition")
        runtime = record["remote_runtime"]
        py = _runtime_python(runtime)
        pins, repo, logs = runtime + "/pinned/pins.json", runtime + "/cranary-bundle", runtime + "/logs"
        script = template.read_text(encoding="utf-8")
        script = script.replace("@SLURM_ACCOUNT@", account).replace("@CPUS_PER_TASK@", str(settings.training_cpus_per_task))
        script = script.replace("@SCRATCH_LOG_DIR@", logs)
        if full:
            _validate_full_walltime_placeholders(script)
            # The Slurm directive and any soft trainer budget share the same validated walltime.
            script = script.replace("@WALLTIME_HH_MM_SS@", walltime)
        partition_in_template = script.count("@SLURM_PARTITION@")
        if partition_in_template > 1:
            raise ValueError("Smoke template has duplicate partition placeholders")
        script = script.replace("@SLURM_PARTITION@", partition)
        unfilled = sorted(set(PLACEHOLDER_RE.findall(script)))
        if unfilled:
            raise ValueError("Smoke template contains an unfilled placeholder: " + ", ".join(unfilled))
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
        first_exec = next((i for i, line in enumerate(lines)
                           if i and line.strip() and not line.lstrip().startswith("#")), len(lines))
        if not lines or not lines[0].startswith("#!") or \
                any(line.lstrip().startswith("#SBATCH") for line in lines[first_exec:]):
            raise ValueError("Sbatch directives must follow the shebang and precede executable statements")
        lines[first_exec:first_exec] = [
            "export CRANARY_SCRATCH=" + shlex.quote(runtime),
            "export CRANARY_REPO=" + shlex.quote(repo),
            "export CRANARY_PINS=" + shlex.quote(pins),
            "export CRANARY_PYTHON=" + shlex.quote(py),
        ]
        rendered = ("\n".join(lines) + "\n").encode()
        required = [b"#SBATCH --gpus-per-node=1", b"#SBATCH --nodes=1",
                    f"#SBATCH --time={walltime}".encode(),
                    f"#SBATCH --account={account}".encode(),
                    f"#SBATCH --partition={partition}".encode(),
                    f"#SBATCH --output={logs}/%x-%j.out".encode()]
        if any(rendered.count(item) != 1 for item in required) or \
                rendered.count(b"#SBATCH --time=") != 1 or \
                any(line.startswith("#SBATCH --error=") and not line.startswith(f"#SBATCH --error={logs}/")
                    for line in lines):
            raise ValueError("Job resource bounds are invalid")
        preflight = "set -e; " + shlex.join(["mkdir", "-p", "-m", "700", logs]) + " && " + " && ".join(
            shlex.join(argv) for _, argv in _gate_script(py, repo, pins, experiment))
        preflight_result = _call(settings, user, ["/bin/bash", "-lc", preflight], timeout=120)
        if preflight_result.get("exit_code") != 0 or preflight_result.get("timed_out"):
            response = _result(preflight_result)
            response.update({"command": "scinet_submit", "success": False,
                             "error": "approval_or_checksum_gate_failed"})
            return response
        script_path = f"{runtime}/{experiment}-{_sha256_bytes(rendered)[:16]}.sbatch"
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
                        "stage_id": stage_id, "runtime_root": runtime, "experiment": experiment,
                        "run_dir": EXPERIMENTS[experiment][1]})
        return {"target": "scinet_training", "command": "scinet_submit", "success": True,
                "job_id": job_id, "stage_id": stage_id, "experiment": experiment,
                "resources": {"gpus": 1, "walltime": walltime,
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
            [record["runtime_root"], job_id, kind, record.get("run_dir", "laya-smoke")]), max_output=MAX_LOG_OUTPUT)
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
        "scinet_setup": scinet_setup,
        "scinet_setup_status": scinet_setup_status,
        "scinet_preflight": scinet_preflight,
        "scinet_record_approvals": scinet_record_approvals,
    }

