"""Fixed, inference-only SciNet flow for the digest-pinned Laya bundle."""

from __future__ import annotations

import hashlib
import secrets
import base64
import csv
import io
import json
import math
import os
import re
import shlex
import stat
import tempfile
import time
import uuid
import fcntl
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.tools.scinet_training import (
    ID_RE,
    MAX_REMOTE_OUTPUT,
    _call,
    _identity,
    _remote_python_command,
    _result,
    _validate_remote_root,
    _validate_token,
    _validate_python,
)

STAGE = "standalone-inference"
ScinetInferenceExperiment = Literal["laya_inference"]
INFERENCE_EXPERIMENT: ScinetInferenceExperiment = "laya_inference"
SCHEMA = "laya-scinet-inference-v2"
ORIGINAL_PROTOCOL_SHA256 = "8f620de59cf930ad6724528898b7c168f2c9258a266b7a3b07e3264f25dc516b"
TEMPLATE_SHA256 = "5d41bf4b5b533e8147ba7c6a38e31fc4ef19bbe1d2d4f8c17f3d15d870e2b79f"
MANIFEST_SHA256 = "d0032d8a9bb6fc3580b2e1d9118bc5ca6f99defd6bfdfdf641a3e59fc02a91c7"
MAX_WALLTIME = "00:30:00"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
STATIC_FILES = frozenset(
    {
        "data/cohort.csv",
        "data/b0.csv",
        "sources/protocol.json",
        "sources/recheck.py",
        "sources/laya-cranary-serve.py",
        "sources/laya_state.py",
        "sources/laya_provenance.py",
        "sources/laya_issue_contract.py",
        "sources/manifests/claims_vs_actual_v1.json",
        "code/handoff.py",
        "code/offline_runner.py",
        "code/inference.sbatch.template",
        "code/README.md",
        "code/runtime_preflight.py",
        "code/prepare_runtime.sh",
        "code/requirements-inference.lock",
        "code/evaluate_return.py",
    }
)
CASE_RE = re.compile(r"P[0-9]{4}_(?:pos|ctl)\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
NUMERIC_JOB_ID_RE = re.compile(r"[1-9][0-9]{0,19}\Z")
MAX_RESULT_FILE_BYTES = 8192
MAX_RESULT_TRANSFER_BYTES = 160 * 1024
MAX_RESULT_RESPONSE_BYTES = 256 * 1024
PREDICTION_FIELDS = {
    "case_id", "score", "decision", "state_sha256", "context_file_sha256",
    "manifest_id", "checkpoint_sha256", "observed_revision", "process_init_id",
}
RESULT_FIELDS = {
    "prediction", "record_sha256", "manifest_sha256", "device", "runtime",
    "runtime_versions", "stage_id", "runtime_catalog_sha256",
}
RUNTIME_DISTRIBUTIONS = {
    "laya", "torch", "transformers", "safetensors", "huggingface_hub", "triton", "python"
}
RUNTIME_VERSIONS = {
    "laya": "0.3.28", "torch": "2.9.1", "transformers": "5.0.0",
    "safetensors": "0.8.0", "huggingface_hub": "1.33.0", "triton": "3.5.1",
}
REVISION = "7b928d828b7b0e022f929d9bd2e44165aa270148"
CHECKPOINT_SHA256 = "891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c"
RESUME_PROTOCOL_SHA256 = "1bdc5716853b98b887895d7088c70b0e0c5bb37d643adfa4a10de70896d7a6b4"


# One fixed snippet is executed locally and embedded verbatim in the remote reader.
# Generic GPU totals cannot establish H100 type without a typed allocation.
TRES_NORMALIZER_SOURCE = r'''def _one_h100_allocation(tres):
    if not isinstance(tres,str) or not tres or len(tres)>8192:
        return False
    resources={}
    for item in tres.split(","):
        parts=item.strip().lower().split("=")
        if len(parts)!=2:
            return False
        name,count=(p.strip() for p in parts)
        if not name or name in resources or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?(?:[kmgtpe](?:i?b)?)?",count):
            return False
        resources[name]=count
    if "gres/gpu" in resources and resources["gres/gpu"]!="1":
        return False
    if "node" in resources and resources["node"]!="1":
        return False
    typed=[(k,v) for k,v in resources.items() if k.startswith("gres/gpu:")]
    if len(typed)!=1 or typed[0][0] not in {"gres/gpu:h100","gres/gpu:nvidia_h100_80gb_hbm3"} or typed[0][1]!="1":
        return False
    return True
'''
exec(TRES_NORMALIZER_SOURCE)

RESULT_READER_PYTHON = "/usr/bin/python3"
REMOTE_INFERENCE_RESULTS = 'import base64,json,os,re,stat,subprocess,sys\n' + TRES_NORMALIZER_SOURCE + r'''
scratch,job,stage,case_list=sys.argv[1:5]
if not re.fullmatch(r"[1-9][0-9]{0,19}",job) or not re.fullmatch(r"[a-f0-9]{32}",stage): raise SystemExit(64)
if not re.fullmatch(r"/scratch/[A-Za-z0-9_./-]+",scratch) or ".." in scratch.split("/") or "//" in scratch: raise SystemExit(64)
root=scratch+"/runs/"+job+"/results"
if os.path.islink(root) or os.path.realpath(root)!=root or not os.path.isdir(root): raise SystemExit(65)
try:
 p=subprocess.run(["/usr/bin/sacct","-n","-P","-j",job,"-o","JobIDRaw,State,ExitCode,AllocTRES"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
 if p.returncode!=0: raise ValueError("scheduler_unavailable")
 rows=[]
 for line in p.stdout.decode("utf-8","strict").splitlines():
  fields=line.split("|")
  if len(fields)==4 and fields[0]==job: rows.append(fields)
 if len(rows)!=1: raise ValueError("scheduler_job_missing_or_ambiguous")
 jobid,state,exitcode,tres=rows[0]
 state_name=state.strip()
 if state_name!="COMPLETED" or exitcode.strip()!="0:0" or not _one_h100_allocation(tres): raise ValueError("scheduler_attestation_failed")
 names=[]
 with os.scandir(root) as it:
  for entry in it:
   names.append(entry.name)
   if len(names)>42: raise ValueError("result_inventory_incomplete")
 case_ids=case_list.split(",")
 if len(case_ids)!=42 or len(set(case_ids))!=42 or any(not re.fullmatch(r"P[0-9]{4}_(?:pos|ctl)",c) for c in case_ids): raise ValueError("invalid_pinned_case_inventory")
 expected={c+".json" for c in case_ids}
 if len(names)!=42 or set(names)!=expected: raise ValueError("result_inventory_incomplete")
 names.sort()
 files=[]; total=0
 for name in names:
  path=os.path.join(root,name)
  if os.path.islink(path): raise ValueError("result_symlink")
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,"rb") as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>8192: raise ValueError("unsafe_or_oversized_result")
   data=f.read(8193)
  if len(data)>8192: raise ValueError("oversized_result")
  total+=len(data)
  if total>163840: raise ValueError("result_transfer_too_large")
  files.append({"name":name,"data":base64.b64encode(data).decode("ascii")})
 out={"job":{"job_id":jobid,"state":state_name,"exit_code":exitcode.strip(),"alloc_tres":tres},"files":files}
 raw=json.dumps(out,sort_keys=True,separators=(",",":" )).encode()
 if len(raw)>262144: raise ValueError("result_response_too_large")
 sys.stdout.buffer.write(raw)
except Exception as e:
 print(json.dumps({"error":str(e) if isinstance(e,ValueError) else "remote_read_failed"},separators=(",",":")))
 raise SystemExit(65)
'''


RESULT_READER_SHA256 = "c0bb58eefab06f9bb5428b422d920168eb1a4de363c401054dd6d1b0140e7a61"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("inference manifest contains a duplicate JSON key")
        result[key] = value
    return result


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8") + b"\n"


def _parse_json(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON value")),
    )


def _cohort_rows(bundle: Path, manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    try:
        with (bundle / "data" / "cohort.csv").open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError("pinned inference cohort is unreadable") from exc
    if (not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames))
            or len(rows) != 42 or any(None in row or None in row.values() for row in rows)):
        raise ValueError("pinned inference cohort is malformed")
    cases = [row.get("case_id") for row in rows]
    if cases != manifest.get("cases"):
        raise ValueError("pinned inference cohort case inventory differs from manifest")
    return {str(row["case_id"]): row for row in rows}


def _check_result_piece(raw: bytes, case_id: str, row: dict[str, str], stage_id: str,
                        runtime_digest: str) -> dict[str, Any]:
    if len(raw) > MAX_RESULT_FILE_BYTES:
        raise ValueError("inference result piece exceeds 8 KiB")
    value = _parse_json(raw)
    if not isinstance(value, dict) or set(value) != RESULT_FIELDS or raw != _canonical_json(value):
        raise ValueError("inference result piece is not canonical or has an invalid schema")
    if (value.get("manifest_sha256") != MANIFEST_SHA256
            or value.get("device") != "cuda:H100"
            or value.get("runtime") != "laya==0.3.28"
            or value.get("stage_id") != stage_id
            or value.get("runtime_catalog_sha256") != runtime_digest):
        raise ValueError("inference result stage, model, or runtime binding mismatch")
    versions = value.get("runtime_versions")
    if (not isinstance(versions, dict) or set(versions) != RUNTIME_DISTRIBUTIONS
            or any(versions.get(name) != expected for name, expected in RUNTIME_VERSIONS.items())
            or not isinstance(versions.get("python"), str)
            or not re.fullmatch(r"3\.12\.[0-9]+", versions["python"])
            or any(not isinstance(item, str) or not 0 < len(item) <= 80
                   or not item.isprintable() for item in versions.values())):
        raise ValueError("inference result runtime inventory is invalid")
    prediction = value.get("prediction")
    if not isinstance(prediction, dict) or set(prediction) != PREDICTION_FIELDS:
        raise ValueError("inference prediction schema is invalid")
    if (value.get("record_sha256") != hashlib.sha256(
            json.dumps(prediction, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()):
        raise ValueError("inference prediction digest mismatch")
    expected_context = row.get("context_file_sha256")
    if (prediction.get("case_id") != case_id
            or prediction.get("context_file_sha256") != expected_context
            or prediction.get("state_sha256") != row.get("state_sha256")
            or prediction.get("checkpoint_sha256") != CHECKPOINT_SHA256
            or prediction.get("observed_revision") != REVISION
            or prediction.get("manifest_id") != "claims_vs_actual_v2"):
        raise ValueError("inference prediction case or model provenance mismatch")
    score = prediction.get("score")
    if not isinstance(score, str):
        raise ValueError("inference score must be frozen decimal text")
    try:
        numeric_score = float(score)
    except ValueError as exc:
        raise ValueError("inference score is invalid") from exc
    expected_decision = "risk" if numeric_score >= 0.70 else "abstain" if numeric_score >= 0.40 else "clear"
    if (not math.isfinite(numeric_score) or not 0 <= numeric_score <= 1
            or prediction.get("decision") != expected_decision
            or not isinstance(prediction.get("process_init_id"), str)
            or not 1 <= len(prediction["process_init_id"]) <= 100):
        raise ValueError("inference prediction score or decision is invalid")
    return value


def _regular_file(path: Path, root: Path) -> os.stat_result:
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("bundle contains an unsafe path")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("bundle files must be regular, single-link files")
    if info.st_size > MAX_FILE_BYTES:
        raise ValueError("bundle file exceeds the 2 MiB limit")
    return info


def _verify_bundle(
    bundle: Path, expected_sha256: str, workspace_root: str | Path | None = None
) -> dict[str, Any]:
    if expected_sha256 != MANIFEST_SHA256:
        raise ValueError("manifest digest differs from the fixed reviewed release")
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("fixed inference package directory is missing or unsafe")
    root = bundle.resolve()
    if workspace_root is not None:
        workspace = Path(os.path.abspath(workspace_root))
        if Path(workspace_root).is_symlink():
            raise ValueError("registered workspace path is a symlink")
        try:
            relative = Path(os.path.abspath(bundle)).relative_to(workspace)
        except ValueError as exc:
            raise ValueError("inference package resolves outside its registered workspace") from exc
        current = workspace
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("inference package path contains a symlink")
    manifest_path = bundle / "manifest.json"
    _regular_file(manifest_path, root)
    if _sha256(manifest_path) != expected_sha256:
        raise ValueError("inference manifest SHA-256 does not match the independent pin")
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("inference manifest is unreadable JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError("inference manifest must be an object")
    if (
        manifest.get("schema") != SCHEMA
        or manifest.get("stage") != STAGE
        or manifest.get("original_protocol_sha256") != ORIGINAL_PROTOCOL_SHA256
        or manifest.get("execution_change") != "cpu to one H100; inference only"
        or manifest.get("split") != "train_val"
        or manifest.get("no_holdout") is not True
        or manifest.get("revision") != "7b928d828b7b0e022f929d9bd2e44165aa270148"
        or manifest.get("weights_sha256")
        != "891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c"
        or manifest.get("runtime") != "laya==0.3.28"
        or manifest.get("max_len") != 8192
        or manifest.get("model") != "convaiinnovations/laya"
    ):
        raise ValueError("manifest does not match the fixed Laya inference contract")
    cases = manifest.get("cases")
    files = manifest.get("files")
    if (
        not isinstance(cases, list)
        or len(cases) != 42
        or not all(isinstance(case, str) and CASE_RE.fullmatch(case) for case in cases)
        or len(set(cases)) != 42
        or not isinstance(files, dict)
    ):
        raise ValueError("manifest case list or file map is invalid")
    expected_files = STATIC_FILES | {f"contexts/{case}.json" for case in cases}
    if set(files) != expected_files:
        raise ValueError("manifest file set differs from the fixed allowlist")
    actual_files: set[str] = set()
    total = manifest_path.stat().st_size
    for current, dirs, names in os.walk(bundle, followlinks=False):
        current_path = Path(current)
        for dirname in dirs:
            if (current_path / dirname).is_symlink():
                raise ValueError("bundle contains a symlink directory")
        for name in names:
            path = current_path / name
            if path == manifest_path:
                continue
            rel = PurePosixPath(path.relative_to(bundle).as_posix())
            if rel.is_absolute() or ".." in rel.parts or str(rel) not in expected_files:
                raise ValueError("bundle contains an unlisted file")
            info = _regular_file(path, root)
            total += info.st_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("inference bundle exceeds the 32 MiB limit")
            want = files[str(rel)]
            if not isinstance(want, str) or not SHA_RE.fullmatch(want):
                raise ValueError("manifest contains an invalid file SHA-256")
            if _sha256(path) != want:
                raise ValueError(f"bundle file SHA-256 mismatch: {rel}")
            actual_files.add(str(rel))
    if actual_files != expected_files:
        raise ValueError("inference bundle is missing allowlisted files")
    if files["code/inference.sbatch.template"] != TEMPLATE_SHA256:
        raise ValueError("inference Slurm template differs from the reviewed template")
    return manifest


APPROVAL_DOMAIN = "agentporter.scinet.laya-inference.approval.v2"
APPROVAL_LIFETIME_SECONDS = 3600
TRUSTED_APPROVAL_PUBLIC_KEY_PATH = Path("/etc/agentporter/laya-inference-approval.pub")
MAX_APPROVAL_PUBLIC_KEY_BYTES = 45  # raw 32 bytes or canonical base64 with optional LF


def _trusted_key_owner_uid() -> int:
    """Root is the production trust anchor; tests may patch this function only."""
    return 0


def _configured_reviewer(settings: Any) -> str:
    reviewer = str(getattr(settings, "inference_approval_reviewer", "") or "").strip()
    if not reviewer:
        raise PermissionError("explicit SciNet inference approval reviewer is not configured")
    return reviewer


def _approval_public_key() -> Ed25519PublicKey:
    """Read only the fixed operator-installed key, never agent configuration."""
    path = TRUSTED_APPROVAL_PUBLIC_KEY_PATH
    parent_fd = key_fd = None
    try:
        owner = _trusted_key_owner_uid()
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner
                or parent.st_mode & 0o022 or path.parent.resolve(strict=True) != path.parent):
            raise ValueError("untrusted public key parent")
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened_parent = os.fstat(parent_fd)
        if (not stat.S_ISDIR(opened_parent.st_mode) or opened_parent.st_uid != owner
                or opened_parent.st_mode & 0o022
                or (parent.st_dev, parent.st_ino) != (opened_parent.st_dev, opened_parent.st_ino)):
            raise ValueError("public key parent changed")
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_mode & 0o022 or info.st_nlink != 1
                or info.st_size > MAX_APPROVAL_PUBLIC_KEY_BYTES):
            raise ValueError("untrusted public key file")
        key_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        opened = os.fstat(key_fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner
                or opened.st_mode & 0o022 or opened.st_nlink != 1
                or opened.st_size > MAX_APPROVAL_PUBLIC_KEY_BYTES
                or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ValueError("public key file changed")
        encoded = os.read(key_fd, MAX_APPROVAL_PUBLIC_KEY_BYTES + 1)
        if len(encoded) > MAX_APPROVAL_PUBLIC_KEY_BYTES:
            raise ValueError("oversized public key")
        if len(encoded) == 32:
            raw = encoded
        else:
            encoded = encoded.removesuffix(b"\n")
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) != 32 or base64.b64encode(raw) != encoded:
                raise ValueError("invalid key encoding")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (OSError, ValueError, RuntimeError) as exc:
        raise PermissionError("trusted SciNet inference public key file is missing, unsafe, or invalid") from exc
    finally:
        if key_fd is not None:
            os.close(key_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _approval_payload(stage_id: str, manifest_sha256: str, runtime_catalog_sha256: str,
                      scratch: str, account: str, partition: str, reviewer: str,
                      nonce: str, *, context: dict[str, Any], issued_at: int,
                      not_after: int) -> dict[str, Any]:
    return {
        "domain": APPROVAL_DOMAIN,
        "stage_id": stage_id,
        "manifest_sha256": manifest_sha256,
        "runtime_catalog_sha256": runtime_catalog_sha256,
        "destination": {"scratch": scratch, "account": account, "partition": partition},
        "resources": {"gpu_count": 1, "gpu_type": "H100", "max_walltime": MAX_WALLTIME},
        "reviewer": reviewer,
        "nonce": nonce,
        "context": context,
        "issued_at": issued_at,
        "not_after": not_after,
    }


def _approval_context(settings, workspace_id, workspace_path, python, hf_cache):
    host = str(getattr(settings, "host", "") or "")
    user = str(getattr(settings, "user", "") or "")
    if not host or not user:
        raise PermissionError("explicit inference SSH host and user are required")
    bootstrap = getattr(settings, "training_bootstrap_python", "")
    if not isinstance(bootstrap, str):
        raise PermissionError("inference bootstrap Python is not configured safely")
    bootstrap = _validate_python(bootstrap, "bootstrap Python")
    return {
        "workspace": {"id": workspace_id, "path": str(Path(workspace_path).resolve())},
        "ssh": {"host": host, "user": user},
        "python": python, "bootstrap_python": bootstrap,
        "hf_cache": hf_cache, "template_sha256": TEMPLATE_SHA256,
    }


def _record_approval_payload(record, settings, context):
    issued_at, not_after = record.get("approval_issued_at"), record.get("approval_not_after")
    now = int(time.time())
    if (type(issued_at) is not int or type(not_after) is not int
            or not issued_at <= now < not_after
            or not 0 < not_after - issued_at <= APPROVAL_LIFETIME_SECONDS):
        raise PermissionError("inference approval challenge is expired or has invalid validity times")
    if record.get("approval_context") != context:
        raise PermissionError("inference approval workspace, SSH, or runtime context changed")
    return _approval_payload(
        record["stage_id"], record["manifest_sha256"], record["runtime_catalog_sha256"],
        record["scratch"], record["account"], record["partition"], _configured_reviewer(settings),
        record["approval_nonce"], context=context, issued_at=issued_at, not_after=not_after,
    )


def _signature_bytes(encoded: str) -> bytes:
    if not isinstance(encoded, str) or len(encoded) != 88:
        raise ValueError("Ed25519 signature must be base64 encoded 64 bytes")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Ed25519 signature must be base64 encoded 64 bytes") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise ValueError("Ed25519 signature must be base64 encoded 64 bytes")
    return signature


def _verify_approval(record: dict[str, Any], settings: Any, context: dict[str, Any]) -> None:
    reviewer = _configured_reviewer(settings)
    if record.get("approval_reviewer") != reviewer:
        raise PermissionError("inference approval reviewer configuration changed")
    if not isinstance(record.get("approval"), dict):
        raise PermissionError("signed stage-scoped inference approval is required")
    payload = _record_approval_payload(record, settings, context)
    raw = _canonical_json(payload)
    digest = hashlib.sha256(raw).hexdigest()
    approval = record.get("approval")
    if (not isinstance(approval, dict) or approval.get("payload_sha256") != digest
            or approval.get("payload_sha256") != record.get("approval_payload_sha256")
            or approval.get("reviewer") != reviewer):
        raise PermissionError("signed stage-scoped inference approval is required")
    try:
        _approval_public_key().verify(_signature_bytes(approval.get("signature", "")), raw)
    except InvalidSignature as exc:
        raise PermissionError("inference approval signature verification failed") from exc


def create_scinet_inference_preflight_tool(registry, settings):
    """Build a local-only readiness report for one fixed workspace location."""

    def scinet_inference_preflight(workspace_id: str) -> dict[str, Any]:
        ws = registry.get(workspace_id)
        if not ws.allow_execute or not ws.allow_scinet_training:
            raise PermissionError("SciNet training is not enabled for this workspace")
        bundle = inference_bundle_path(ws.path)
        expected = _expected_manifest(settings)
        report: dict[str, Any] = {
            "target": "scinet_inference",
            "command": "scinet_inference_preflight",
            "experiment": INFERENCE_EXPERIMENT,
            "stage": STAGE,
            "bundle_path": str(bundle),
            "submission_enabled": False,
            "runtime_readiness_verified": False,
            "trusted_retrieval_available": True,
            "resources": {"gpus": 1, "gpu_type": "H100", "walltime": MAX_WALLTIME},
            "blockers": [
                "reviewed runtime catalog and offline cache must pass read-only pre-submit checks",
                "results become available through the authenticated, ledger-bound receipt tool after submission",
                "the human must separately approve the generated stage ID and manifest digest",
                "SciNet account, partition, and H100 directive require operator verification",
            ],
        }
        try:
            manifest = _verify_bundle(bundle, expected, ws.path)
        except (OSError, ValueError) as exc:
            report.update({"success": False, "bundle_verified": False, "error": str(exc)})
            return report
        report.update({
            "success": True,
            "bundle_verified": True,
            "manifest_sha256": expected,
            "case_count": len(manifest["cases"]),
            "model_revision": manifest["revision"],
            "checkpoint_sha256": manifest["weights_sha256"],
        })
        return report

    return scinet_inference_preflight


def inference_bundle_path(workspace_path: str | Path) -> Path:
    return (
        Path(workspace_path)
        / "data-raw" / "cran-history" / "training" / "trillium"
        / "standalone-inference" / "package-v2"
    )


def _expected_manifest(settings) -> str:
    configured = str(getattr(settings, "inference_manifest_sha256", "") or "")
    if configured and configured != MANIFEST_SHA256:
        raise PermissionError("configured inference manifest differs from code-pinned release")
    return MANIFEST_SHA256


REMOTE_INFERENCE_RECEIVER = r'''import hashlib,json,os,sys
root,stage=sys.argv[1:3]
if not stage.isalnum() or len(stage)!=32: raise SystemExit(64)
if not root.startswith("/scratch/") or ".." in root.split("/"): raise SystemExit(64)
if os.path.lexists(root) and (os.path.islink(root) or os.path.realpath(root)!=root): raise SystemExit(64)
scratch=os.path.dirname(root)
os.makedirs(scratch,mode=0o700,exist_ok=True)
if os.path.islink(scratch) or os.path.realpath(scratch)!=scratch: raise SystemExit(64)
si=os.stat(scratch,follow_symlinks=False)
if si.st_uid!=os.getuid() or si.st_mode&0o077: raise SystemExit(64)
header=json.loads(sys.stdin.buffer.readline())
files=header.get("files")
if not isinstance(files,list) or not files or len(files)>64: raise SystemExit(64)
base=os.path.join(root,stage)
os.makedirs(root,mode=0o700,exist_ok=True)
if os.path.islink(root) or os.path.realpath(root)!=root: raise SystemExit(64)
ri=os.stat(root,follow_symlinks=False)
if ri.st_uid!=os.getuid() or ri.st_mode&0o077: raise SystemExit(64)
try: os.mkdir(base,0o700)
except FileExistsError: print(json.dumps({"success":False,"error":"destination_exists"})); raise SystemExit(73)
try:
 total=0; seen=set()
 for item in files:
  name=item["name"]; size=int(item["size"]); want=item["sha256"]
  parts=name.split("/")
  if not parts or any(p in ("",".","..") or p.startswith(".") for p in parts) or name in seen or size<0 or size>2097152: raise ValueError("invalid_file")
  seen.add(name); total+=size
  if total>33554432: raise ValueError("bundle_too_large")
  parent=os.path.join(base,*parts[:-1]); os.makedirs(parent,mode=0o700,exist_ok=True)
  path=os.path.join(base,*parts); h=hashlib.sha256(); remaining=size
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
  with os.fdopen(fd,"wb") as out:
   while remaining:
    data=sys.stdin.buffer.read(min(1048576,remaining))
    if not data: raise ValueError("truncated")
    out.write(data); h.update(data); remaining-=len(data)
  if h.hexdigest()!=want: raise ValueError("file_sha256_mismatch")
 with open(os.path.join(base,"manifest.json"),"rb") as f: mh=hashlib.sha256(f.read()).hexdigest()
 if mh!=header.get("manifest_sha256"): raise ValueError("manifest_sha256_mismatch")
 for current,dirs,names in os.walk(base,topdown=False):
  for d in dirs: os.chmod(os.path.join(current,d),0o500)
 os.chmod(base,0o500)
 print(json.dumps({"success":True,"stage_id":stage,"bundle":base,"manifest_sha256":mh},sort_keys=True))
except Exception as e:
 import shutil; shutil.rmtree(base,ignore_errors=True)
 print(json.dumps({"success":False,"error":type(e).__name__})); raise SystemExit(65)
'''

REMOTE_INFERENCE_VERIFY = r'''import hashlib,json,os,sys,stat
bundle,want=sys.argv[1:3]
if want!="d0032d8a9bb6fc3580b2e1d9118bc5ca6f99defd6bfdfdf641a3e59fc02a91c7" or os.path.realpath(bundle)!=bundle: raise SystemExit(64)
if os.path.islink(bundle) or not os.path.isdir(bundle): raise SystemExit(64)
bi=os.stat(bundle)
if bi.st_uid!=os.getuid() or bi.st_mode&0o077: raise SystemExit(64)
mp=os.path.join(bundle,"manifest.json")
mi=os.stat(mp,follow_symlinks=False)
if not stat.S_ISREG(mi.st_mode) or mi.st_nlink!=1 or mi.st_size>2097152 or mi.st_uid!=os.getuid() or mi.st_mode&0o077: raise SystemExit(64)
if hashlib.sha256(open(mp,"rb").read()).hexdigest()!=want: raise SystemExit(65)
m=json.load(open(mp,encoding="utf-8"))
cases=m.get("cases",[]); files=m.get("files",{})
expected={"data/cohort.csv","data/b0.csv","sources/protocol.json","sources/recheck.py","sources/laya-cranary-serve.py","sources/laya_state.py","sources/laya_provenance.py","sources/laya_issue_contract.py","sources/manifests/claims_vs_actual_v1.json","code/handoff.py","code/offline_runner.py","code/inference.sbatch.template","code/README.md","code/runtime_preflight.py","code/prepare_runtime.sh","code/requirements-inference.lock","code/evaluate_return.py"}|{"contexts/"+c+".json" for c in cases}
if m.get("schema")!="laya-scinet-inference-v2" or m.get("stage")!="standalone-inference" or len(cases)!=42 or len(set(cases))!=42 or set(files)!=expected: raise SystemExit(66)
actual=set(); total=os.path.getsize(mp)
for current,dirs,names in os.walk(bundle,followlinks=False):
 for d in dirs:
  if os.path.islink(os.path.join(current,d)): raise SystemExit(67)
 for n in names:
  p=os.path.join(current,n); rel=os.path.relpath(p,bundle).replace(os.sep,"/")
  if rel=="manifest.json": continue
  if rel not in expected or os.path.islink(p) or not os.path.isfile(p): raise SystemExit(68)
  info=os.stat(p,follow_symlinks=False)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or info.st_mode&0o077: raise SystemExit(68)
  size=info.st_size; total+=size
  if size>2097152 or total>33554432: raise SystemExit(69)
  if hashlib.sha256(open(p,"rb").read()).hexdigest()!=files.get(rel): raise SystemExit(70)
  actual.add(rel)
if actual!=expected or files.get("code/inference.sbatch.template")!="5d41bf4b5b533e8147ba7c6a38e31fc4ef19bbe1d2d4f8c17f3d15d870e2b79f": raise SystemExit(71)
print(json.dumps({"success":True,"manifest_sha256":want,"file_count":len(actual)+1}))
'''


class _InferenceLedger:
    def __init__(self, state_dir):
        if not state_dir:
            raise PermissionError("SciNet inference state directory is required")
        self.path = Path(state_dir) / "scinet_inference.json"
        self.lock_path = self.path.with_suffix(".lock")

    def locked(self):
        return _LedgerLock(self.lock_path, self.path)


class _LedgerLock:
    def __init__(self, lock_path, data_path):
        self.lock_path, self.data_path = lock_path, data_path

    def __enter__(self):
        self.data_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lock_info = os.fstat(self.fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
                or lock_info.st_uid != os.getuid() or lock_info.st_mode & 0o077):
            os.close(self.fd)
            raise PermissionError("SciNet inference ledger lock is unsafe")
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        try:
            if self.data_path.exists():
                info = self.data_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or info.st_mode & 0o077):
                    raise PermissionError("SciNet inference ledger file is unsafe")
            value = json.loads(self.data_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            value = {"stages": {}, "jobs": {}}
        except PermissionError:
            os.close(self.fd)
            raise
        except (OSError, ValueError) as exc:
            os.close(self.fd)
            raise PermissionError("SciNet inference ledger is unreadable") from exc
        if not isinstance(value, dict) or not isinstance(value.get("stages", {}), dict):
            os.close(self.fd)
            raise PermissionError("SciNet inference ledger is invalid")
        self.value = value
        return value

    def __exit__(self, *_):
        fd, temporary = tempfile.mkstemp(prefix=".inference-", dir=self.data_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(self.value, out, sort_keys=True)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.data_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            os.close(self.fd)


def _inference_settings(registry, settings, workspace_id):
    user, ws = _identity(registry, workspace_id, settings)
    if not ws.allow_scinet_training:
        raise PermissionError("SciNet inference requires workspace training permission")
    root = _validate_remote_root(getattr(settings, "training_remote_root", ""))
    scratch = str(getattr(settings, "inference_scratch_root", "") or "")
    python = str(getattr(settings, "inference_python", "") or "")
    cache = str(getattr(settings, "inference_hf_cache", "") or "")
    safe_remote_path = re.compile(r"/scratch/[A-Za-z0-9_./-]+\Z")
    if (not safe_remote_path.fullmatch(scratch) or ".." in scratch.split("/")
            or "//" in scratch):
        raise PermissionError("SciNet inference scratch must be a fixed /scratch path")
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", python)
            or ".." in python.split("/")):
        raise PermissionError("SciNet inference Python must be an absolute path")
    if (not safe_remote_path.fullmatch(cache) or ".." in cache.split("/")
            or "//" in cache):
        raise PermissionError("SciNet inference HF cache must be a fixed /scratch path")
    account = _validate_token(getattr(settings, "training_account", ""), "account")
    partition = _validate_token(getattr(settings, "training_partition", ""), "partition")
    _runtime_metadata(settings, scratch.rstrip("/"), python, cache.rstrip("/"))
    return user, ws, root, scratch.rstrip("/"), python, cache.rstrip("/"), account, partition


def _runtime_metadata(settings, scratch: str, python: str, cache: str) -> dict[str, str]:
    digest = str(getattr(settings, "inference_runtime_catalog_sha256", "") or "")
    if not SHA_RE.fullmatch(digest):
        raise PermissionError("independently reviewed inference runtime catalog SHA-256 is required")
    # Paths are private deployment configuration, never Action arguments. The catalog
    # has one fixed basename; neither callers nor the catalog can select executable code.
    for value in (python, cache):
        path = PurePosixPath(value)
        if (not re.fullmatch(r"/scratch/[A-Za-z0-9_./-]+", value)
                or any(p in (".", "..") for p in value.split("/"))
                or "//" in value or str(path) != value
                or not path.is_relative_to(PurePosixPath(scratch)) or str(path) == scratch):
            raise PermissionError("inference runtime and offline cache must be fixed paths under scratch")
    catalog = f"{scratch}/runtime-catalog.json"
    for value in (python, cache):
        if any(PurePosixPath(value).is_relative_to(PurePosixPath(f"{scratch}/{reserved}"))
               for reserved in ("stages", "runs", "logs", "submissions")):
            raise PermissionError("runtime inputs must be separate from stages and job outputs")
    if PurePosixPath(python).is_relative_to(PurePosixPath(cache)):
        raise PermissionError("inference interpreter must be separate from model cache")
    return {"runtime_catalog": catalog, "runtime_catalog_sha256": digest,
            "python": python, "hf_cache": cache}


def _validate_stage_record(record, stage_id, scratch, runtime):
    if (record.get("stage_id") != stage_id or record.get("manifest_sha256") != MANIFEST_SHA256
            or record.get("bundle") != f"{scratch}/stages/{stage_id}"
            or any(record.get(k) != v for k, v in runtime.items())):
        raise PermissionError("inference stage manifest or runtime configuration changed; restage required")


def _runtime_preflight_script(bundle: Path) -> str:
    """Embed only locally verified code; perform read-only, import-only checks.

    No provisioning script, candidate catalog mode, model load or CUDA device
    discovery is invoked. This checks artifacts on the login host; the fixed
    job retains its compute-node checks. Same-user/native code is a trust boundary.
    """
    manifest = _verify_bundle(bundle, MANIFEST_SHA256)
    sources = {}
    for name, rel in {
        "handoff": "code/handoff.py", "runtime_preflight": "code/runtime_preflight.py",
        "laya_provenance": "sources/laya_provenance.py",
    }.items():
        raw = (bundle / rel).read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["files"][rel]:
            raise PermissionError("embedded runtime preflight source changed")
        sources[name] = raw.decode("utf-8")
    # Suppress the fingerprint-only receipt; emit one combined receipt after all checks.
    verifier = REMOTE_INFERENCE_VERIFY.rsplit("print(json.dumps(", 1)[0]
    return verifier + "\nSOURCES=" + repr(sources) + r'''
from pathlib import Path
import types
scratch,cache,catalog,digest=sys.argv[3:7]
for value in (scratch,cache,catalog):
 p=Path(value)
 if not p.is_absolute() or not str(p).startswith("/scratch/") or ".." in p.parts: raise SystemExit(74)
 if p.resolve()!=p or not p.is_relative_to(Path(scratch)): raise SystemExit(74)
 info=p.stat()
 if info.st_uid!=os.getuid() or info.st_mode&0o077: raise SystemExit(74)
if not Path(scratch).is_dir() or not Path(cache).is_dir() or not Path(catalog).is_file(): raise SystemExit(74)
if not Path(sys.prefix).resolve().is_relative_to(Path(scratch)): raise SystemExit(74)
# Never inherit credentials or online library modes into dependency imports.
for key in ("HF_TOKEN","HUGGING_FACE_HUB_TOKEN","CRANARY_LAYA_TOKEN","PYTHONPATH","PYTHONHOME"):
 os.environ.pop(key,None)
for key in ("HF_HUB_OFFLINE","TRANSFORMERS_OFFLINE","HF_DATASETS_OFFLINE","PYTHONNOUSERSITE"):
 os.environ[key]="1"
os.environ["HF_HUB_CACHE"]=cache
os.environ["HUGGINGFACE_HUB_CACHE"]=cache
sys.dont_write_bytecode=True
# Fail closed if even import-time code attempts a network connection or filesystem write.
def readonly(event,args):
 if event.startswith("socket.") and event not in ("socket.__new__",): raise PermissionError("offline preflight")
 if event=="open" and args[0]!=os.devnull:
  mode,flags=args[1:3]
  if (isinstance(mode,str) and any(c in mode for c in "wax+")) or (isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)): raise PermissionError("read-only preflight")
 if event in ("os.mkdir","os.remove","os.rmdir","os.rename","os.link","os.symlink","os.chmod","os.chown","os.truncate","subprocess.Popen","os.system","os.exec","os.posix_spawn"):
  raise PermissionError("read-only preflight")
sys.addaudithook(readonly)
for name in ("handoff","runtime_preflight","laya_provenance"):
 module=types.ModuleType(name)
 module.__file__=os.path.join(bundle,"sources" if name=="laya_provenance" else "code",name+".py")
 sys.modules[name]=module
 exec(compile(SOURCES[name],module.__file__,"exec"),module.__dict__)
# Suppress dependency output, including native output; never expose artifact contents.
sys.stdout.flush(); sys.stderr.flush()
saved=[os.dup(1),os.dup(2)]
try:
 null=os.open(os.devnull,os.O_WRONLY)
 os.dup2(null,1); os.dup2(null,2); os.close(null)
 sys.modules["runtime_preflight"].verify_catalog(catalog,digest,cache,installed=True)
finally:
 for fd,prior in zip((1,2),saved): os.dup2(prior,fd); os.close(prior)
print(json.dumps({"success":True,"manifest_sha256":want,"file_count":len(actual)+1,
 "runtime_catalog_sha256":digest,"runtime_artifacts_verified":True,"model_loaded":False,"gpu_readiness":False}))
'''


def _isolated_remote_python_command(python, script, args):
    return ["/bin/bash", "-lc", shlex.join([python, "-I", "-B", "-c", script, *args])]


def _bundle_files(bundle: Path, expected: str, workspace_root: str | Path | None = None):
    manifest = _verify_bundle(bundle, expected, workspace_root)
    names = sorted(set(manifest["files"]) | {"manifest.json"})
    return manifest, [
        (name, bundle / name, expected if name == "manifest.json" else manifest["files"][name])
        for name in names
    ]


def create_scinet_inference_tools(registry, settings=None, state_dir=None):
    """Create inference stage, signature verification, submit, and result tools."""
    ledger = _InferenceLedger(state_dir)

    def scinet_inference_results(workspace_id: str, job_id: str) -> dict[str, Any]:
        """Retrieve fixed results over SSH and issue an AgentPorter-local receipt."""
        if not isinstance(job_id, str) or not NUMERIC_JOB_ID_RE.fullmatch(job_id):
            raise ValueError("SciNet inference job_id must be a numeric Slurm job ID")
        ws = registry.get(workspace_id)
        if not ws.allow_execute or not ws.allow_scinet_training:
            raise PermissionError("SciNet inference results require an enabled workspace")

        with ledger.locked() as data:
            jobs = data.get("jobs", {})
            stages = data.get("stages", {})
            if not isinstance(jobs, dict) or not isinstance(stages, dict):
                raise PermissionError("SciNet inference job ledger is invalid")
            job = jobs.get(job_id)
            if (not isinstance(job, dict)
                    or job.get("workspace_id") != workspace_id
                    or job.get("experiment") != INFERENCE_EXPERIMENT):
                raise PermissionError(
                    "SciNet inference job was not submitted by this workspace"
                )
            stage_id = job.get("stage_id")
            if not isinstance(stage_id, str) or not ID_RE.fullmatch(stage_id):
                raise PermissionError("SciNet inference job ledger binding is invalid")
            stage = stages.get(stage_id)
            if (not isinstance(stage, dict)
                    or stage.get("workspace_id") != workspace_id
                    or stage.get("state") != "submitted"
                    or stage.get("job_id") != job_id
                    or stage.get("manifest_sha256") != MANIFEST_SHA256):
                raise PermissionError("SciNet inference job ledger binding is invalid")
            stage_id_from_ledger = stage_id
            runtime_digest = stage.get("runtime_catalog_sha256")
            if not isinstance(runtime_digest, str) or not SHA_RE.fullmatch(runtime_digest):
                raise PermissionError("SciNet inference runtime catalog binding is invalid")
            scratch = stage.get("scratch")
            if (not isinstance(scratch, str)
                    or not re.fullmatch(r"/scratch/[A-Za-z0-9_./-]+", scratch)
                    or ".." in scratch.split("/") or "//" in scratch):
                raise PermissionError("SciNet inference scratch binding is invalid")

        user, current_ws, _root, configured_scratch, python, cache, _account, _partition = (
            _inference_settings(registry, settings, workspace_id)
        )
        runtime = _runtime_metadata(settings, configured_scratch, python, cache)
        if (configured_scratch != scratch
                or runtime["runtime_catalog_sha256"] != runtime_digest
                or stage.get("bundle") != f"{scratch}/stages/{stage_id_from_ledger}"
                or any(stage.get(key) != value for key, value in runtime.items())):
            raise PermissionError("inference ledger differs from the fixed approved runtime catalog")
        bundle = inference_bundle_path(ws.path)
        manifest = _verify_bundle(bundle, MANIFEST_SHA256, ws.path)
        cohort = _cohort_rows(bundle, manifest)
        # The source-bound manifest contains nonconsecutive package IDs;
        # never assume cases are numbered P0001..P0021.
        fixed_case_ids = ",".join(manifest["cases"])
        if hashlib.sha256(REMOTE_INFERENCE_RESULTS.encode("utf-8")).hexdigest() != RESULT_READER_SHA256:
            raise PermissionError("fixed inference result reader digest mismatch")
        remote = [RESULT_READER_PYTHON, "-I", "-B", "-c", REMOTE_INFERENCE_RESULTS,
                  scratch, job_id, stage_id_from_ledger, fixed_case_ids]
        transport = _call(settings, user, remote, timeout=60,
                          max_output=MAX_RESULT_RESPONSE_BYTES,
                          operation="inference_results")
        stdout = transport.get("stdout", b"")
        if not isinstance(stdout, bytes):
            stdout = str(stdout).encode("utf-8")
        if (transport.get("exit_code") != 0 or transport.get("timed_out")
                or transport.get("truncated") or len(stdout) > MAX_RESULT_RESPONSE_BYTES):
            raise PermissionError("authenticated SciNet result or scheduler retrieval failed")
        try:
            transfer = _parse_json(stdout)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise PermissionError("authenticated SciNet result response is invalid") from exc
        if not isinstance(transfer, dict) or set(transfer) != {"job", "files"}:
            raise PermissionError("authenticated SciNet result response is incomplete")
        scheduler = transfer["job"]
        if (not isinstance(scheduler, dict) or scheduler.get("job_id") != job_id
                or scheduler.get("state") != "COMPLETED"
                or scheduler.get("exit_code") != "0:0"
                or not _one_h100_allocation(scheduler.get("alloc_tres"))):
            raise PermissionError("Slurm did not attest COMPLETED, ExitCode 0:0, and one H100")
        entries = transfer["files"]
        expected_names = {f"{case}.json" for case in manifest["cases"]}
        if not isinstance(entries, list) or len(entries) != 42:
            raise PermissionError("SciNet result inventory is missing cases")
        local_files: dict[str, bytes] = {}
        total_bytes = 0
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"name", "data"}:
                raise PermissionError("SciNet result inventory entry is invalid")
            name = entry["name"]
            if (not isinstance(name, str) or name not in expected_names
                    or name in local_files or not isinstance(entry["data"], str)):
                raise PermissionError("SciNet returned an unapproved result name")
            try:
                raw = base64.b64decode(entry["data"], validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise PermissionError("SciNet result bytes are not valid base64") from exc
            if len(raw) > MAX_RESULT_FILE_BYTES:
                raise PermissionError("SciNet result bytes exceed the per-file limit")
            total_bytes += len(raw)
            if total_bytes > MAX_RESULT_TRANSFER_BYTES:
                raise PermissionError("SciNet result transfer exceeds the bounded size")
            case_id = name[:-5]
            try:
                _check_result_piece(raw, case_id, cohort[case_id], stage_id, runtime_digest)
            except (UnicodeError, ValueError, TypeError) as exc:
                raise PermissionError("SciNet result piece failed the pinned model and case contract") from exc
            local_files[name] = raw
        if set(local_files) != expected_names:
            raise PermissionError("SciNet result inventory is missing cases")
        piece_hashes = {name: hashlib.sha256(raw).hexdigest()
                        for name, raw in sorted(local_files.items())}
        receipt = {
            "schema": "laya-inference-execution-receipt-v1",
            "stage_id": stage_id,
            "manifest_sha256": MANIFEST_SHA256,
            "runtime_catalog_sha256": runtime_digest,
            "device": "cuda:H100",
            "original_protocol_sha256": ORIGINAL_PROTOCOL_SHA256,
            "original_resume_protocol_sha256": RESUME_PROTOCOL_SHA256,
            "jobs": [job_id],
            "pieces": piece_hashes,
        }
        receipt_bytes = _canonical_json(receipt)
        result = {
            "target": "scinet_inference",
            "command": "scinet_inference_results",
            "success": True,
            "workspace_id": workspace_id,
            "job_id": job_id,
            "job_source": "scinet_inference_submit",
            "stage_id": stage_id,
            "manifest_sha256": MANIFEST_SHA256,
            "runtime_catalog_sha256": runtime_digest,
            "source": "agentporter_protected_job_submission_ledger",
            "results_directory": f"{scratch}/runs/{job_id}/results",
            "scheduler_attestation": {
                "job_id": job_id, "state": "COMPLETED", "exit_code": "0:0",
                "h100_allocated": True,
            },
            "expected_case_count": 42,
            "observed_case_count": len(local_files),
            "complete": True,
            "trusted_receipt": receipt,
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_encoding": "canonical-json-utf8-newline",
            "result_files_base64": {name: base64.b64encode(raw).decode("ascii")
                                    for name, raw in sorted(local_files.items())},
            "result_bytes": total_bytes,
            "trusted_retrieval_available": True,
            "remote_call_made": True,
            "trust_boundary": (
                "AgentPorter issued this receipt from result bytes read over the "
                "configured authenticated SSH session and Slurm sacct response. "
                "This trusts SSH identity, Slurm records, and the remote sandbox; "
                "it is not cryptographic proof of GPU execution."
            ),
        }
        if len(json.dumps(result, separators=(",", ":")).encode("utf-8")) > MAX_RESULT_RESPONSE_BYTES:
            raise PermissionError("validated result response exceeds the 256 KiB API limit")
        return result

    def scinet_inference_stage(workspace_id: str) -> dict[str, Any]:
        user, ws, _root, scratch, _python, _cache, account, partition = _inference_settings(
            registry, settings, workspace_id
        )
        expected = _expected_manifest(settings)
        runtime = _runtime_metadata(settings, scratch, _python, _cache)
        reviewer = _configured_reviewer(settings)
        context = _approval_context(settings, workspace_id, ws.path, _python, _cache)
        _approval_public_key()
        bundle = inference_bundle_path(ws.path)
        manifest, files = _bundle_files(bundle, expected, ws.path)
        stage_id = "a" + uuid.uuid4().hex[1:]  # v2 handoff requires an initial letter
        nonce = secrets.token_hex(32)
        stage_root = f"{scratch}/stages"
        entries = [{"name": n, "size": p.stat().st_size, "sha256": h} for n, p, h in files]
        payload = json.dumps({"files": entries, "manifest_sha256": expected},
                             sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for _name, path, _hash in files:
            payload += path.read_bytes()
        result = _call(settings, user, _remote_python_command(
            settings.training_bootstrap_python, REMOTE_INFERENCE_RECEIVER,
            [stage_root, stage_id]), input_bytes=payload, timeout=900,
            max_output=MAX_REMOTE_OUTPUT)
        parsed = _result(result)
        parsed.update({"command": "scinet_inference_stage", "success": False,
                       "experiment": INFERENCE_EXPERIMENT})
        if result.get("exit_code") != 0 or result.get("timed_out") or result.get("truncated"):
            parsed["error"] = "inference_stage_transport_failed"
            return parsed
        try:
            receipt = json.loads(parsed["stdout"])
        except ValueError:
            parsed["error"] = "invalid_inference_stage_receipt"
            return parsed
        expected_remote_bundle = f"{stage_root}/{stage_id}"
        if (receipt.get("success") is not True or receipt.get("stage_id") != stage_id
                or receipt.get("manifest_sha256") != expected
                or receipt.get("bundle") != expected_remote_bundle):
            parsed["error"] = receipt.get("error", "inference_stage_rejected")
            return parsed
        issued_at = int(time.time())
        not_after = issued_at + APPROVAL_LIFETIME_SECONDS
        approval_payload = _approval_payload(
            stage_id, expected, runtime["runtime_catalog_sha256"], scratch, account,
            partition, reviewer, nonce, context=context, issued_at=issued_at, not_after=not_after,
        )
        approval_payload_sha256 = hashlib.sha256(_canonical_json(approval_payload)).hexdigest()
        with ledger.locked() as data:
            stages = data.setdefault("stages", {})
            if any(isinstance(item, dict) and item.get("approval_nonce") == nonce for item in stages.values()):
                raise PermissionError("inference approval challenge replay detected")
            stages[stage_id] = {
                "workspace_id": workspace_id, "stage_id": stage_id,
                "manifest_sha256": expected, "bundle": receipt["bundle"],
                "scratch": scratch, "account": account, "partition": partition,
                **runtime,
                "files": manifest["files"],
                "approval_nonce": nonce,
                "approval_reviewer": reviewer,
                "approval_payload_sha256": approval_payload_sha256,
                "approval_context": context,
                "approval_issued_at": issued_at, "approval_not_after": not_after,
                "state": "staged", "created_at": int(time.time()),
            }
        return {"target": "scinet_inference", "command": "scinet_inference_stage",
                "success": True, "experiment": INFERENCE_EXPERIMENT,
                "stage_id": stage_id, "manifest_sha256": expected,
                "bundle_path": receipt["bundle"], **runtime,
                "approval_authentication": "ed25519_signature_required",
                "trusted_retrieval_available": False,
                "destination": {"scratch": scratch, "account": account,
                                "partition": partition},
                "resources": {"gpus": 1, "gpu_type": "H100", "walltime": MAX_WALLTIME},
                "approval_payload": approval_payload,
                "approval_payload_sha256": approval_payload_sha256,
                "approval_payload_base64": base64.b64encode(_canonical_json(approval_payload)).decode("ascii"),
                "approval_signature_encoding": "base64-ed25519-64-byte-signature"}

    def scinet_inference_approve(
        workspace_id: str, stage_id: str, reviewer: str, signature: str
    ) -> dict[str, Any]:
        if not isinstance(stage_id, str) or not ID_RE.fullmatch(stage_id):
            raise ValueError("Invalid SciNet inference stage_id")
        if not isinstance(signature, str) or len(signature) > 88:
            raise ValueError("Ed25519 signature exceeds the 88-character limit")
        _signature_bytes(signature)
        _user, _ws, _root, scratch, python, _cache, account, partition = _inference_settings(
            registry, settings, workspace_id
        )
        runtime = _runtime_metadata(settings, scratch, python, _cache)
        expected_reviewer = _configured_reviewer(settings)
        if not isinstance(reviewer, str) or reviewer != expected_reviewer:
            raise PermissionError("reviewer must exactly match configured human approver")
        verifier = _approval_public_key()
        with ledger.locked() as data:
            record = data.get("stages", {}).get(stage_id)
            if not record or record.get("workspace_id") != workspace_id:
                raise PermissionError("inference stage was not created by this workspace")
            _validate_stage_record(record, stage_id, scratch, runtime)
            if record.get("state") != "staged":
                raise PermissionError("inference stage no longer awaiting approval")
            destination = {"scratch": scratch, "account": account, "partition": partition}
            if any(record.get(key) != value for key, value in destination.items()):
                raise PermissionError("inference stage destination configuration changed")
            if record.get("approval_reviewer") != expected_reviewer:
                raise PermissionError("reviewer differs from the reviewer shown in the signed challenge")
            payload = _record_approval_payload(
                record, settings,
                _approval_context(settings, workspace_id, _ws.path, python, _cache),
            )
            raw_payload = _canonical_json(payload)
            payload_digest = hashlib.sha256(raw_payload).hexdigest()
            if payload_digest != record.get("approval_payload_sha256"):
                raise PermissionError("inference approval challenge is stale or forged")
            if record.get("approval"):
                raise PermissionError("inference stage approval already recorded")
            try:
                verifier.verify(_signature_bytes(signature), raw_payload)
            except InvalidSignature as exc:
                raise PermissionError("inference approval signature verification failed") from exc
            record["approval"] = {
                "reviewer": expected_reviewer,
                "signature": signature,
                "payload_sha256": payload_digest,
                "signed_at": int(time.time()),
            }
        return {
            "target": "scinet_inference", "command": "scinet_inference_approve",
            "success": True, "stage_id": stage_id, "reviewer": expected_reviewer,
            "approval_payload_sha256": payload_digest,
            "authentication": "ed25519_verified",
            "resources": {"gpus": 1, "gpu_type": "H100", "walltime": MAX_WALLTIME},
        }

    def scinet_inference_submit(workspace_id: str, stage_id: str) -> dict[str, Any]:
        if not isinstance(stage_id, str) or not ID_RE.fullmatch(stage_id):
            raise ValueError("Invalid SciNet inference stage_id")
        user, _ws, _root, scratch, python, hf_cache, account, partition = _inference_settings(
            registry, settings, workspace_id
        )
        runtime = _runtime_metadata(settings, scratch, python, hf_cache)
        with ledger.locked() as data:
            record = data.get("stages", {}).get(stage_id)
            if not record or record.get("workspace_id") != workspace_id:
                raise PermissionError("inference stage was not created by this workspace")
            if any(record.get(k) != v for k, v in {
                "scratch": scratch, "account": account, "partition": partition
            }.items()):
                raise PermissionError("inference destination configuration changed after staging")
            if record.get("state") != "staged":
                raise PermissionError("inference stage submission is already reserved or complete")
            _validate_stage_record(record, stage_id, scratch, runtime)
            _verify_approval(record, settings,
                             _approval_context(settings, workspace_id, _ws.path, python, hf_cache))
            bundle = inference_bundle_path(registry.get(workspace_id).path)
            manifest, _files = _bundle_files(
                bundle, record["manifest_sha256"], registry.get(workspace_id).path
            )
            if manifest["files"] != record["files"]:
                raise PermissionError("local inference package fingerprint changed after stage")
            template = (bundle / "code" / "inference.sbatch.template").read_text(encoding="utf-8")
            rendered = render_inference_template(template, account, partition, scratch)
            record["state"] = "submitting"  # reserve before any remote side effect
            record["submit_reserved_at"] = int(time.time())
            data["stages"][stage_id] = record

        # Independent remote content/fingerprint verification immediately precedes submit.
        verify = _call(settings, user, _isolated_remote_python_command(
            python, _runtime_preflight_script(bundle),
            [record["bundle"], record["manifest_sha256"], scratch, hf_cache,
             runtime["runtime_catalog"], runtime["runtime_catalog_sha256"]]), timeout=300)
        if verify.get("exit_code") != 0 or verify.get("timed_out") or verify.get("truncated"):
            return {"target": "scinet_inference", "command": "scinet_inference_submit",
                    "success": False, "error": "remote_inference_runtime_or_fingerprint_failed",
                    "stage_id": stage_id}
        try:
            readiness = json.loads(_result(verify)["stdout"])
        except (ValueError, TypeError):
            readiness = {}
        if readiness != {"success": True, "manifest_sha256": record["manifest_sha256"],
                         "file_count": 60, "runtime_catalog_sha256": runtime["runtime_catalog_sha256"],
                         "runtime_artifacts_verified": True, "model_loaded": False,
                         "gpu_readiness": False}:
            return {"success": False, "error": "invalid_inference_runtime_receipt",
                    "stage_id": stage_id}
        if "@" in re.sub(r"USR1@120", "", rendered):
            raise ValueError("unrendered inference template placeholder")
        verifier = shlex.join([settings.training_bootstrap_python, "-c",
                              REMOTE_INFERENCE_VERIFY, record["bundle"],
                              record["manifest_sha256"]])
        # Use Slurm --wrap so AgentPorter never executes a mutable staged sbatch file.
        wrapped_script = "set -euo pipefail\n" + verifier + "\n" + rendered.split("\n", 1)[1]
        wrapped_command = "exec /bin/bash -c " + shlex.quote(wrapped_script)
        script_hash = hashlib.sha256(wrapped_command.encode("utf-8")).hexdigest()
        bundle_path = record["bundle"]
        submit_script = "set -eu; umask 077; marker=" + shlex.quote(
            f"{scratch}/submissions/{stage_id}"
        ) + "; mkdir -p -m 700 " + shlex.quote(f"{scratch}/submissions") + "; " \
        + "test ! -L " + shlex.quote(f"{scratch}/submissions") + "; chmod 700 " \
        + shlex.quote(f"{scratch}/submissions") + "; " \
            + "mkdir -p -m 700 " + shlex.quote(f"{scratch}/logs") + "; " \
            + "test ! -L " + shlex.quote(f"{scratch}/logs") + "; chmod 700 " \
            + shlex.quote(f"{scratch}/logs") + "; mkdir \"$marker\" || exit 73; " \
            + "exec sbatch --parsable --job-name=cranary-standalone-inference " \
            + "--account=" + shlex.quote(account) + " --partition=" + shlex.quote(partition) \
            + " --time=00:30:00 --nodes=1 --ntasks=1 --gpus-per-node=h100:1 " \
            + "--cpus-per-task=8 --signal=USR1@120 " \
            + "--output=" + shlex.quote(f"{scratch}/logs/%x-%j.out") \
            + " --error=" + shlex.quote(f"{scratch}/logs/%x-%j.err") \
            + " --export=" + ",".join(
                shlex.quote(k + "=" + v) for k, v in {
                    "CRANARY_INFERENCE_SCRATCH": scratch,
                    "CRANARY_INFERENCE_BUNDLE": bundle_path,
                    "CRANARY_INFERENCE_SHA256": record["manifest_sha256"],
                    "CRANARY_INFERENCE_PYTHON": python,
                    "CRANARY_INFERENCE_HF_CACHE": hf_cache,
                    "CRANARY_INFERENCE_STAGE_ID": stage_id,
                    "CRANARY_INFERENCE_RUNTIME_CATALOG": runtime["runtime_catalog"],
                    "CRANARY_INFERENCE_RUNTIME_SHA256": runtime["runtime_catalog_sha256"],
                    "PATH": "/usr/bin:/bin",
                }.items()
            ) + " --wrap=" + shlex.quote(wrapped_command)
        # A slow preflight must not carry an expired challenge into allocation.
        _verify_approval(record, settings,
                         _approval_context(settings, workspace_id, _ws.path, python, hf_cache))
        result = _call(settings, user, ["/bin/bash", "-lc", submit_script], timeout=120)
        output = _result(result)
        job_id = output["stdout"].strip()
        if (result.get("exit_code") != 0 or result.get("timed_out")
                or result.get("truncated") or not JOB_ID_RE.fullmatch(job_id)):
            return {"target": "scinet_inference", "command": "scinet_inference_submit",
                    "success": False, "error": "submission_outcome_unknown_no_replay",
                    "stage_id": stage_id}
        with ledger.locked() as data:
            record = data["stages"][stage_id]
            record.update({"state": "submitted", "job_id": job_id,
                           "script_sha256": script_hash, "submitted_at": int(time.time())})
            data.setdefault("jobs", {})[job_id] = {"workspace_id": workspace_id,
                "stage_id": stage_id, "experiment": INFERENCE_EXPERIMENT}
        return {"target": "scinet_inference", "command": "scinet_inference_submit",
                "success": True, "stage_id": stage_id, "job_id": job_id,
                "manifest_sha256": record["manifest_sha256"],
                "resources": {"gpus": 1, "gpu_type": "H100", "walltime": MAX_WALLTIME}}

    return {"scinet_inference_stage": scinet_inference_stage,
            "scinet_inference_approve": scinet_inference_approve,
            "scinet_inference_submit": scinet_inference_submit,
            "scinet_inference_results": scinet_inference_results}


JOB_ID_RE = re.compile(r"[0-9]+\Z")


def render_inference_template(template: str, account: str, partition: str, scratch: str) -> str:
    if hashlib.sha256(template.encode("utf-8")).hexdigest() != TEMPLATE_SHA256:
        raise ValueError("inference Slurm template differs reviewed template")
    for placeholder in ("@ACCOUNT@", "@PARTITION@", "@SCRATCH@"):
        if not template.count(placeholder):
            raise ValueError("required inference template placeholder is missing")
    rendered = template.replace("@ACCOUNT@", account).replace("@PARTITION@", partition)
    rendered = rendered.replace("@SCRATCH@", scratch)
    lines = rendered.splitlines()
    if (sum(line.startswith("#SBATCH --time=") for line in lines) != 1
            or "#SBATCH --time=00:30:00" not in lines
            or sum("--gpus-per-node=h100:1" in line for line in lines) != 1
            or any(line.startswith("#SBATCH --gpus-per-node=")
                   and line != "#SBATCH --gpus-per-node=h100:1" for line in lines)
            or any(token in rendered for token in ("@ACCOUNT@", "@PARTITION@", "@SCRATCH@"))):
        raise ValueError("inference Slurm resource envelope or placeholders are invalid")
    return rendered + ("" if rendered.endswith("\n") else "\n")
