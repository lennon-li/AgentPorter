import hashlib
import base64
import json
import os
import stat
import shlex
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter.tools import scinet_inference as inference


PRODUCTION_OWNER_GATE = inference._trusted_key_owner_uid
RELEASE_MANIFEST = inference.MANIFEST_SHA256
RELEASE_TEMPLATE = inference.TEMPLATE_SHA256
RUNTIME_DIGEST = "d" * 64
SCRATCH = "/scratch/user/run"
PYTHON = SCRATCH + "/inference-env/bin/python"
CACHE = SCRATCH + "/model-cache"


@pytest.fixture(autouse=True)
def restore_release_pins(monkeypatch, tmp_path):
    # Legacy fixture generation must never leak fake release pins into other tests.
    monkeypatch.setattr(inference, "MANIFEST_SHA256", RELEASE_MANIFEST)
    monkeypatch.setattr(inference, "TEMPLATE_SHA256", RELEASE_TEMPLATE)
    parent = tmp_path / "trusted-key"
    parent.mkdir(mode=0o755)
    monkeypatch.setattr(inference, "TRUSTED_APPROVAL_PUBLIC_KEY_PATH", parent / "approval.pub")
    monkeypatch.setattr(inference, "_trusted_key_owner_uid", os.getuid)


def _test_signer(settings):
    settings.host = getattr(settings, "host", "trillium.example")
    settings.user = getattr(settings, "user", "user")
    private_key = getattr(settings, "_test_private_key", None)
    if private_key is None:
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        inference.TRUSTED_APPROVAL_PUBLIC_KEY_PATH.write_bytes(base64.b64encode(public_bytes) + b"\n")
        inference.TRUSTED_APPROVAL_PUBLIC_KEY_PATH.chmod(0o644)
        settings._test_private_key = private_key
    return private_key


def _sign_challenge(staged, settings):
    raw = base64.b64decode(staged["approval_payload_base64"], validate=True)
    return base64.b64encode(_test_signer(settings).sign(raw)).decode("ascii")


def runtime_metadata():
    return {"runtime_catalog": SCRATCH + "/runtime-catalog.json",
            "runtime_catalog_sha256": RUNTIME_DIGEST, "python": PYTHON, "hf_cache": CACHE}


def make_bundle(root: Path, *, stage="standalone-inference", template=b"template\n"):
    root.mkdir()
    cases = [f"P{i:04d}_{kind}" for i in range(1, 22) for kind in ("pos", "ctl")]
    files = {name: b"fixed reviewed fixture\n" for name in inference.STATIC_FILES}
    files["code/inference.sbatch.template"] = template
    files.update({f"contexts/{case}.json": b"{}\n" for case in cases})
    context_hash = hashlib.sha256(b"{}\n").hexdigest()
    files["data/cohort.csv"] = (
        "case_id,context_file_sha256,state_sha256\n" +
        "".join(f"{case},{context_hash},{'e' * 64}\n" for case in cases)
    ).encode()
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {
        "schema": inference.SCHEMA,
        "stage": stage,
        "original_protocol_sha256": inference.ORIGINAL_PROTOCOL_SHA256,
        "execution_change": "cpu to one H100; inference only",
        "model": "convaiinnovations/laya",
        "revision": "7b928d828b7b0e022f929d9bd2e44165aa270148",
        "weights_sha256": "891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c",
        "runtime": "laya==0.3.28",
        "max_len": 8192,
        "cases": cases,
        "split": "train_val",
        "no_holdout": True,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
    inference.MANIFEST_SHA256 = digest
    inference.TEMPLATE_SHA256 = hashlib.sha256(template).hexdigest()
    return digest


def test_preflight_verifies_fixed_bundle_contract(tmp_path):
    package = tmp_path / "package"
    digest = make_bundle(package)
    manifest = inference._verify_bundle(package, digest)
    assert len(manifest["cases"]) == 42


@pytest.mark.parametrize("stage", ["laya_expA", ""])
def test_wrong_stage_fails_closed(tmp_path, stage):
    package = tmp_path / "package"
    digest = make_bundle(package, stage=stage)
    with pytest.raises(ValueError, match="fixed Laya inference contract"):
        inference._verify_bundle(package, digest)


def test_wrong_manifest_digest_and_modified_file_fail_closed(tmp_path):
    package = tmp_path / "package"
    digest = make_bundle(package)
    with pytest.raises(ValueError, match="fixed reviewed release"):
        inference._verify_bundle(package, "f" * 64)
    with pytest.raises(ValueError, match="fixed reviewed release"):
        inference._verify_bundle(package, "")
    (package / "data" / "cohort.csv").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="file SHA-256 mismatch"):
        inference._verify_bundle(package, digest)


def test_wrong_template_and_extra_file_fail_closed(tmp_path):
    package = tmp_path / "package"
    digest = make_bundle(package)
    (package / "code" / "inference.sbatch.template").write_text("changed\n")
    with pytest.raises(ValueError, match="file SHA-256 mismatch"):
        inference._verify_bundle(package, digest)
    (package / "code" / "inference.sbatch.template").write_bytes(b"template\n")
    (package / "unlisted.py").write_text("print('no')", encoding="utf-8")
    with pytest.raises(ValueError, match="unlisted file"):
        inference._verify_bundle(package, digest)


def test_duplicate_case_manifest_fails_closed(tmp_path):
    package = tmp_path / "package"
    digest = make_bundle(package)
    path = package / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["cases"][1] = manifest["cases"][0]
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="independent pin"):
        inference._verify_bundle(package, digest)


def test_preflight_and_training_contracts_are_separate(tmp_path):
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    report = inference.create_scinet_inference_preflight_tool(
        registry, SimpleNamespace(inference_manifest_sha256="")
    )("cranary")
    assert report["success"] is False
    assert report["experiment"] == "laya_inference"
    assert report["resources"] == {"gpus": 1, "gpu_type": "H100", "walltime": "00:30:00"}
    tools = inference.create_scinet_inference_tools(registry, SimpleNamespace(), tmp_path / "state")
    assert set(tools) == {
        "scinet_inference_stage", "scinet_inference_approve",
        "scinet_inference_submit", "scinet_inference_results",
    }
    from agentporter.tools import scinet_training
    assert "laya_inference" not in scinet_training.EXPERIMENTS
    assert "laya_inference" not in scinet_training.APPROVAL_FIELDS


def _piece(case_id, stage_id, *, runtime_digest=RUNTIME_DIGEST, model_sha=None):
    prediction = {
        "case_id": case_id,
        "score": "0.2",
        "decision": "clear",
        "state_sha256": "e" * 64,
        "context_file_sha256": hashlib.sha256(b"{}\n").hexdigest(),
        "manifest_id": "claims_vs_actual_v2",
        "checkpoint_sha256": model_sha or inference.CHECKPOINT_SHA256,
        "observed_revision": inference.REVISION,
        "process_init_id": "init-test",
    }
    record_sha = hashlib.sha256(json.dumps(
        prediction, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()
    piece = {
        "prediction": prediction, "record_sha256": record_sha,
        "manifest_sha256": inference.MANIFEST_SHA256, "device": "cuda:H100",
        "runtime": "laya==0.3.28",
        "runtime_versions": {**inference.RUNTIME_VERSIONS, "python": "3.12.8"},
        "stage_id": stage_id, "runtime_catalog_sha256": runtime_digest,
    }
    return inference._canonical_json(piece)


def _result_transfer(stage_id, *, job_id="123456", state="COMPLETED", exit_code="0:0",
                     alloc_tres="cpu=4,gres/gpu:h100=1", omit=None, bad_case=None,
                     model_sha=None, runtime_digest=RUNTIME_DIGEST):
    files = []
    for i in range(1, 22):
        for kind in ("pos", "ctl"):
            case_id = f"P{i:04d}_{kind}"
            if case_id == omit:
                continue
            raw = _piece(case_id, stage_id, runtime_digest=runtime_digest,
                         model_sha=model_sha if case_id == bad_case else None)
            if case_id == bad_case and model_sha == "wrong-stage":
                value = json.loads(raw)
                value["stage_id"] = "b" * 32
                raw = inference._canonical_json(value)
            files.append({"name": case_id + ".json", "data": base64.b64encode(raw).decode("ascii")})
    return {"job": {"job_id": job_id, "state": state, "exit_code": exit_code,
                    "alloc_tres": alloc_tres}, "files": files}


def _setup_results(monkeypatch, tmp_path, transfer=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    monkeypatch.setattr(inference, "inference_bundle_path", lambda _: bundle)
    monkeypatch.setattr(inference, "_inference_settings", lambda *_: (
        "user", workspace, "/scratch/root", SCRATCH, PYTHON, CACHE, "acct", "gpu"
    ))
    tools = inference.create_scinet_inference_tools(
        registry, SimpleNamespace(inference_runtime_catalog_sha256=RUNTIME_DIGEST), tmp_path / "state"
    )
    ledger = inference._InferenceLedger(tmp_path / "state")
    stage_id, job_id = "a" * 32, "123456"
    with ledger.locked() as data:
        data["stages"] = {stage_id: {
            "workspace_id": "cranary", "stage_id": stage_id, "state": "submitted",
            "job_id": job_id, "manifest_sha256": inference.MANIFEST_SHA256,
            "runtime_catalog_sha256": RUNTIME_DIGEST, "scratch": SCRATCH,
            "bundle": f"{SCRATCH}/stages/{stage_id}", **runtime_metadata(),
        }}
        data["jobs"] = {job_id: {
            "workspace_id": "cranary", "stage_id": stage_id,
            "experiment": inference.INFERENCE_EXPERIMENT,
        }}
    transfer = transfer or _result_transfer(stage_id)
    monkeypatch.setattr(inference, "_call", lambda *a, **k: {
        "exit_code": 0, "stdout": json.dumps(transfer, sort_keys=True,
            separators=(",", ":")).encode(), "stderr": b""
    })
    return tools, ledger, stage_id, job_id


def test_remote_reader_consumes_manifest_case_inventory_not_synthetic_range():
    # Actual historical cases include P0966; a P0001..P0021 assumption made
    # the first implementation reject valid output after paying for the GPU.
    reader = inference.REMOTE_INFERENCE_RESULTS
    assert 'case_ids=case_list.split(",")' in reader
    assert 'expected={c+".json" for c in case_ids}' in reader
    assert '"P%04d_%s.json"' not in reader
    assert 'state_name=state.strip()' in reader
    assert inference.TRES_NORMALIZER_SOURCE in reader
    assert 'names.append(entry.name)' in reader  # reject extra filenames


def test_results_issue_local_canonical_receipt_from_authenticated_transfer(monkeypatch, tmp_path):
    tools, ledger, stage_id, job_id = _setup_results(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="numeric"):
        tools["scinet_inference_results"]("cranary", "000123")
    compile(inference.REMOTE_INFERENCE_RESULTS, "<remote-results-reader>", "exec")
    result = tools["scinet_inference_results"]("cranary", job_id)
    assert result["success"] and result["trusted_retrieval_available"]
    assert result["remote_call_made"] and result["observed_case_count"] == 42
    receipt = result["trusted_receipt"]
    assert receipt["schema"] == "laya-inference-execution-receipt-v1"
    assert receipt["stage_id"] == stage_id and receipt["jobs"] == [job_id]
    assert len(receipt["pieces"]) == 42
    receipt_bytes = inference._canonical_json(receipt)
    assert hashlib.sha256(receipt_bytes).hexdigest() == result["receipt_sha256"]
    assert "not cryptographic proof of GPU execution" in result["trust_boundary"]
    assert len(json.dumps(result).encode()) <= 256 * 1024

    with pytest.raises(PermissionError, match="not submitted"):
        tools["scinet_inference_results"]("other", job_id)
    with pytest.raises(ValueError, match="numeric"):
        tools["scinet_inference_results"]("cranary", "../123456")
    with pytest.raises(PermissionError, match="not submitted"):
        tools["scinet_inference_results"]("cranary", "999999")
    with ledger.locked() as data:
        data["stages"][stage_id]["manifest_sha256"] = "0" * 64
    with pytest.raises(PermissionError, match="ledger binding"):
        tools["scinet_inference_results"]("cranary", job_id)


@pytest.mark.parametrize("transfer", [
    _result_transfer("a" * 32, state="FAILED"),
    _result_transfer("a" * 32, exit_code="1:0"),
    _result_transfer("a" * 32, alloc_tres="cpu=4,gres/gpu:v100=1"),
    _result_transfer("a" * 32, omit="P0001_pos"),
    _result_transfer("a" * 32, bad_case="P0001_pos", model_sha="0" * 64),
    _result_transfer("a" * 32, bad_case="P0001_pos", model_sha="wrong-stage"),
    _result_transfer("a" * 32, runtime_digest="e" * 64),
])
def test_bad_scheduler_model_stage_or_missing_case_fails_closed(monkeypatch, tmp_path, transfer):
    tools, _, _, job_id = _setup_results(monkeypatch, tmp_path, transfer)
    with pytest.raises(PermissionError):
        tools["scinet_inference_results"]("cranary", job_id)


def test_result_digest_and_remote_symlink_fail_closed(monkeypatch, tmp_path):
    transfer = _result_transfer("a" * 32)
    piece = json.loads(base64.b64decode(transfer["files"][0]["data"]))
    piece["record_sha256"] = "0" * 64
    transfer["files"][0]["data"] = base64.b64encode(
        inference._canonical_json(piece)
    ).decode("ascii")
    tools, _, _, job_id = _setup_results(monkeypatch, tmp_path, transfer)
    with pytest.raises(PermissionError, match="piece failed"):
        tools["scinet_inference_results"]("cranary", job_id)

    tools, _, _, job_id = _setup_results(
        monkeypatch, tmp_path / "symlink", {"error": "result_symlink"}
    )
    monkeypatch.setattr(inference, "_call", lambda *a, **k: {
        "exit_code": 65, "stdout": b'{"error":"result_symlink"}', "stderr": b""
    })
    assert "os.path.islink(path)" in inference.REMOTE_INFERENCE_RESULTS
    assert "os.O_NOFOLLOW" in inference.REMOTE_INFERENCE_RESULTS
    with pytest.raises(PermissionError, match="retrieval failed"):
        tools["scinet_inference_results"]("cranary", job_id)


def test_result_transfer_and_api_response_size_are_bounded(monkeypatch, tmp_path):
    transfer = _result_transfer("a" * 32)
    transfer["files"][0]["data"] = base64.b64encode(b"x" * (inference.MAX_RESULT_FILE_BYTES + 1)).decode()
    tools, _, _, job_id = _setup_results(monkeypatch, tmp_path, transfer)
    with pytest.raises(PermissionError, match="per-file limit"):
        tools["scinet_inference_results"]("cranary", job_id)

    tools, _, _, job_id = _setup_results(monkeypatch, tmp_path / "large-response")
    monkeypatch.setattr(inference, "_call", lambda *a, **k: {
        "exit_code": 0, "stdout": b" " * (inference.MAX_RESULT_RESPONSE_BYTES + 1), "stderr": b""
    })
    with pytest.raises(PermissionError, match="retrieval failed"):
        tools["scinet_inference_results"]("cranary", job_id)


@pytest.mark.parametrize(("kwargs", "valid"), [
    ({"action": "inference_results", "job_id": "123"}, True),
    ({"action": "inference_results"}, False),
    ({"action": "inference_results", "job_id": "../123"}, False),
    ({"action": "inference_results", "job_id": "123", "stage_id": "a" * 32}, False),
    ({"action": "inference_submit", "stage_id": "a" * 32, "job_id": "123"}, False),
])
def test_rest_inference_results_requires_only_numeric_job_id(kwargs, valid):
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest

    if valid:
        assert ScinetSetupRequest(**kwargs).job_id == "123"
    else:
        with pytest.raises(ValidationError):
            ScinetSetupRequest(**kwargs)


def test_rest_inference_actions_enforce_stage_scoping():
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest

    assert ScinetSetupRequest(action="inference_preflight").action == "inference_preflight"
    assert ScinetSetupRequest(action="inference_stage").action == "inference_stage"
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action="inference_stage", stage_id="a" * 32)
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action="inference_approve", stage_id="a" * 32)
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action="inference_submit")
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action="inference_submit", stage_id="a" * 32, reviewer="human")


def test_configured_pin_cannot_override_release_digest(monkeypatch):
    monkeypatch.setattr(inference, "MANIFEST_SHA256", "a" * 64)
    with pytest.raises(PermissionError, match="code-pinned"):
        inference._expected_manifest(SimpleNamespace(inference_manifest_sha256="b" * 64))


def _template(walltime="00:30:00"):
    return ("#!/bin/bash\n#SBATCH --account=@ACCOUNT@\n#SBATCH --partition=@PARTITION@\n"
            f"#SBATCH --time={walltime}\n#SBATCH --gpus-per-node=h100:1\n"
            "#SBATCH --output=@SCRATCH@/logs/%x-%j.out\n"
            "#SBATCH --error=@SCRATCH@/logs/%x-%j.err\nUSR1@120\n")


def test_template_digest_resources_and_walltime_are_fixed(monkeypatch):
    template = _template()
    monkeypatch.setattr(inference, "TEMPLATE_SHA256", hashlib.sha256(template.encode()).hexdigest())
    rendered = inference.render_inference_template(template, "acct", "gpu", "/scratch/user/run")
    assert "#SBATCH --time=00:30:00" in rendered
    assert "#SBATCH --gpus-per-node=h100:1" in rendered
    assert "@SCRATCH@" not in rendered
    with pytest.raises(ValueError, match="differs reviewed"):
        inference.render_inference_template(template + "# changed\n", "acct", "gpu", "/scratch/u/r")
    too_long = _template("00:31:00")
    monkeypatch.setattr(inference, "TEMPLATE_SHA256", hashlib.sha256(too_long.encode()).hexdigest())
    with pytest.raises(ValueError, match="resource envelope"):
        inference.render_inference_template(too_long, "acct", "gpu", "/scratch/u/r")


def test_approval_payload_binds_stage_runtime_destination_reviewer_and_nonce():
    payload = inference._approval_payload(
        "a" * 32, "b" * 64, RUNTIME_DIGEST, SCRATCH, "acct", "gpu", "lennon", "c" * 64,
        context={"test": "context"}, issued_at=100, not_after=3700,
    )
    assert payload == {
        "domain": inference.APPROVAL_DOMAIN,
        "stage_id": "a" * 32,
        "manifest_sha256": "b" * 64,
        "runtime_catalog_sha256": RUNTIME_DIGEST,
        "destination": {"scratch": SCRATCH, "account": "acct", "partition": "gpu"},
        "resources": {"gpu_count": 1, "gpu_type": "H100", "max_walltime": "00:30:00"},
        "reviewer": "lennon", "nonce": "c" * 64,
        "context": {"test": "context"}, "issued_at": 100, "not_after": 3700,
    }
    assert inference._canonical_json(payload).endswith(b"\n")


def test_approval_refuses_forged_reviewer_and_bad_signature(monkeypatch, tmp_path):
    stage_id = "3" * 32
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    settings = SimpleNamespace(inference_approval_reviewer="lennon",
                               training_account="acct", training_partition="gpu",
                               training_bootstrap_python="/usr/bin/python3",
                               inference_runtime_catalog_sha256=RUNTIME_DIGEST)
    private_key = _test_signer(settings)
    nonce = "c" * 64
    context = inference._approval_context(settings, "cranary", tmp_path, PYTHON, CACHE)
    issued_at = int(time.time())
    payload = inference._approval_payload(
        stage_id, inference.MANIFEST_SHA256, RUNTIME_DIGEST,
        SCRATCH, "acct", "gpu", "lennon", nonce,
        context=context, issued_at=issued_at, not_after=issued_at + 3600,
    )
    digest = hashlib.sha256(inference._canonical_json(payload)).hexdigest()
    monkeypatch.setattr(inference, "_inference_settings", lambda *_: (
        "user", workspace, "/scratch/root", SCRATCH, PYTHON, CACHE, "acct", "gpu",
    ))
    tools = inference.create_scinet_inference_tools(registry, settings, tmp_path / "state")
    ledger = inference._InferenceLedger(tmp_path / "state")
    with ledger.locked() as data:
        data["stages"] = {stage_id: {
            "workspace_id": "cranary", "stage_id": stage_id,
            "manifest_sha256": inference.MANIFEST_SHA256, "state": "staged",
            "bundle": f"{SCRATCH}/stages/{stage_id}", **runtime_metadata(),
            "scratch": SCRATCH, "account": "acct", "partition": "gpu",
            "approval_nonce": nonce, "approval_reviewer": "lennon",
            "approval_payload_sha256": digest,
            "approval_context": context, "approval_issued_at": issued_at,
            "approval_not_after": issued_at + 3600,
        }}
    valid_signature = base64.b64encode(private_key.sign(inference._canonical_json(payload))).decode("ascii")
    with pytest.raises(PermissionError, match="reviewer"):
        tools["scinet_inference_approve"]("cranary", stage_id, "agentporter", valid_signature)
    with pytest.raises(PermissionError, match="signature verification"):
        tools["scinet_inference_approve"]("cranary", stage_id, "lennon", base64.b64encode(b"x" * 64).decode())
    wrong_stage_payload = inference._approval_payload(
        "4" * 32, inference.MANIFEST_SHA256, RUNTIME_DIGEST,
        SCRATCH, "acct", "gpu", "lennon", nonce,
        context=context, issued_at=issued_at, not_after=issued_at + 3600,
    )
    wrong_stage_signature = base64.b64encode(
        private_key.sign(inference._canonical_json(wrong_stage_payload))
    ).decode("ascii")
    with pytest.raises(PermissionError, match="signature verification"):
        tools["scinet_inference_approve"]("cranary", stage_id, "lennon", wrong_stage_signature)
    with ledger.locked() as data:
        assert data["stages"][stage_id].get("approval") is None


def test_submit_rejects_missing_approval_and_prevents_replay(monkeypatch, tmp_path):
    stage_id = "2" * 32
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    settings = SimpleNamespace(training_account="acct", training_partition="gpu",
                               inference_runtime_catalog_sha256=RUNTIME_DIGEST,
                               training_bootstrap_python="/usr/bin/python3",
                               inference_approval_reviewer="lennon")
    _test_signer(settings)
    monkeypatch.setattr(inference, "_inference_settings", lambda *_: (
        "user", workspace, "/scratch/root", "/scratch/user/run",
        PYTHON, CACHE, "acct", "gpu",
    ))
    tools = inference.create_scinet_inference_tools(registry, settings, tmp_path / "state")
    ledger = inference._InferenceLedger(tmp_path / "state")
    with ledger.locked() as data:
        data["stages"] = {stage_id: {
            "workspace_id": "cranary", "stage_id": stage_id,
            "manifest_sha256": inference.MANIFEST_SHA256,
            "bundle": f"/scratch/user/run/stages/{stage_id}",
            "scratch": "/scratch/user/run", "account": "acct", "partition": "gpu",
            "files": {}, "state": "staged", **runtime_metadata(),
            "approval_reviewer": "lennon", "approval_nonce": "c" * 64,
            "approval_payload_sha256": "d" * 64,
        }}
    with pytest.raises(PermissionError, match="signed stage-scoped"):
        tools["scinet_inference_submit"]("cranary", stage_id)
    with ledger.locked() as data:
        data["stages"][stage_id]["state"] = "submitting"
    with pytest.raises(PermissionError, match="already reserved"):
        tools["scinet_inference_submit"]("cranary", stage_id)


def setup_flow(monkeypatch, tmp_path):
    bundle = tmp_path / 'bundle'
    digest = make_bundle(bundle, template=_template().encode())
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    registry = SimpleNamespace(get=lambda _: workspace)
    settings = SimpleNamespace(training_account='acct', training_partition='gpu',
                               inference_runtime_catalog_sha256=RUNTIME_DIGEST,
                               inference_approval_reviewer='lennon',
                               training_bootstrap_python='/usr/bin/python3')
    _test_signer(settings)
    monkeypatch.setattr(inference, '_inference_settings', lambda *_: (
        'user', workspace, '/scratch/root', SCRATCH, PYTHON, CACHE, 'acct', 'gpu'))
    monkeypatch.setattr(inference, 'inference_bundle_path', lambda _: bundle)
    tools = inference.create_scinet_inference_tools(registry, settings, tmp_path / 'state')
    calls = []

    def remote(_settings, _user, command, **kwargs):
        import shlex
        calls.append((command, kwargs))
        tokens = shlex.split(command[2])
        if 'input_bytes' in kwargs:
            header = json.loads(kwargs['input_bytes'].split(b'\n', 1)[0])
            assert len(header['files']) == 60
            stage = tokens[-1]
            receipt = {'success': True, 'stage_id': stage, 'manifest_sha256': digest,
                       'bundle': f'{SCRATCH}/stages/{stage}'}
        elif '-I' in tokens:
            assert tokens[:4] == [PYTHON, '-I', '-B', '-c']
            assert tokens[-2:] == [SCRATCH + '/runtime-catalog.json', RUNTIME_DIGEST]
            compile(tokens[4], '<remote-readonly-preflight>', 'exec')
            receipt = {'success': True, 'manifest_sha256': digest, 'file_count': 60,
                       'runtime_catalog_sha256': RUNTIME_DIGEST,
                       'runtime_artifacts_verified': True, 'model_loaded': False,
                       'gpu_readiness': False}
        else:
            return {'exit_code': 0, 'stdout': b'123456\n'}
        return {'exit_code': 0, 'stdout': json.dumps(receipt).encode()}

    monkeypatch.setattr(inference, '_call', remote)
    return tools, settings, calls, remote


def test_stage_fails_closed_without_trusted_public_key_or_configured_reviewer(monkeypatch, tmp_path):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    monkeypatch.setattr(inference, "TRUSTED_APPROVAL_PUBLIC_KEY_PATH", tmp_path / "missing.pub")
    with pytest.raises(PermissionError, match="public key file is missing"):
        tools["scinet_inference_stage"]("cranary")
    assert calls == []
    settings.inference_approval_reviewer = ""
    with pytest.raises(PermissionError, match="reviewer is not configured"):
        tools["scinet_inference_stage"]("cranary")
    assert calls == []


def test_v2_stage_approval_submit_exports_and_no_replay(monkeypatch, tmp_path):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    stage = staged['stage_id']
    assert stage[0].isalpha() and len(stage) == 32
    assert staged['runtime_catalog_sha256'] == RUNTIME_DIGEST
    assert staged['trusted_retrieval_available'] is False
    assert 'approval_confirmation' not in staged
    approval = tools['scinet_inference_approve'](
        'cranary', stage, 'lennon', _sign_challenge(staged, settings))
    assert approval['success']
    with pytest.raises(PermissionError, match='already recorded'):
        tools['scinet_inference_approve']('cranary', stage, 'lennon', _sign_challenge(staged, settings))
    result = tools['scinet_inference_submit']('cranary', stage)
    assert result['job_id'] == '123456'
    assert len(calls) == 3
    script = calls[-1][0][2]
    assert "--export=CRANARY_INFERENCE_SCRATCH=" in script
    assert "--export=NONE" not in script and "--export=ALL" not in script
    for value in (f'CRANARY_INFERENCE_STAGE_ID={stage}',
                  f'CRANARY_INFERENCE_RUNTIME_SHA256={RUNTIME_DIGEST}',
                  f'CRANARY_INFERENCE_RUNTIME_CATALOG={SCRATCH}/runtime-catalog.json',
                  '--time=00:30:00', '--gpus-per-node=h100:1',
                  'test ! -L /scratch/user/run/submissions',
                  'chmod 700 /scratch/user/run/submissions'):
        assert value in script
    with pytest.raises(PermissionError, match='already reserved'):
        tools['scinet_inference_submit']('cranary', stage)
    assert len(calls) == 3


@pytest.mark.parametrize('preflight_result', [
    {'exit_code': 3, 'stdout': b''},
    {'exit_code': 0, 'stdout': b'{}'},
    {'exit_code': 0, 'stdout': b'not-json'},
    {'exit_code': 0, 'stdout': b'{}', 'timed_out': True},
    {'exit_code': 0, 'stdout': b'{}', 'truncated': True},
])
def test_bad_runtime_preflight_never_reaches_sbatch(monkeypatch, tmp_path, preflight_result):
    tools, settings, calls, remote = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', _sign_challenge(staged, settings))
    attempted = []
    monkeypatch.setattr(inference, '_call', lambda *a, **k: attempted.append(a[2]) or preflight_result)
    assert not tools['scinet_inference_submit']('cranary', staged['stage_id'])['success']
    assert len(attempted) == 1 and 'sbatch --parsable' not in attempted[0][2]
    with pytest.raises(PermissionError, match='already reserved'):
        tools['scinet_inference_submit']('cranary', staged['stage_id'])
    assert len(attempted) == 1


@pytest.mark.parametrize('change', ['digest', 'missing_catalog', 'old_manifest', 'missing_approval', 'resources'])
def test_changed_stage_contract_blocks_all_remote_calls(monkeypatch, tmp_path, change):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    stage = staged['stage_id']
    tools['scinet_inference_approve']('cranary', stage, 'lennon', _sign_challenge(staged, settings))
    if change == 'digest':
        settings.inference_runtime_catalog_sha256 = 'e' * 64
    elif change == 'missing_catalog':
        settings.inference_runtime_catalog_sha256 = ''
    else:
        with inference._InferenceLedger(tmp_path / 'state').locked() as data:
            record = data['stages'][stage]
            if change == 'old_manifest':
                record['manifest_sha256'] = '06c665e7fd7323bedd5d257ba8b647d521bbcb2d4462719490e70829ef4144e0'
            elif change == 'missing_approval':
                record.pop('approval')
            else:
                record['approval']['signature'] = base64.b64encode(b'x' * 64).decode()
    with pytest.raises(PermissionError):
        tools['scinet_inference_submit']('cranary', stage)
    assert len(calls) == 1


@pytest.mark.parametrize('cache,python,digest', [
    (CACHE, PYTHON, ''), (CACHE, PYTHON, 'bad'),
    ('/scratch/elsewhere/cache', PYTHON, RUNTIME_DIGEST),
    (CACHE, '/opt/laya/bin/python', RUNTIME_DIGEST),
    (SCRATCH + '/stages/cache', PYTHON, RUNTIME_DIGEST),
    (SCRATCH + '/cache/../escape', PYTHON, RUNTIME_DIGEST),
])
def test_missing_catalog_or_unsafe_fixed_runtime_paths(cache, python, digest):
    with pytest.raises(PermissionError):
        inference._runtime_metadata(SimpleNamespace(inference_runtime_catalog_sha256=digest),
                                    SCRATCH, python, cache)


def test_historical_pins_and_template_are_rejected(tmp_path):
    assert inference.MANIFEST_SHA256 == 'd0032d8a9bb6fc3580b2e1d9118bc5ca6f99defd6bfdfdf641a3e59fc02a91c7'
    assert inference.TEMPLATE_SHA256 == '5d41bf4b5b533e8147ba7c6a38e31fc4ef19bbe1d2d4f8c17f3d15d870e2b79f'
    assert inference.inference_bundle_path(tmp_path).name == 'package-v2'
    with pytest.raises(ValueError, match='fixed reviewed release'):
        inference._verify_bundle(tmp_path, '06c665e7fd7323bedd5d257ba8b647d521bbcb2d4462719490e70829ef4144e0')
    assert RELEASE_TEMPLATE in inference.REMOTE_INFERENCE_VERIFY
    assert RELEASE_MANIFEST in inference.REMOTE_INFERENCE_VERIFY


def test_typed_actions_do_not_accept_catalog_path_or_command():
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest
    for extra in ({'runtime_catalog': '/tmp/untrusted.json'}, {'command': 'touch /tmp/no'}):
        with pytest.raises(ValidationError):
            ScinetSetupRequest(action='inference_stage', **extra)


def private_fixture_bundle(root):
    digest = make_bundle(root)
    for path in root.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o400)
    root.chmod(0o700)
    return digest


def fixture_remote_verifier():
    return inference.REMOTE_INFERENCE_VERIFY.replace(
        RELEASE_MANIFEST, inference.MANIFEST_SHA256).replace(
        RELEASE_TEMPLATE, inference.TEMPLATE_SHA256)


def test_remote_verifier_checks_all_60_files_and_refuses_mutation(tmp_path):
    import subprocess
    import sys
    bundle = tmp_path / 'bundle'
    digest = private_fixture_bundle(bundle)
    command = [sys.executable, '-I', '-B', '-c', fixture_remote_verifier(), str(bundle), digest]
    result = subprocess.run(command, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['file_count'] == 60
    target = bundle / 'code/runtime_preflight.py'
    target.chmod(0o600)
    target.write_text('changed')
    result = subprocess.run(command, capture_output=True)
    assert result.returncode != 0


def test_remote_readonly_preflight_refuses_absent_catalog_before_imports(tmp_path):
    import subprocess
    import sys
    bundle = tmp_path / 'bundle'
    digest = private_fixture_bundle(bundle)
    script = inference._runtime_preflight_script(bundle).replace(
        RELEASE_MANIFEST, inference.MANIFEST_SHA256).replace(
        RELEASE_TEMPLATE, inference.TEMPLATE_SHA256)
    # The fixed remote path is deliberately absent. No script or import is allowed
    # to create it, contact a network or reach a model/GPU check.
    result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(bundle), digest,
                             '/scratch/agentporter-absent-test',
                             '/scratch/agentporter-absent-test/model-cache',
                             '/scratch/agentporter-absent-test/runtime-catalog.json',
                             RUNTIME_DIGEST], capture_output=True)
    assert result.returncode != 0
    assert not result.stdout


def test_rest_requires_bounded_signature_for_inference_approval():
    from pydantic import ValidationError
    from agentporter.rest.routers.scinet import ScinetSetupRequest
    stage = 'a' * 32
    signature = base64.b64encode(b'x' * 64).decode('ascii')
    request = ScinetSetupRequest(action='inference_approve', stage_id=stage,
                                 reviewer='lennon', signature=signature)
    assert request.signature == signature
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action='inference_approve', stage_id=stage,
                           reviewer='lennon', confirmation='I approve')
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action='inference_approve', stage_id=stage,
                           reviewer='lennon', signature=signature + 'x')
    with pytest.raises(ValidationError):
        ScinetSetupRequest(action='record_approvals', reviewer='lennon',
                           confirmation='I approve', approved_fields=['x'], signature=signature)


@pytest.mark.parametrize('encoding', ['raw', 'base64', 'base64-lf'])
def test_trusted_key_accepts_only_documented_formats(encoding):
    settings = SimpleNamespace()
    private = _test_signer(settings)
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    encoded = raw if encoding == 'raw' else base64.b64encode(raw)
    if encoding == 'base64-lf':
        encoded += b'\n'
    inference.TRUSTED_APPROVAL_PUBLIC_KEY_PATH.write_bytes(encoded)
    inference._approval_public_key().verify(private.sign(b'challenge'), b'challenge')


@pytest.mark.parametrize('unsafe', [
    'missing', 'file-symlink', 'parent-symlink', 'directory', 'fifo', 'hardlink',
    'file-group-write', 'file-other-write', 'parent-group-write', 'parent-other-write',
    'file-owner', 'parent-owner', 'oversized', 'bad-base64', 'extra-newline', 'noncanonical',
])
def test_untrusted_public_key_file_fails_closed(monkeypatch, unsafe):
    _test_signer(SimpleNamespace())
    path = inference.TRUSTED_APPROVAL_PUBLIC_KEY_PATH
    if unsafe == 'missing':
        monkeypatch.setattr(inference, 'TRUSTED_APPROVAL_PUBLIC_KEY_PATH', path.parent / 'missing')
    elif unsafe == 'file-symlink':
        target = path.with_suffix('.target')
        path.rename(target)
        path.symlink_to(target)
    elif unsafe == 'parent-symlink':
        link = path.parent.with_name('parent-link')
        link.symlink_to(path.parent, target_is_directory=True)
        monkeypatch.setattr(inference, 'TRUSTED_APPROVAL_PUBLIC_KEY_PATH', link / path.name)
    elif unsafe in ('directory', 'fifo'):
        path.rename(path.with_suffix('.original'))
        path.mkdir() if unsafe == 'directory' else os.mkfifo(path)
    elif unsafe == 'hardlink':
        os.link(path, path.with_suffix('.link'))
    elif unsafe.endswith('write'):
        target = path.parent if unsafe.startswith('parent') else path
        target.chmod(target.stat().st_mode | (0o020 if 'group' in unsafe else 0o002))
    elif unsafe.endswith('owner'):
        original = Path.lstat if unsafe == 'parent-owner' else inference.os.stat
        def wrong_owner(*args, **kwargs):
            info = original(*args, **kwargs)
            if str(args[0]) == (str(path.parent) if unsafe == 'parent-owner' else path.name):
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info
        if unsafe == 'parent-owner':
            monkeypatch.setattr(Path, 'lstat', wrong_owner)
        else:
            monkeypatch.setattr(inference.os, 'stat', wrong_owner)
    else:
        path.write_bytes({
            'oversized': b'x' * 46, 'bad-base64': b'!' * 44,
            'extra-newline': b'A' * 43 + b'=\n\n',
            'noncanonical': b'A' * 42 + b'B=',
        }[unsafe])
    with pytest.raises(PermissionError, match='public key file'):
        inference._approval_public_key()


def test_root_owner_gate_is_not_derived_from_settings_or_environment(monkeypatch):
    assert PRODUCTION_OWNER_GATE() == 0
    monkeypatch.setattr(inference, '_trusted_key_owner_uid', PRODUCTION_OWNER_GATE)
    _test_signer(SimpleNamespace())
    if os.getuid() != 0:
        with pytest.raises(PermissionError, match='public key file'):
            inference._approval_public_key()


def test_wrong_key_and_config_env_substitution_do_not_authorize(monkeypatch, tmp_path):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    attacker = Ed25519PrivateKey.generate()
    public = attacker.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    settings.inference_approval_public_key = base64.b64encode(public).decode()
    monkeypatch.setenv('AGENTPORTER_SCINET_INFERENCE_APPROVAL_PUBLIC_KEY', settings.inference_approval_public_key)
    monkeypatch.setenv('AGENTPORTER_SCINET_INFERENCE_APPROVAL_PUBLIC_KEY_PATH', '/agent/writable/key')
    signature = base64.b64encode(attacker.sign(base64.b64decode(staged['approval_payload_base64']))).decode()
    with pytest.raises(PermissionError, match='signature verification'):
        tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', signature)
    assert len(calls) == 1


@pytest.mark.parametrize('tres,valid', [
    ('cpu=8,mem=64G,node=1,billing=8,gres/gpu=1,gres/gpu:nvidia_h100_80gb_hbm3=1', True),
    ('gres/gpu:h100=1', True),
    (' gres/gpu:H100 = 1 , gres/gpu = 1 , node = 1 ', True),
    ('gres/gpu=1,gres/gpu:a100=1', False),
    ('gres/gpu=1', False), ('cpu=8', False), ('', False),
    ('gres/gpu:h100=1,gres/gpu:a100=1', False),
    ('gres/gpu:h100=1,gres/gpu:nvidia_h100_80gb_hbm3=1', False),
    ('gres/gpu=2,gres/gpu:h100=1', False), ('gres/gpu:h100=2', False),
    ('gres/gpu:h100=1,node=2', False), ('gres/gpu:h100=1,node=0', False),
    ('gres/gpu:h100=1,gres/gpu=0', False),
    ('gres/gpu:h100=1,gres/gpu:h100=1', False),
    ('gres/gpu:h100=1,gres/gpu:a100=0', False),
    ('gres/gpu:h100=1,', False), ('gres/gpu:h100=1,garbage', False),
    ('gres/gpu:h100=1.0', False), ('gres/gpu:h100=1G', False),
    ('gres/gpu:h100=1,gres/gpu=1,gres/gpu=2', False),
])
def test_identical_remote_and_local_h100_tres_validation(monkeypatch, tmp_path, tres, valid):
    # Extract and execute the actual remote function, not a second hand-written parser.
    import ast
    module = ast.parse(inference.REMOTE_INFERENCE_RESULTS)
    function = next(n for n in module.body if isinstance(n, ast.FunctionDef))
    namespace = {'re': __import__('re')}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<remote-tres>', 'exec'), namespace)
    assert namespace['_one_h100_allocation'](tres) is valid
    assert inference._one_h100_allocation(tres) is valid
    tools, _, _, job = _setup_results(monkeypatch, tmp_path)
    transfer = _result_transfer('a' * 32, alloc_tres=tres)
    monkeypatch.setattr(inference, '_call', lambda *a, **k: {
        'exit_code': 0, 'stdout': json.dumps(transfer).encode()})
    if valid:
        assert tools['scinet_inference_results']('cranary', job)['success']
    else:
        with pytest.raises(PermissionError, match='Slurm did not attest'):
            tools['scinet_inference_results']('cranary', job)


def test_results_use_fixed_system_interpreter_and_pinned_code(monkeypatch, tmp_path):
    tools, _, _, job = _setup_results(monkeypatch, tmp_path)
    calls = []
    def remote(_settings, _user, command, **kwargs):
        calls.append(command)
        tokens = command
        assert kwargs['operation'] == 'inference_results'
        assert kwargs['timeout'] == 60
        assert kwargs['max_output'] == inference.MAX_RESULT_RESPONSE_BYTES
        assert tokens[:4] == ['/usr/bin/python3', '-I', '-B', '-c']
        assert hashlib.sha256(tokens[4].encode()).hexdigest() == inference.RESULT_READER_SHA256
        return {'exit_code': 0, 'stdout': json.dumps(_result_transfer('a' * 32)).encode()}
    monkeypatch.setattr(inference, '_call', remote)
    assert tools['scinet_inference_results']('cranary', job)['success']
    monkeypatch.setattr(inference, 'REMOTE_INFERENCE_RESULTS', inference.REMOTE_INFERENCE_RESULTS + '\n# mutated')
    with pytest.raises(PermissionError, match='reader digest mismatch'):
        tools['scinet_inference_results']('cranary', job)
    assert len(calls) == 1


@pytest.mark.parametrize('use_broker', [False, True])
def test_recorded_results_reach_real_transport_with_exact_tokens(monkeypatch, tmp_path, use_broker):
    from agentporter.tools import scinet, scinet_broker, scinet_training
    _, _, stage, job = _setup_results(monkeypatch, tmp_path)
    workspace = SimpleNamespace(path=tmp_path, allow_execute=True, allow_scinet_training=True)
    settings = SimpleNamespace(inference_runtime_catalog_sha256=RUNTIME_DIGEST,
                               host='cluster.example', user='user', control_socket='~/.ssh/master',
                               broker_socket=str(tmp_path / 'broker') if use_broker else '')
    monkeypatch.setattr(inference, '_inference_settings', lambda *_: (
        SimpleNamespace(pw_dir=str(tmp_path)), workspace, '/scratch/root', SCRATCH,
        PYTHON, CACHE, 'acct', 'gpu'))
    monkeypatch.setattr(inference, '_call', scinet_training._call)
    monkeypatch.setattr(scinet_broker, '_control_socket_available', lambda _: True)
    service = scinet_broker.ScinetBroker(str(tmp_path / 'broker'), str(tmp_path / 'master'),
                                         settings.host, settings.user)
    seen = []
    def host(argv, home, **kwargs):
        seen.append(argv)
        tokens = shlex.split(argv[-1])
        assert tokens[:6] == ['exec', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
                              '/usr/bin/timeout', '60s']
        assert tokens[6:11] == ['/usr/bin/python3', '-I', '-B', '-c', inference.REMOTE_INFERENCE_RESULTS]
        assert tokens[11:14] == [SCRATCH, job, stage]
        assert tokens[14].split(',') == list(_cohort_for_test())
        assert len(tokens) == 15 and kwargs['input_bytes'] is None
        assert kwargs['max_output'] == inference.MAX_RESULT_RESPONSE_BYTES
        return {'exit_code': 0, 'stdout': json.dumps(_result_transfer(stage)).encode(), 'stderr': b''}
    def _cohort_for_test():
        return [f'P{i:04d}_{kind}' for i in range(1, 22) for kind in ('pos', 'ctl')]
    def fake_broker(settings, remote, **kwargs):
        assert kwargs['operation'] == 'inference_results'
        response = service._request(dict(version=1, operation=kwargs['operation'], remote=remote,
                                         input_length=0, max_output=kwargs['max_output']), b'')
        return {**response, 'stdout': base64.b64decode(response['stdout']),
                'stderr': base64.b64decode(response['stderr'])}
    monkeypatch.setattr(scinet, 'run_host_bytes', host)
    monkeypatch.setattr(scinet_broker, 'run_host_bytes', host)
    monkeypatch.setattr(scinet, 'broker_request', fake_broker)
    tools = inference.create_scinet_inference_tools(SimpleNamespace(get=lambda _: workspace),
                                                    settings, tmp_path / 'state')
    assert tools['scinet_inference_results']('cranary', job)['success']
    assert len(seen) == 1


@pytest.mark.parametrize('change', ['host', 'user', 'workspace', 'python', 'bootstrap', 'cache', 'template', 'expiry', 'future', 'forged-time'])
@pytest.mark.parametrize('phase', ['approve', 'submit'])
def test_signed_approval_binds_context_and_validity(monkeypatch, tmp_path, change, phase):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    signature = _sign_challenge(staged, settings)
    if phase == 'submit':
        tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', signature)
    if change in ('host', 'user'):
        setattr(settings, change, 'attacker.example')
    elif change == 'bootstrap':
        settings.training_bootstrap_python = '/scratch/attacker/python'
    elif change == 'template':
        monkeypatch.setattr(inference, 'TEMPLATE_SHA256', 'f' * 64)
    elif change in ('expiry', 'future'):
        now = staged['approval_payload']['not_after'] if change == 'expiry' else staged['approval_payload']['issued_at'] - 1
        monkeypatch.setattr(inference.time, 'time', lambda: now)
    elif change == 'forged-time':
        with inference._InferenceLedger(tmp_path / 'state').locked() as data:
            data['stages'][staged['stage_id']]['approval_not_after'] -= 1
    else:
        with inference._InferenceLedger(tmp_path / 'state').locked() as data:
            context = data['stages'][staged['stage_id']]['approval_context']
            if change == 'workspace':
                context['workspace']['path'] = '/different/workspace'
            else:
                context['python' if change == 'python' else 'hf_cache'] += '/changed'
    with pytest.raises((PermissionError, ValueError)):
        if phase == 'approve':
            tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', signature)
        else:
            tools['scinet_inference_submit']('cranary', staged['stage_id'])
    assert len(calls) == 1


def test_expiry_during_preflight_prevents_sbatch(monkeypatch, tmp_path):
    tools, settings, calls, remote = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', _sign_challenge(staged, settings))
    def slow_remote(*args, **kwargs):
        result = remote(*args, **kwargs)
        monkeypatch.setattr(inference.time, 'time', lambda: staged['approval_payload']['not_after'])
        return result
    monkeypatch.setattr(inference, '_call', slow_remote)
    with pytest.raises(PermissionError, match='expired'):
        tools['scinet_inference_submit']('cranary', staged['stage_id'])
    assert len(calls) == 2


def test_bootstrap_drift_during_preflight_prevents_sbatch(monkeypatch, tmp_path):
    tools, settings, calls, remote = setup_flow(monkeypatch, tmp_path)
    staged = tools['scinet_inference_stage']('cranary')
    assert staged['approval_payload']['context']['bootstrap_python'] == '/usr/bin/python3'
    tools['scinet_inference_approve']('cranary', staged['stage_id'], 'lennon', _sign_challenge(staged, settings))
    def changed_remote(*args, **kwargs):
        result = remote(*args, **kwargs)
        settings.training_bootstrap_python = '/scratch/attacker/python'
        return result
    monkeypatch.setattr(inference, '_call', changed_remote)
    with pytest.raises(PermissionError, match='runtime context changed'):
        tools['scinet_inference_submit']('cranary', staged['stage_id'])
    assert len(calls) == 2  # Stage plus preflight; no sbatch call.


@pytest.mark.parametrize('bootstrap', ['', 'python3', '/usr/bin/python3;id', None])
def test_stage_rejects_invalid_bootstrap_before_remote_call(monkeypatch, tmp_path, bootstrap):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    settings.training_bootstrap_python = bootstrap
    with pytest.raises(PermissionError, match='bootstrap Python'):
        tools['scinet_inference_stage']('cranary')
    assert calls == []


@pytest.mark.parametrize('target,change', [
    ('parent', 'owner'), ('parent', 'mode'), ('parent', 'inode'),
    ('file', 'owner'), ('file', 'mode'), ('file', 'inode'), ('file', 'type'),
])
def test_opened_public_key_metadata_must_remain_trusted(monkeypatch, target, change):
    _test_signer(SimpleNamespace())
    original = os.fstat
    def changed(fd):
        info = original(fd)
        is_parent = stat.S_ISDIR(info.st_mode)
        if is_parent != (target == 'parent'):
            return info
        fields = list(info)
        if change == 'owner':
            fields[4] = os.getuid() + 1
        elif change == 'mode':
            fields[0] |= 0o002
        elif change == 'type':
            fields[0] = stat.S_IFIFO | 0o644
        else:
            fields[1] += 1
        return os.stat_result(fields)
    monkeypatch.setattr(inference.os, 'fstat', changed)
    with pytest.raises(PermissionError, match='public key file'):
        inference._approval_public_key()


def test_signature_cannot_replay_between_stages(monkeypatch, tmp_path):
    tools, settings, calls, _ = setup_flow(monkeypatch, tmp_path)
    first = tools['scinet_inference_stage']('cranary')
    second = tools['scinet_inference_stage']('cranary')
    assert first['approval_payload']['nonce'] != second['approval_payload']['nonce']
    with pytest.raises(PermissionError, match='signature verification'):
        tools['scinet_inference_approve']('cranary', second['stage_id'], 'lennon', _sign_challenge(first, settings))
    assert len(calls) == 2


@pytest.mark.parametrize('state,exit_code,tres,valid', [
    ('COMPLETED', '0:0', 'cpu=8,mem=64G,node=1,gres/gpu=1,gres/gpu:nvidia_h100_80gb_hbm3=1', True),
    ('COMPLETED', '0:0', 'gres/gpu:h100=1', True),
    ('COMPLETED+', '0:0', 'gres/gpu:h100=1', False),
    ('COMPLETED garbage', '0:0', 'gres/gpu:h100=1', False),
    ('FAILED', '0:0', 'gres/gpu:h100=1', False),
    ('COMPLETED', '0:1', 'gres/gpu:h100=1', False),
    ('COMPLETED', '0:0', 'gres/gpu:h100=1,gres/gpu:a100=1', False),
    ('COMPLETED', '0:0', 'gres/gpu=2,gres/gpu:h100=1', False),
    ('COMPLETED', '0:0', 'gres/gpu:a100=1', False),
    ('MISSING_SACCT', '0:0', 'gres/gpu:h100=1', False),
])
def test_actual_system_python_remote_reader_scheduler_gate(tmp_path, state, exit_code, tres, valid):
    import subprocess
    bundle = tmp_path / 'bundle'
    make_bundle(bundle)
    transfer = _result_transfer('a' * 32)
    scratch = tmp_path / 'scratch'
    results = scratch / 'runs' / '123456' / 'results'
    results.mkdir(parents=True)
    for entry in transfer['files']:
        (results / entry['name']).write_bytes(base64.b64decode(entry['data']))
    # Keep fixed code intact except the scratch-prefix guard for local fixtures.
    script = inference.REMOTE_INFERENCE_RESULTS.replace('r"/scratch/[A-Za-z0-9_./-]+"', 'r"/[A-Za-z0-9_./-]+"', 1)
    row = f'123456|{state}|{exit_code}|{tres}\n'.encode()
    stub = ('import subprocess,types\n'
            'def scheduler(argv,**kw):\n'
            ' assert argv == ["/usr/bin/sacct","-n","-P","-j","123456","-o","JobIDRaw,State,ExitCode,AllocTRES"]\n'
            ' assert kw["stdin"] == subprocess.DEVNULL\n'
            + (' raise FileNotFoundError("missing absolute sacct")\n' if state == 'MISSING_SACCT' else
               f' return types.SimpleNamespace(returncode=0,stdout={row!r})\n')
            + 'subprocess.run=scheduler\n')
    cases = ','.join(entry['name'][:-5] for entry in transfer['files'])
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', stub + script,
                             str(scratch), '123456', 'a' * 32, cases], capture_output=True, timeout=10)
    assert result.returncode == (0 if valid else 65), result.stderr
    returned = json.loads(result.stdout)
    if valid:
        assert returned['files'] == sorted(transfer['files'], key=lambda item: item['name'])
        assert returned['job']['alloc_tres'] == tres
    else:
        assert returned == {'error': 'remote_read_failed' if state == 'MISSING_SACCT'
                            else 'scheduler_attestation_failed'}
