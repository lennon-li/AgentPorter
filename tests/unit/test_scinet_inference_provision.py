"""Unit tests for the read-only SciNet inference provision (inspect) flow."""

import hashlib
import json
import re
import shlex
from types import SimpleNamespace

import pytest

from agentporter.tools import scinet_inference as inference
from agentporter.tools import scinet_broker as broker
from agentporter.config import ScinetSettings
from agentporter.rest.routers.scinet import ScinetSetupRequest

RUN_ID = "a" * 32
SCRATCH = "/scratch/yeli/cranary-laya"
CACHE = SCRATCH + "/model-cache"
BOOTSTRAP = "/usr/bin/python3"


def provision_argv():
    return inference._provision_argv(
        "inspect", BOOTSTRAP, SCRATCH, CACHE, RUN_ID)


def test_provision_script_pins_match_module_sources():
    for name, pin in (
        ("REMOTE_PROVISION_INSPECT", inference.PROVISION_INSPECT_SCRIPT_SHA256),
        ("REMOTE_PROVISION_PREPARE", inference.PROVISION_PREPARE_SCRIPT_SHA256),
    ):
        script = getattr(inference, name)
        assert hashlib.sha256(script.encode("utf-8")).hexdigest() == pin


def test_broker_accepts_pinned_inspect_argv():
    command = broker.inference_provision_command(provision_argv())
    assert shlex_contains(command, "/usr/bin/timeout") is not None
    assert "150s" in command
    assert "/usr/bin/python3" in command


def shlex_contains(command, token):
    return command if token in command else None


def test_broker_rejects_tampered_script():
    remote = provision_argv()
    remote[4] = remote[4] + "\n"
    with pytest.raises(PermissionError):
        broker.inference_provision_command(remote)
    remote = provision_argv()
    remote[4] = ""
    with pytest.raises(PermissionError):
        broker.inference_provision_command(remote)


def test_broker_rejects_bad_arguments():
    for mutate in (
        lambda r: r.__setitem__(5, "prepare"),
        lambda r: r.__setitem__(6, "/usr/bin/../bin"),
        lambda r: r.__setitem__(7, "not-a-scratch"),
        lambda r: r.__setitem__(9, "zz"),
        lambda r: r.__setitem__(9, "a" * 31),
        lambda r: r.__setitem__(8, str(SCRATCH)),
        lambda r: r.__setitem__(5, r[5] + "x"),
    ):
        remote = provision_argv()
        mutate(remote)
        with pytest.raises(PermissionError):
            broker.inference_provision_command(remote)


def test_broker_envelope_is_stdin_free():
    argv = broker._ssh_envelope(
        "trillium-gpu.alliancecan.ca", "yeli", "/tmp/.ssh/cm",
        provision_argv(), operation="inference_provision")
    assert "-n" in argv


def test_scinet_fallback_rejects_stdin_or_command():
    from agentporter.tools import scinet
    settings = ScinetSettings(
        host="trillium-gpu.alliancecan.ca", user="yeli",
        control_socket="/home/yeli/.ssh/cm", machine="asgard",
    )
    user = SimpleNamespace(pw_dir="/home/yeli")
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(
            settings, user, provision_argv(), input_bytes=b"x",
            operation="inference_provision")
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(
            settings, user, provision_argv(), command="inspect",
            operation="inference_provision")


def test_prepare_runs_pinned_transfer_and_prepare(monkeypatch, tmp_path):
    calls = []

    def fake_call(settings, user, remote, **kwargs):
        if kwargs.get("operation") == "inference_provision":
            return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                    "stderr": b"", "timed_out": False, "truncated": False}
        operation = kwargs.get("operation")
        calls.append((operation, remote, kwargs.get("input_bytes")))
        if operation == "inference_provision_sources":
            return {"exit_code": 0, "stdout": json.dumps({
                "success": True, "stage_id": remote[4],
                "bundle": SCRATCH + "/provision-sources/" + remote[4],
                "manifest_sha256": inference.MANIFEST_SHA256,
            }, sort_keys=True).encode() + b"\n",
                "stderr": b"", "timed_out": False, "truncated": False}
        return {"exit_code": 0, "stdout": json.dumps(prepare_payload()).encode(),
                "stderr": b"", "timed_out": False, "truncated": False}

    monkeypatch.setattr(inference, "_call", fake_call)
    tool = provision_tool(monkeypatch, tmp_path)
    result = tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)
    assert calls[0][0] == "inference_provision_sources"
    sources_argv = calls[0][1]
    transfer_id = sources_argv[4]
    assert sources_argv == [
        BOOTSTRAP, "-c", inference.REMOTE_INFERENCE_RECEIVER,
        SCRATCH + "/provision-sources", transfer_id]
    assert sources_argv[2] == inference.REMOTE_INFERENCE_RECEIVER
    assert re.fullmatch(r"[0-9a-f]{32}", transfer_id)
    payload = calls[0][2]
    assert len(payload) <= 32 * 1024 * 1024
    header = json.loads(payload.split(b"\n", 1)[0])
    assert header["manifest_sha256"] == inference.MANIFEST_SHA256
    assert [entry["name"] for entry in header["files"]].count("manifest.json") == 1
    assert len(header["files"]) == 60
    assert calls[1][0] == "inference_provision_prepare"
    prepare_argv = calls[1][1]
    assert prepare_argv[:4] == ["/usr/bin/python3", "-I", "-B", "-c"]
    assert hashlib.sha256(prepare_argv[4].encode()).hexdigest() == (
        inference.PROVISION_PREPARE_SCRIPT_SHA256)
    assert prepare_argv[5] == "prepare"
    assert prepare_argv[6] == BOOTSTRAP
    assert prepare_argv[7] == SCRATCH
    assert prepare_argv[8] == CACHE
    assert prepare_argv[9] == RUN_ID
    assert prepare_argv[10] == SCRATCH + "/provision-sources/" + transfer_id
    assert prepare_argv[11] == "none"
    assert result["phase"] == "prepare"
    assert result["provision_source_transfer_id"] == transfer_id
    assert result["stage_id"] is None
    assert result["blocked"] is True
    assert "review" in result["approval_barrier"]


def test_prepare_surfaced_blockers_fail_before_side_effects(monkeypatch, tmp_path):
    payload = prepare_payload()
    payload["blockers"] = [
        "missing:rl_agent_config.json",
        "laya_wheel_missing_from_previous_wheelhouse",
    ]
    payload["reason"] = "provisioning_refused_before_any_side_effect"

    def fake_call(settings, user, remote, **kwargs):
        if kwargs.get("operation") == "inference_provision":
            return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                    "stderr": b"", "timed_out": False, "truncated": False}
        if kwargs.get("operation") == "inference_provision_sources":
            return {"exit_code": 0, "stdout": json.dumps({
                "success": True, "stage_id": remote[4],
                "bundle": SCRATCH + "/provision-sources/" + remote[4],
                "manifest_sha256": inference.MANIFEST_SHA256,
            }).encode(), "stderr": b"", "timed_out": False, "truncated": False}
        return {"exit_code": 3, "stdout": json.dumps(payload).encode(),
                "stderr": b"", "timed_out": False, "truncated": False}

    monkeypatch.setattr(inference, "_call", fake_call)
    tool = provision_tool(monkeypatch, tmp_path)
    result = tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)
    assert result["blocked"] is True
    assert "missing:rl_agent_config.json" in result["blockers"]
    assert result["environment_provisioned"] is False


def test_prepare_transfer_rejection_aborts(monkeypatch, tmp_path):
    def fake_call(settings, user, remote, **kwargs):
        if kwargs.get("operation") == "inference_provision":
            return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                    "stderr": b"", "timed_out": False, "truncated": False}
        return {"exit_code": 73, "stdout": json.dumps(
            {"success": False, "error": "destination_exists"}).encode(),
            "stderr": b"", "timed_out": False, "truncated": False}

    monkeypatch.setattr(inference, "_call", fake_call)
    tool = provision_tool(monkeypatch, tmp_path)
    with pytest.raises(PermissionError, match="destination_exists"):
        tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)


def test_prepare_transfer_tampered_digest_aborts(monkeypatch, tmp_path):
    def fake_call(settings, user, remote, **kwargs):
        if kwargs.get("operation") == "inference_provision":
            return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                    "stderr": b"", "timed_out": False, "truncated": False}
        if kwargs.get("operation") == "inference_provision_sources":
            return {"exit_code": 65, "stdout": json.dumps(
                {"success": False, "error": "FileExistsError"}).encode(),
                "stderr": b"", "timed_out": False, "truncated": False}
        raise AssertionError("prepare must not run after a rejected transfer")

    monkeypatch.setattr(inference, "_call", fake_call)
    tool = provision_tool(monkeypatch, tmp_path)
    with pytest.raises(PermissionError):
        tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)


def test_prepare_never_adopts_gpu_or_promotion(monkeypatch, tmp_path):
    payload = prepare_payload()
    payload["gpu_allocated"] = True
    monkeypatch.setattr(inference, "_call", prepare_call(payload))
    tool = provision_tool(monkeypatch, tmp_path)
    with pytest.raises(PermissionError, match="GPU"):
        tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)
    payload = prepare_payload()
    payload["runtime_catalog_promoted"] = True
    monkeypatch.setattr(inference, "_call", prepare_call(payload))
    with pytest.raises(PermissionError, match="promote"):
        tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)


def test_prepare_candidate_never_self_reviewed(monkeypatch, tmp_path):
    payload = prepare_payload()
    payload["candidate_runtime_catalog_sha256"] = "c" * 64
    monkeypatch.setattr(inference, "_call", prepare_call(payload))
    tool = provision_tool(monkeypatch, tmp_path)
    result = tool(ws_id(), phase="prepare", previous_run_id=RUN_ID)
    assert result["candidate_runtime_catalog_sha256"] == "c" * 64
    assert result["configured_runtime_catalog_sha256"] is None
    assert result["runtime_catalog_promoted"] is False
    ledger = json.loads((tmp_path / "state" / "scinet_inference.json").read_text())
    record = ledger["provisions"][RUN_ID]
    assert record["blocked"] is True
    assert record["environment_provisioned"] is False


def test_prepared_provision_argv_digest_pin_is_guarded(monkeypatch):
    monkeypatch.setattr(
        inference, "REMOTE_PROVISION_PREPARE",
        inference.REMOTE_PROVISION_PREPARE + "\n# tampered")
    with pytest.raises(PermissionError, match="digest mismatch"):
        inference._provision_argv(
            "prepare", BOOTSTRAP, SCRATCH, CACHE, RUN_ID,
            bundle=SCRATCH + "/provision-sources/" + "b" * 32, digest="none")


def test_prepare_phase_rejects_caller_supplied_stage_id(monkeypatch, tmp_path):
    monkeypatch.setattr(inference, "_call", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("no remote call")))
    tool = provision_tool(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="server-generated"):
        tool(ws_id(), phase="prepare", previous_run_id=RUN_ID, stage_id="b" * 32)


def test_inspect_reports_read_only_state(monkeypatch, tmp_path):
    captured = {}

    def fake_call(settings, user, remote, **kwargs):
        captured["remote"] = remote
        captured["operation"] = kwargs.get("operation")
        return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                "stderr": b"", "timed_out": False, "truncated": False}

    monkeypatch.setattr(inference, "_call", fake_call)
    monkeypatch.setattr(
        inference, "_identity",
        lambda *a: (SimpleNamespace(pw_dir="/home/yeli"),
                    SimpleNamespace(allow_scinet_training=True)))
    tool = inference.create_scinet_inference_provision_tool(None, settings(), tmp_path)
    result = tool(ws_id(), previous_run_id=RUN_ID)
    assert captured["operation"] == "inference_provision"
    assert captured["remote"] == provision_argv()
    assert result["phase"] == "inspect"
    assert result["read_only"] is True
    assert result["gpu_allocated"] is False
    assert result["previous_run_id"] == RUN_ID


def test_inspect_rejects_gpu_or_network_claim(monkeypatch, tmp_path):
    payload = inspect_payload()
    payload["gpu_allocated"] = True
    monkeypatch.setattr(inference, "_call", lambda *a, **k: {
        "exit_code": 0, "stdout": json.dumps(payload).encode(),
        "stderr": b"", "timed_out": False, "truncated": False})
    monkeypatch.setattr(
        inference, "_identity",
        lambda *a: (SimpleNamespace(pw_dir="/home/yeli"),
                    SimpleNamespace(allow_scinet_training=True)))
    tool = inference.create_scinet_inference_provision_tool(None, settings(), tmp_path)
    with pytest.raises(PermissionError, match="GPU"):
        tool(ws_id(), previous_run_id=RUN_ID)


def test_provision_settings_derive_fixed_defaults(monkeypatch):
    monkeypatch.setattr(
        inference, "_identity",
        lambda *a: (SimpleNamespace(pw_dir="/home/yeli"),
                    SimpleNamespace(allow_scinet_training=True)))
    user, _ws, scratch, python, cache = inference._provision_settings(
        None, settings(), ws_id())
    assert scratch == SCRATCH
    assert python == SCRATCH + "/inference-env/bin/python"
    assert cache == SCRATCH + "/model-cache"
    assert inference._provision_settings(None, configured_settings(), ws_id())[2:] == (
        SCRATCH, PYTHON_CONFIGURED, CACHE_CONFIGURED)


def test_provision_settings_reject_partial_configuration(monkeypatch):
    monkeypatch.setattr(
        inference, "_identity",
        lambda *a: (SimpleNamespace(pw_dir="/home/yeli"),
                    SimpleNamespace(allow_scinet_training=True)))
    partial = settings()
    partial.inference_scratch_root = SCRATCH
    with pytest.raises(PermissionError, match="configured together"):
        inference._provision_settings(None, partial, ws_id())


def test_rest_request_requires_only_previous_run_id():
    assert ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID)
    with pytest.raises(Exception):
        ScinetSetupRequest(action="inference_provision")
    with pytest.raises(Exception):
        ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID,
                           stage_id="b" * 32)


PYTHON_CONFIGURED = SCRATCH + "/inference-env/bin/python"
CACHE_CONFIGURED = SCRATCH + "/model-cache"


def settings() -> ScinetSettings:
    return ScinetSettings(
        host="trillium-gpu.alliancecan.ca", user="yeli", machine="asgard",
        training_bootstrap_python=BOOTSTRAP,
    )


def configured_settings() -> ScinetSettings:
    value = settings()
    value.inference_scratch_root = SCRATCH
    value.inference_python = PYTHON_CONFIGURED
    value.inference_hf_cache = CACHE_CONFIGURED
    return value


def ws_id() -> str:
    return "asgard"


def inspect_payload() -> dict:
    return {
        "success": True, "phase": "inspect", "blocked": False, "blockers": [],
        "read_only": True, "gpu_allocated": False, "internet_used": False,
        "previous_run_id": RUN_ID, "previous_run_ok": True,
        "model_checkpoint_sha256": None,
        "model_cache_checkpoint_sha256": None,
        "snapshot_artifacts": [],
        "wheel_count": 0, "wheelhouse_bytes": 0,
        "laya_wheel_present": True,
        "model_cache_snapshot_present": False,
        "bootstrap_python_version": None,
        "wheelhouse_target_exists": False,
        "model_cache_target_exists": False,
        "catalog_candidate_exists": False,
        "catalog_promoted": False,
        "runtime_catalog_promoted": None,
    }


# ---------------------------------------------------------------------------
# Prepare-flow helpers: a locally verified package fixture standing in for the
# reviewed release bytes; the tool still works against the module-pinned
# manifest/template digests, which the fixture builder patches.
# ---------------------------------------------------------------------------


def make_package(root, monkeypatch, *, template=b"template\n"):
    root.mkdir(parents=True, exist_ok=True)
    cases = [f"P{i:04d}_{kind}" for i in range(1, 22) for kind in ("pos", "ctl")]
    files = {name: b"fixed reviewed fixture\n" for name in inference.STATIC_FILES}
    files["code/inference.sbatch.template"] = template
    files.update({f"contexts/{case}.json": b"{}\n" for case in cases})
    files["data/cohort.csv"] = (
        "case_id,context_file_sha256,state_sha256\n"
        + "".join(f"{case},{hashlib.sha256(b'{}\\n').hexdigest()},{'e' * 64}\n"
                  for case in cases)
    ).encode()
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {
        "schema": inference.SCHEMA,
        "stage": inference.STAGE,
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
    monkeypatch.setattr(inference, "MANIFEST_SHA256",
                        hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest())
    monkeypatch.setattr(inference, "TEMPLATE_SHA256", hashlib.sha256(template).hexdigest())


def provision_tool(monkeypatch, tmp_path):
    ws_root = tmp_path / "ws"
    package = ws_root / "data-raw" / "cran-history" / "training" / "trillium" \
        / "standalone-inference" / "package-v2"
    package.parent.mkdir(parents=True, exist_ok=True)
    make_package(package, monkeypatch)
    workspace = SimpleNamespace(path=ws_root, allow_scinet_training=True)
    monkeypatch.setattr(
        inference, "_identity",
        lambda *a: (SimpleNamespace(pw_dir="/home/yeli"), workspace))
    return inference.create_scinet_inference_provision_tool(None, settings(), tmp_path / "state")


def prepare_payload() -> dict:
    return {
        "success": True, "phase": "prepare", "blocked": True,
        "reason": "runtime_catalog_candidate_awaits_independent_human_review",
        "candidate_runtime_catalog_sha256": "c" * 64,
        "environment_provisioned": False, "runtime_catalog_promoted": None,
        "wheel_count": 3, "snapshot_files": ["model.safetensors"],
        "blockers": ["the candidate catalog sha must be independently reviewed"],
        "gpu_allocated": False, "internet_used": False,
    }


def transfer_fixture():
    def fake_call(settings, user, remote, **kwargs):
        return {"exit_code": 0, "stdout": json.dumps({
            "success": True, "stage_id": remote[4],
            "bundle": SCRATCH + "/provision-sources/" + remote[4],
            "manifest_sha256": inference.MANIFEST_SHA256,
        }).encode(), "stderr": b"", "timed_out": False, "truncated": False}
    return fake_call


def prepare_call(payload: dict):
    transfer = transfer_fixture()

    def fake_call(settings, user, remote, **kwargs):
        if kwargs.get("operation") == "inference_provision":
            return {"exit_code": 0, "stdout": json.dumps(inspect_payload()).encode(),
                    "stderr": b"", "timed_out": False, "truncated": False}
        if kwargs.get("operation") == "inference_provision_sources":
            return transfer(settings, user, remote, **kwargs)
        return {"exit_code": 0, "stdout": json.dumps(payload).encode(),
                "stderr": b"", "timed_out": False, "truncated": False}

    return fake_call


def test_broker_accepts_pinned_sources_argv():
    argv = [BOOTSTRAP, "-c", inference.REMOTE_INFERENCE_RECEIVER,
            SCRATCH + "/provision-sources", "b" * 32]
    command = broker.inference_provision_sources_command(argv)
    assert "920s" in command and "/usr/bin/python3" in command
    envelope = broker._ssh_envelope(
        "trillium-gpu.alliancecan.ca", "yeli", "/tmp/.ssh/cm",
        argv, operation="inference_provision_sources")
    assert "-n" not in envelope


def test_broker_rejects_unsafe_sources_arguments():
    base = [BOOTSTRAP, "-c", inference.REMOTE_INFERENCE_RECEIVER,
            SCRATCH + "/provision-sources", "b" * 32]
    mutations = (
        lambda r: r.__setitem__(2, r[2] + "\nimport os"),
        lambda r: r.__setitem__(3, SCRATCH + "/stages"),
        lambda r: r.__setitem__(3, SCRATCH + "/provision-sources/../runs"),
        lambda r: r.__setitem__(3, "/provision-sources"),
        lambda r: r.__setitem__(3, SCRATCH + "/other-root"),
        lambda r: r.__setitem__(4, "zz"),
        lambda r: r.__setitem__(4, "b" * 31),
        lambda r: r.__setitem__(0, BOOTSTRAP + ";sh"),
        lambda r: r.insert(3, "-I"),
    )
    for mutate in mutations:
        remote = list(base)
        mutate(remote)
        with pytest.raises(PermissionError):
            broker.inference_provision_sources_command(remote)


def test_broker_prepare_command_and_stdin_denial():
    bundle = SCRATCH + "/provision-sources/" + "b" * 32
    argv = inference._provision_argv(
        "prepare", BOOTSTRAP, SCRATCH, CACHE, RUN_ID, bundle=bundle, digest="none")
    command = broker.inference_provision_prepare_command(argv)
    assert "920s" in command
    envelope = broker._ssh_envelope(
        "trillium-gpu.alliancecan.ca", "yeli", "/tmp/.ssh/cm",
        argv, operation="inference_provision_prepare")
    assert "-n" in envelope


def test_broker_rejects_tampered_or_unsafe_prepare_arguments():
    bundle = SCRATCH + "/provision-sources/" + "b" * 32
    base = inference._provision_argv(
        "prepare", BOOTSTRAP, SCRATCH, CACHE, RUN_ID, bundle=bundle, digest="none")
    mutations = (
        lambda r: r.__setitem__(4, r[4] + "\n"),
        lambda r: r.__setitem__(5, "inspect"),
        lambda r: r.__setitem__(6, "/usr/../bin/python3"),
        lambda r: r.__setitem__(10, SCRATCH + "/provision-sources/" + "zz"),
        lambda r: r.__setitem__(10, SCRATCH + "/runs/" + "b" * 32),
        lambda r: r.__setitem__(11, "0" * 63),
        lambda r: r.__setitem__(11, "none; rm -rf ~"),
        lambda r: r.__setitem__(7, "not-a-scratch"),
        lambda r: r.pop(),
    )
    for mutate in mutations:
        remote = list(base)
        mutate(remote)
        with pytest.raises(PermissionError):
            broker.inference_provision_prepare_command(remote)


def test_broker_request_denies_arbitrary_commands_and_oversized_stdin(monkeypatch, tmp_path):
    instance = broker.ScinetBroker(str(tmp_path / "broker.sock"),
                                   str(tmp_path / "control.sock"),
                                   "trillium-gpu.alliancecan.ca", "yeli")
    sources_remote = [BOOTSTRAP, "-c", inference.REMOTE_INFERENCE_RECEIVER,
                      SCRATCH + "/provision-sources", "b" * 32]
    with pytest.raises(PermissionError):
        instance._request({"version": broker.BROKER_PROTOCOL,
                           "operation": "inference_provision_sources",
                           "remote": sources_remote, "input_length": 5,
                           "command": "arbitrary"}, b"data!")
    with pytest.raises(PermissionError):
        instance._request({"version": broker.BROKER_PROTOCOL,
                           "operation": "inference_provision_sources",
                           "remote": sources_remote, "input_length": 0}, b"")
    oversized = broker.PROVISION_SOURCES_MAX_INPUT_BYTES + 1
    with pytest.raises(PermissionError):
        instance._request({"version": broker.BROKER_PROTOCOL,
                           "operation": "inference_provision_sources",
                           "remote": sources_remote, "input_length": oversized},
                          bytes(oversized))
    prepare_remote = inference._provision_argv(
        "prepare", BOOTSTRAP, SCRATCH, CACHE, RUN_ID,
        bundle=SCRATCH + "/provision-sources/" + "b" * 32, digest="none")
    with pytest.raises(PermissionError):
        instance._request({"version": broker.BROKER_PROTOCOL,
                           "operation": "inference_provision_prepare",
                           "remote": prepare_remote, "input_length": 1}, b"x")
    accepted = instance._request({"version": broker.BROKER_PROTOCOL,
                                  "operation": "inference_provision_prepare",
                                  "remote": prepare_remote, "input_length": 0}, b"")
    assert accepted["error"] in (None, "scinet_auth_required")
    assert accepted["error"] in (None, "scinet_auth_required")


def test_fallback_rejects_wrong_stdin_mode_for_new_ops():
    from agentporter.tools import scinet
    settings_value = ScinetSettings(
        host="trillium-gpu.alliancecan.ca", user="yeli",
        control_socket="/home/yeli/.ssh/cm", machine="asgard",
    )
    user = SimpleNamespace(pw_dir="/home/yeli")
    sources_remote = [BOOTSTRAP, "-c", inference.REMOTE_INFERENCE_RECEIVER,
                      SCRATCH + "/provision-sources", "b" * 32]
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(settings_value, user, sources_remote,
                                input_bytes=None, operation="inference_provision_sources")
    prepare_remote = inference._provision_argv(
        "prepare", BOOTSTRAP, SCRATCH, CACHE, RUN_ID,
        bundle=SCRATCH + "/provision-sources/" + "b" * 32, digest="none")
    with pytest.raises(PermissionError):
        scinet.run_scinet_bytes(settings_value, user, prepare_remote, input_bytes=b"x",
                                operation="inference_provision_prepare")


def test_rest_request_accepts_only_inspect_or_prepare_phase():
    assert ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID)
    assert ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID,
                              phase="prepare")
    assert ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID,
                              phase="inspect")
    for bad in ("deploy", "stage"):
        with pytest.raises(Exception):
            ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID,
                               phase=bad)  # type: ignore[arg-type]
    with pytest.raises(Exception):
        ScinetSetupRequest(action="inference_preflight", phase="prepare")
    with pytest.raises(Exception):
        ScinetSetupRequest(action="inference_provision", previous_run_id=RUN_ID,
                           phase="prepare", stage_id="b" * 32)
