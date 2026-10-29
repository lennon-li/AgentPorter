"""Independent signatures and durable, request-scoped replay protection."""
import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter import scoped_approvals as approvals


@pytest.fixture
def context(tmp_path):
    key = Ed25519PrivateKey.generate()
    root = tmp_path / "workspace"
    root.mkdir()
    args = {"task": "Fix the bounded bug", "agent": "jax"}
    options = dict(workspace_id="a7", workspace_root=str(root), action="dispatch_agent",
                   arguments=args, operations=["write"], expires_at=1500,
                   issued_at=1000, agent="jax")
    verifier = approvals.ApprovalVerifier(key.public_key(), tmp_path / "grants.sqlite", clock=lambda: 1100)
    verify = dict(workspace_id="a7", workspace_root=str(root), action="dispatch_agent",
                  arguments=args, request_id="request-1", required_operations={"write"}, agent="jax")
    return key, options, verifier, verify


def test_signed_grant_allows_identical_retry(context):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    first = verifier.verify(token, **verify)
    assert first.grant_id
    assert first.claims["task_sha256"]
    assert verifier.verify(token, **verify).grant_id == first.grant_id


@pytest.mark.parametrize("field,value", [
    ("workspace_id", "elsewhere"), ("workspace_root", "/different"),
    ("action", "exec_run"), ("arguments", {"task": "Delete everything"}),
    ("agent", "liz"), ("required_operations", {"delete"}),
])
def test_scope_mismatch_denied(context, field, value):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    verify[field] = value
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)


def test_different_request_cannot_reuse_grant(context):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    verifier.verify(token, **verify)
    verify["request_id"] = "different"
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)


def test_replay_is_persistent(context, tmp_path):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    verifier.verify(token, **verify)
    fresh = approvals.ApprovalVerifier(key.public_key(), tmp_path / "grants.sqlite", clock=lambda: 1100)
    with pytest.raises(approvals.ApprovalError):
        fresh.verify(token, **{**verify, "request_id": "new"})


def test_signature_and_expiry_fail_closed(context):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    stranger = approvals.ApprovalVerifier(Ed25519PrivateKey.generate().public_key(), verifier.ledger_path, clock=lambda: 1100)
    with pytest.raises(approvals.ApprovalError):
        stranger.verify(token, **verify)
    verifier.clock = lambda: 1500
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)


def test_tampered_payload_denied(context):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["workspace_id"] = "evil"
    altered = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(altered + "." + signature, **verify)


@pytest.mark.parametrize("arguments", [{"n": float("nan")}, {"n": float("inf")}, {"x": "e\u0301"}, {"x": "\ud800"}, {1: "bad"}, {"x": (1, 2)}])
def test_ambiguous_arguments_denied(arguments):
    with pytest.raises(approvals.ApprovalError):
        approvals.hash_arguments(arguments)


def test_argument_hash_is_key_order_independent():
    assert approvals.hash_arguments({"b": 2, "a": 1}) == approvals.hash_arguments({"a": 1, "b": 2})


def test_transport_fields_are_not_hashed():
    assert approvals.hash_arguments({"task": "x", "approval_token": "secret", "request_id": "r"}) == approvals.hash_arguments({"task": "x"})


@pytest.mark.parametrize("changes", [
    {"operations": ["shell"]}, {"operations": []}, {"operations": ["write", "write"]},
    {"expires_at": 50000}, {"expires_at": True}, {"issued_at": True},
    {"action": "unknown"}, {"agent": None}, {"grant_id": "not-random-id"},
])
def test_issuer_rejects_invalid_claims(context, changes):
    key, options, _, _ = context
    with pytest.raises(approvals.ApprovalError):
        approvals.sign_grant(key, **{**options, **changes})


@pytest.mark.parametrize("raw", [b'{"version":1,"version":1}', b'{"expires_at":NaN}', b'[]', b'{}'])
def test_signed_malformed_schema_rejected(context, raw):
    key, _, verifier, verify = context
    enc = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    token = enc(raw) + "." + enc(key.sign(raw))
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)


@pytest.mark.parametrize("token", ["", "x" * 8193, "bad.bad", "a.b.c", "é.a"])
def test_malformed_token_rejected(context, token):
    _, _, verifier, verify = context
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)


@pytest.mark.parametrize("mode", [0o644, 0o666])
def test_ledger_permissions_rejected(context, tmp_path, mode):
    key, options, verifier, verify = context
    verifier.ledger_path.touch(mode=mode)
    os.chmod(verifier.ledger_path, mode)
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(approvals.sign_grant(key, **options), **verify)


def test_ledger_symlink_rejected(context, tmp_path):
    key, options, verifier, verify = context
    target = tmp_path / "other"
    target.touch(mode=0o600)
    verifier.ledger_path.symlink_to(target)
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(approvals.sign_grant(key, **options), **verify)


def test_grant_id_cannot_be_reissued_for_another_scope(context):
    key, options, verifier, verify = context
    grant_id = "a" * 32
    verifier.verify(approvals.sign_grant(key, **options, grant_id=grant_id), **verify)
    changed = {**options, "operations": ["write", "delete"]}
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(approvals.sign_grant(key, **changed, grant_id=grant_id), **verify)


@pytest.mark.parametrize("field,value", [("version", True), ("extra", "unknown"), ("expires_at", True), ("operations", ["write", 1])])
def test_signed_invalid_schema_denied(context, field, value):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    payload[field] = value
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    enc = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(enc(raw) + "." + enc(key.sign(raw)), **verify)


def test_not_yet_valid_does_not_consume_grant(context):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    verifier.clock = lambda: 999
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(token, **verify)
    assert not verifier.ledger_path.exists()
    verifier.clock = lambda: 1100
    verifier.verify(token, **verify)


def test_separate_service_ledgers_accept_same_admission(context, tmp_path):
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)
    verifier.verify(token, **verify)
    worker = approvals.ApprovalVerifier(key.public_key(), tmp_path / "worker.sqlite", clock=lambda: 1100)
    assert worker.verify(token, **verify).grant_id


def test_raw_and_pem_public_keys(context, tmp_path):
    from cryptography.hazmat.primitives import serialization
    key, options, _, verify = context
    token = approvals.sign_grant(key.private_bytes_raw(), **options)
    for public in [key.public_key().public_bytes_raw(), key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)]:
        verifier = approvals.ApprovalVerifier(public, tmp_path / "keys.sqlite", clock=lambda: 1100)
        assert verifier.verify(token, **verify).grant_id


def test_commit_requires_explicit_commit_operation(context):
    key, options, verifier, verify = context
    options.update(action="git_commit", agent=None, operations=["commit"])
    verify.update(action="git_commit", agent=None, required_operations={"commit"})
    assert verifier.verify(approvals.sign_grant(key, **options), **verify).grant_id


def test_unsafe_ledger_directory_rejected(context, tmp_path):
    key, options, verifier, verify = context
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    verifier.ledger_path = public / "ledger"
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(approvals.sign_grant(key, **options), **verify)


def test_nonfinite_clock_fails_closed(context):
    key, options, verifier, verify = context
    verifier.clock = lambda: float("nan")
    with pytest.raises(approvals.ApprovalError):
        verifier.verify(approvals.sign_grant(key, **options), **verify)


def test_concurrent_different_requests_allow_only_one(context):
    from concurrent.futures import ThreadPoolExecutor
    key, options, verifier, verify = context
    token = approvals.sign_grant(key, **options)

    def attempt(index):
        try:
            verifier.verify(token, **{**verify, "request_id": f"request-{index}"})
            return True
        except approvals.ApprovalError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(8))) == 1


def test_private_key_file_must_be_owned_private_regular_file(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "issuer.key"
    path.write_bytes(key.private_bytes_raw())
    os.chmod(path, 0o600)
    assert approvals.load_private_key(path, owner_uid=os.geteuid()).public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    os.chmod(path, 0o644)
    with pytest.raises(approvals.ApprovalError):
        approvals.load_private_key(path, owner_uid=os.geteuid())
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(approvals.ApprovalError):
        approvals.load_private_key(link, owner_uid=os.geteuid())


@pytest.fixture
def issuer():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "scripts/issue-production-approval.py"
    spec = importlib.util.spec_from_file_location("production_issuer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_plan_does_not_load_private_key(issuer, context, tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    _, options, _, _ = context
    policy = SimpleNamespace(workspaces={"a7": {"path": options["workspace_root"]}}, capabilities=lambda _: {"writable": True})
    monkeypatch.setattr(issuer, "load_workspace_policy", lambda: policy)
    monkeypatch.setattr(issuer, "load_private_key", lambda *_: pytest.fail("plan must not load signing key"))
    request = tmp_path / "request.json"
    request.write_text(json.dumps(options["arguments"]))
    os.chmod(request, 0o600)
    assert issuer.main(["--workspace", "a7", "--agent", "jax", "--action", "dispatch_agent", "--request-json", str(request), "--operations", "write", "--ttl", "300"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["approval_required"] is True
    assert "approval_token" not in result


def test_cli_requires_root_and_emits_bound_token(issuer, context, tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    key, options, verifier, verify = context
    policy = SimpleNamespace(workspaces={"a7": {"path": options["workspace_root"]}}, capabilities=lambda _: {"writable": True})
    monkeypatch.setattr(issuer, "load_workspace_policy", lambda: policy)
    request = tmp_path / "request.json"
    request.write_text(json.dumps(options["arguments"]))
    os.chmod(request, 0o600)
    argv = ["--workspace", "a7", "--agent", "jax", "--action", "dispatch_agent", "--request-json", str(request), "--operations", "write", "--ttl", "300", "--approve"]
    monkeypatch.setattr(issuer.os, "geteuid", lambda: 1000)
    with pytest.raises(approvals.ApprovalError):
        issuer.main(argv)
    monkeypatch.setattr(issuer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(issuer, "load_private_key", lambda path: key)
    monkeypatch.setattr(issuer, "_read_request", lambda path: options["arguments"])
    assert issuer.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["request_id"]) == 32
    import time
    verifier.clock = time.time
    monkeypatch.setattr(issuer.os, "geteuid", lambda: verifier.ledger_path.parent.stat().st_uid)
    normalized = {"workspace_id": "a7", "task": "Fix the bounded bug", "agent": "jax",
                  "purpose": "", "model": None, "reasoning_effort": None,
                  "allow_commit": False, "allow_push": False, "read_only": True}
    assert verifier.verify(result["approval_token"], **{**verify, "arguments": normalized, "request_id": result["request_id"]}).grant_id


@pytest.mark.parametrize("workspace,writable,operations,ttl", [
    ("unregistered", True, "write", "300"), ("a7", False, "write", "300"),
    ("a7", True, "shell", "300"), ("a7", True, "write", "3601"),
    ("a7", True, "write,write", "300"),
])
def test_cli_refuses_invalid_scope(issuer, context, tmp_path, monkeypatch, workspace, writable, operations, ttl):
    from types import SimpleNamespace
    _, options, _, _ = context
    policy = SimpleNamespace(workspaces={"a7": {"path": options["workspace_root"]}}, capabilities=lambda _: {"writable": writable})
    monkeypatch.setattr(issuer, "load_workspace_policy", lambda: policy)
    monkeypatch.setattr(issuer, "load_private_key", lambda *_: pytest.fail("denied scope must not load signing key"))
    with pytest.raises(approvals.ApprovalError):
        issuer.main(["--workspace", workspace, "--agent", "jax", "--action", "dispatch_agent", "--request-json", str(tmp_path / "unused"), "--operations", operations, "--ttl", ttl])


@pytest.mark.parametrize("raw", ['{"task":"one","task":"two"}', '{"value":NaN}', '[]'])
def test_cli_request_rejects_ambiguous_json(issuer, tmp_path, raw):
    request = tmp_path / "request.json"
    request.write_text(raw)
    os.chmod(request, 0o600)
    with pytest.raises(approvals.ApprovalError):
        issuer._read_request(str(request))


def test_private_key_file_rejects_wrong_owner_and_malformed_bytes(tmp_path):
    path = tmp_path / "key"
    path.write_bytes(b"malformed key")
    os.chmod(path, 0o600)
    with pytest.raises(approvals.ApprovalError):
        approvals.load_private_key(path, owner_uid=os.geteuid() + 1)
    with pytest.raises(approvals.ApprovalError):
        approvals.load_private_key(path, owner_uid=os.geteuid())
