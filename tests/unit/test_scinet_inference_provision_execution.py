"""Execute provisioning code with small, private local fixtures.

The driver and its file helpers are real. Only the scratch path policy, large
artifact pins and subprocess outcomes are substituted in prepare tests. These
tests do NOT install wheels, validate an 842 MB model, or establish GPU/runtime
compatibility. The preflight import test executes the actual frozen CLI with
--help; candidate generation and installation are controlled test doubles.
"""

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agentporter.tools import scinet_inference as inference


RUN = "a" * 32
TRANSFER = "b" * 32
FROZEN = Path(
    "/home/operator/repos/cranary/data-raw/cran-history/training/trillium/"
    "standalone-inference/package-v2"
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_file(path, raw=b"small fixture\n"):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def definitions(source):
    """Keep the original driver logic, removing only its top-level invocation."""
    tree = ast.parse(source)
    tree.body = [
        node for node in tree.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "main")
    ]
    return ast.unparse(tree)


# Defense in depth: even a regressed driver cannot mutate /scratch or invoke a
# shell/network command. Reads remain available for the stdlib and frozen code.
SANDBOX = r'''
import os, sys
from pathlib import Path
test_root = Path(sys.argv[1]).resolve()
def inside(path):
    if isinstance(path, int):
        return True
    return Path(os.fsdecode(path)).resolve().is_relative_to(test_root)
def audit(event, args):
    if event == "open":
        mode, flags = args[1:3]
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if writing and args[0] != os.devnull and not inside(args[0]):
            raise AssertionError("write outside hermetic fixture: " + str(args[0]))
    elif event in {"os.mkdir", "os.chmod", "os.remove", "os.rmdir", "os.utime"}:
        if not inside(args[0]):
            raise AssertionError("mutation outside hermetic fixture")
    elif event in {"os.rename", "os.link", "os.symlink"}:
        if not all(inside(p) for p in args[:2]):
            raise AssertionError("mutation outside hermetic fixture")
    elif event.startswith("socket.") or event in {"os.system", "os.exec", "os.posix_spawn"}:
        raise AssertionError("external execution/network forbidden")
    elif event == "subprocess.Popen":
        if args[0] != sys.executable:
            raise AssertionError("only isolated local Python is allowed")
sys.addaudithook(audit)
os.umask(0o077)
'''


def isolated(root, code, payload=b""):
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", SANDBOX + "\n" + code, str(root)],
        input=payload, capture_output=True, timeout=25, cwd=root,
        env={"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root),
             "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
             "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )


def receipt(result):
    assert result.stdout, result.stderr.decode(errors="replace")
    return json.loads(result.stdout.splitlines()[-1])


@pytest.mark.parametrize("helper", ["checkpoint_identity", "sha_file", "copy_regular_file"])
def test_real_helpers_accept_unchanged_regular_file(tmp_path, helper):
    source = private_file(tmp_path / "source")
    target = tmp_path / "copy"
    args = {
        "checkpoint_identity": [str(source)],
        "sha_file": [str(source), 1024],
        "copy_regular_file": [str(source), str(target), 1024],
    }[helper]
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON +
                      f"\nprint(json.dumps({helper}(*{args!r})))")
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == [sha(source.read_bytes()), source.stat().st_size]
    if helper == "copy_regular_file":
        assert target.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("helper", ["checkpoint_identity", "sha_file", "copy_regular_file"])
@pytest.mark.parametrize("link_type", ["symlink", "hardlink"])
def test_real_helpers_refuse_linked_inputs(tmp_path, helper, link_type):
    original = private_file(tmp_path / "original")
    source = tmp_path / "linked"
    if link_type == "symlink":
        source.symlink_to(original)
    else:
        os.link(original, source)
    args = [str(source)]
    if helper == "sha_file":
        args.append(1024)
    elif helper == "copy_regular_file":
        args += [str(tmp_path / "copy"), 1024]
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON + f'''
try:
    {helper}(*{args!r})
except (OSError, ValueError):
    print('{{"refused":true}}')
else:
    raise AssertionError("linked input accepted")
''')
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == {"refused": True}
    assert not (tmp_path / "copy").exists()


def test_real_copy_is_idempotent_but_refuses_different_existing_target(tmp_path):
    source = private_file(tmp_path / "source")
    target = private_file(tmp_path / "target", source.read_bytes())
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON + f'''
print(json.dumps(copy_regular_file({str(source)!r}, {str(target)!r}, 1024)))
''')
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == [sha(source.read_bytes()), source.stat().st_size]
    target.write_bytes(b"different")
    target.chmod(0o600)
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON + f'''
try:
    copy_regular_file({str(source)!r}, {str(target)!r}, 1024)
except ValueError:
    print('{{"refused":true}}')
else:
    raise AssertionError("different existing target accepted")
''')
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == {"refused": True}


@pytest.fixture
def reviewed_bundle():
    if not FROZEN.is_dir():
        pytest.skip("frozen Cranary package-v2 is not present on this host")
    raw = (FROZEN / "manifest.json").read_bytes()
    assert sha(raw) == inference.MANIFEST_SHA256
    manifest = json.loads(raw)
    for name, digest in manifest["files"].items():
        assert not (FROZEN / name).is_symlink()
        assert sha((FROZEN / name).read_bytes()) == digest, name
    return manifest


def test_reviewed_manifest_and_driver_source_pins(reviewed_bundle):
    """Reviewed script digests must be independent constants in the remote driver."""
    literals = {
        node.value for node in ast.walk(ast.parse(inference.REMOTE_PROVISION_PREPARE))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for name in ("code/prepare_runtime.sh", "code/runtime_preflight.py",
                 "code/requirements-inference.lock", "code/handoff.py"):
        assert reviewed_bundle["files"][name] in literals, f"remote driver lacks reviewed pin: {name}"
    assert reviewed_bundle["files"]["code/offline_runner.py"] in inference.REMOTE_PROVISION_PREPARE
    for source, digest in (
        (inference.REMOTE_PROVISION_PREPARE, inference.PROVISION_PREPARE_SCRIPT_SHA256),
        (inference.REMOTE_PROVISION_INSPECT, inference.PROVISION_INSPECT_SCRIPT_SHA256),
    ):
        assert sha(source.encode()) == digest


def driver_node(predicate):
    main = next(node for node in ast.parse(inference.REMOTE_PROVISION_PREPARE).body
                if isinstance(node, ast.FunctionDef) and node.name == "main")
    matches = [node for node in main.body if predicate(node)]
    assert len(matches) == 1, "driver structure changed; update the AST extraction explicitly"
    return matches[0]


def contains(node, literal):
    return any(isinstance(child, ast.Constant) and child.value == literal
               for child in ast.walk(node))


def test_original_candidate_policy_accepts_complete_tiny_inventory(tmp_path):
    # Execute the actual policy branch independently of earlier file checks so
    # the historical tuple <= set TypeError cannot be hidden by another defect.
    branch = driver_node(lambda node: isinstance(node, ast.If) and
                         contains(node, "candidate_catalog_failed_checkpoint_policy"))
    code = inference.REMOTE_PROVISION_COMMON + '''
snapshot_files = {name: {"sha256": CHECKPOINT_SHA256, "size": WEIGHTS_BYTES}
                  for name in REQUIRED_ARTIFACTS}
content = {"snapshot_files": snapshot_files}
candidate_sha = "c" * 64
'''
    result = isolated(tmp_path, code + ast.unparse(branch) + '\nprint("{\\"accepted\\":true}")')
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == {"accepted": True}


def test_original_success_receipt_has_explicit_unblocked_contract(tmp_path):
    statement = driver_node(lambda node: isinstance(node, ast.Expr) and
                            contains(node, "env_python") and contains(node, "environment_provisioned"))
    scope = '''
env_python = "/fixture/inference-env/bin/python"
catalog_digest = candidate_sha = "c" * 64
script_sha = preflight_sha = "d" * 64
wheels = ["tiny.whl"]
wheel_bytes = 10
snapshot_files = dict.fromkeys(REQUIRED_ARTIFACTS)
'''
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON + scope + ast.unparse(statement))
    assert result.returncode == 0, result.stderr.decode()
    value = receipt(result)
    assert value["success"] is True and value["environment_provisioned"] is True
    assert value.get("blocked") is False and value.get("blockers") == []


@pytest.fixture
def provision_tree(tmp_path, reviewed_bundle):
    root = tmp_path / "scratch"
    root.mkdir(mode=0o700)
    bundle = root / "provision-sources" / TRANSFER
    # Copy only the 60 reviewed small release files, never model/cache contents.
    for name in ["manifest.json", *reviewed_bundle["files"]]:
        private_file(bundle / name, (FROZEN / name).read_bytes())
    model = root / "runs" / RUN / "model"
    for name in ("model.safetensors", "rl_agent_config.json", "encoder/config.json",
                 "tokenizer/tokenizer.json", "tokenizer/tokenizer_config.json"):
        private_file(model / name, b"tiny model" if name == "model.safetensors" else b"{}")
    private_file(root / "runs" / RUN / "wheelhouse" / "laya-0.3.28-py3-none-any.whl", b"tiny wheel")
    for directory in root.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o700)
    return root, bundle


def prepare(root, bundle, *, digest="none", probe="True"):
    # AST extraction removes only main(sys.argv); all original branches run.
    # The two small-fixture pins replace the checkpoint/wheel payloads, not the
    # independently reviewed manifest or runtime script digests.
    setup = f'''
import re, subprocess
SCRATCH_RE = re.compile(re.escape({str(root)!r}) + r"(?:/[A-Za-z0-9_./-]+)?\\Z")
CHECKPOINT_SHA256 = {sha(b"tiny model")!r}
WEIGHTS_BYTES = {len(b"tiny model")}
LAYA_WHEEL_SHA256 = {sha(b"tiny wheel")!r}
LAYA_WHEEL_BYTES = {len(b"tiny wheel")}
actual_run = subprocess.run
calls = []
def simulated_run(argv, **kwargs):
    calls.append(argv)
    if argv[0] == "/bin/bash":
        p = Path({str(root)!r}) / "inference-env/bin/python"
        p.parent.mkdir(parents=True, mode=0o700)
        p.write_bytes(b"fixture interpreter, not executable")
        return subprocess.CompletedProcess(argv, 0, b"", b"")
    raise AssertionError("unexpected subprocess: " + repr(argv))
subprocess.run = simulated_run
def run_python(argv, timeout):
    if "-c" in argv and "sys.version_info" in argv[argv.index("-c") + 1]:
        if {probe is None!r}:
            return actual_run(argv, capture_output=True, timeout=10,
                              env={{"PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"}})
        return subprocess.CompletedProcess(argv, 0, {(probe or '').encode()!r}, b"")
    candidate = Path({str(root)!r}) / "runtime-catalog.candidate.json"
    files = {{name: {{"sha256": CHECKPOINT_SHA256 if name == "model.safetensors" else {sha(b'{}')!r},
                     "size": WEIGHTS_BYTES if name == "model.safetensors" else 2}}
             for name in REQUIRED_ARTIFACTS}}
    lock = Path({str(bundle / 'code/requirements-inference.lock')!r}).read_bytes()
    catalog = {{"schema": "laya-inference-runtime-v1", "model": "convaiinnovations/laya",
               "revision": REVISION, "python": "3.12", "cuda": "12.8",
               "lock_sha256": hashlib.sha256(lock).hexdigest(),
               "versions": dict(re.findall(r'^([A-Za-z0-9_-]+)==([^\\s\\\\]+)', lock.decode(), re.M)),
               "snapshot_files": files,
               "wheel_files": {{LAYA_WHEEL: {{"sha256": LAYA_WHEEL_SHA256, "size": LAYA_WHEEL_BYTES}}}}}}
    raw = (json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\\n").encode()
    if not candidate.exists():
        candidate.write_bytes(raw)
    return subprocess.CompletedProcess(argv, 0, b"", b"")
args = ["driver", "prepare", sys.executable, {str(root)!r},
        {str(root / 'model-cache')!r}, {RUN!r}, {str(bundle)!r}, {digest!r}]
main(args)
'''
    return isolated(root.parent, definitions(inference.REMOTE_PROVISION_PREPARE) + "\n" + setup)


def test_actual_preflight_loader_imports_verified_sources_under_isolation(provision_tree):
    root, bundle = provision_tree
    node = next(node for node in ast.parse(inference.REMOTE_PROVISION_PREPARE).body
                if isinstance(node, ast.FunctionDef) and node.name == "run_verified_preflight")
    setup = f'''
import subprocess, sys
OFFLINE_ENV = {{"PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"}}
def run_python(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, env=OFFLINE_ENV, check=False)
'''
    call = f'''
result = run_verified_preflight(sys.executable, {str(bundle / 'code')!r},
                               {str(root / 'model-cache')!r}, {str(root / 'wheelhouse')!r},
                               {str(root / 'candidate.json')!r}, [])
print(json.dumps({{"returncode": result.returncode, "stderr": result.stderr.decode()}}))
'''
    result = isolated(root.parent, definitions(inference.REMOTE_PROVISION_COMMON) + setup
                      + ast.unparse(node) + call)
    value = receipt(result)
    # Real isolated candidate-generation invocation; tiny fixtures deliberately
    # fail pinned artifact policy, but must pass the frozen sibling import phase.
    assert result.returncode == 0, result.stderr.decode()
    assert value["returncode"] == 3, value
    assert "No module named 'offline_runner'" not in value["stderr"]
    assert not (root / "candidate.json").exists()


def test_prepare_candidate_review_and_resume_do_not_duplicate_work(provision_tree):
    root, bundle = provision_tree
    first = prepare(root, bundle)
    value = receipt(first)
    assert first.returncode == 3, (value, first.stderr.decode())
    assert value["reason"] == "runtime_catalog_candidate_awaits_independent_human_review"
    assert value["blocked"] is True and value["environment_provisioned"] is False
    candidate = root / "runtime-catalog.candidate.json"
    raw = candidate.read_bytes()
    assert value["candidate_runtime_catalog_sha256"] == sha(raw)
    before = {str(p.relative_to(root)): (p.stat().st_ino, p.read_bytes())
              for p in root.rglob("*") if p.is_file()}
    repeated = prepare(root, bundle)
    repeated_value = receipt(repeated)
    assert repeated.returncode == 3, (repeated_value, repeated.stderr.decode())
    assert repeated_value["reason"] == value["reason"]
    after = {str(p.relative_to(root)): (p.stat().st_ino, p.read_bytes())
             for p in root.rglob("*") if p.is_file()}
    assert after == before, "retry must neither recopy nor recreate candidate artifacts"
    # Simulate explicit operator placement of independently reviewed bytes.
    private_file(root / "runtime-catalog.json", raw)
    resumed = prepare(root, bundle, digest=sha(raw))
    final = receipt(resumed)
    assert resumed.returncode == 0, (final, resumed.stderr.decode())
    assert final["environment_provisioned"] is True
    assert final["blocked"] is False and final["blockers"] == []
    assert final["runtime_catalog_promoted"] is False
    assert final["runtime_catalog_sha256"] == sha(raw)
    assert candidate.read_bytes() == raw




def test_prepare_rejects_missing_pinned_laya_wheel_before_copying(provision_tree):
    root, bundle = provision_tree
    wheel = root / "runs" / RUN / "wheelhouse" / "laya-0.3.28-py3-none-any.whl"
    wheel.unlink()
    result = prepare(root, bundle)
    value = receipt(result)
    assert result.returncode == 3, value
    assert any(item.startswith("laya_wheel_missing_from_previous_wheelhouse")
               for item in value["blockers"])
    assert not (root / "wheelhouse").exists()
    assert not (root / "model-cache" / "models--convaiinnovations--laya" / inference.REVISION).exists()

@pytest.mark.parametrize("probe", ["False", "not True", "True-ish"])
def test_prepare_rejects_non_312_interpreter_before_creating_targets(provision_tree, probe):
    root, bundle = provision_tree
    result = prepare(root, bundle, probe=probe)
    value = receipt(result)
    assert result.returncode != 0
    assert "bootstrap_python_3_12_unavailable" in value["blockers"]
    for target in ("wheelhouse", "inference-env", "provision-cache", "model-cache"):
        assert not (root / target).exists()


def test_prepare_real_wrong_python_version_is_refused(provision_tree):
    if sys.version_info[:2] == (3, 12):
        pytest.skip("host interpreter is 3.12; no real wrong-version interpreter available")
    root, bundle = provision_tree
    result = prepare(root, bundle, probe=None)
    value = receipt(result)
    assert result.returncode != 0
    assert "bootstrap_python_3_12_unavailable" in value["blockers"]
    assert not (root / "wheelhouse").exists()
    assert not (root / "runtime-catalog.candidate.json").exists()


@pytest.mark.parametrize("name", ["prepare_runtime.sh", "runtime_preflight.py",
                                 "requirements-inference.lock", "handoff.py"])
def test_prepare_refuses_unreviewed_script_before_side_effects(provision_tree, name):
    root, bundle = provision_tree
    private_file(bundle / "code" / name, b"# substituted unreviewed source\n")
    result = prepare(root, bundle)
    value = receipt(result)
    assert result.returncode != 0, value
    assert value.get("blocked") is True or value.get("success") is False, value
    assert "checkpoint_unreadable_or_unsafe" not in value.get("blockers", []), value
    assert not (root / "wheelhouse").exists(), value
    assert not (root / "runtime-catalog.candidate.json").exists(), value


def receiver(root, stage, entries, manifest_digest):
    # The production receiver has a literal /scratch gate. AST-replace only
    # that path prefix; preserve all framing, digest and filesystem logic.
    tree = ast.parse(inference.REMOTE_INFERENCE_RECEIVER)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "/scratch/":
            node.value = str(root.parent) + "/"
    header = {"files": [{"name": n, "size": len(raw), "sha256": digest}
                         for n, raw, digest in entries],
              "manifest_sha256": manifest_digest}
    payload = json.dumps(header).encode() + b"\n" + b"".join(raw for _, raw, _ in entries)
    code = f"sys.argv = ['receiver', {str(root)!r}, {stage!r}]\n" + ast.unparse(tree)
    return isolated(root.parent, code, payload)


def test_receiver_rejects_caller_chosen_manifest_digest(tmp_path):
    raw = b'{"files":{},"schema":"attacker-controlled"}'
    result = receiver(tmp_path / "sources", TRANSFER, [("manifest.json", raw, sha(raw))], sha(raw))
    assert result.returncode != 0, "receiver trusted the sender's arbitrary manifest digest"
    assert not (tmp_path / "sources" / TRANSFER).exists()


def test_receiver_rejects_corrupt_payload_digest(tmp_path):
    raw = b"corrupt bytes"
    result = receiver(tmp_path / "sources", TRANSFER,
                      [("manifest.json", raw, "0" * 64)], inference.MANIFEST_SHA256)
    assert result.returncode != 0
    assert not (tmp_path / "sources" / TRANSFER).exists()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "code/../../escape",
                                 "code//hidden", "code/.hidden"])
def test_receiver_rejects_unsafe_payload_paths(tmp_path, name):
    raw = b"unsafe path payload"
    result = receiver(tmp_path / "sources", TRANSFER,
                      [(name, raw, sha(raw))], inference.MANIFEST_SHA256)
    assert result.returncode != 0
    assert not (tmp_path / "sources" / TRANSFER).exists()
    assert not (tmp_path / "escape").exists()




def test_receiver_rejects_caller_supplied_manifest_digest(tmp_path, reviewed_bundle):
    entries = [(name, (FROZEN / name).read_bytes(), digest)
               for name, digest in [("manifest.json", inference.MANIFEST_SHA256),
                                    *sorted(reviewed_bundle["files"].items())]]
    root = tmp_path / "sources"
    result = receiver(root, TRANSFER, entries, "e" * 64)
    assert result.returncode != 0
    assert not (root / TRANSFER).exists()

def test_receiver_real_reviewed_transfer_and_duplicate_refusal(tmp_path, reviewed_bundle):
    entries = [(name, (FROZEN / name).read_bytes(), digest)
               for name, digest in [("manifest.json", inference.MANIFEST_SHA256),
                                    *sorted(reviewed_bundle["files"].items())]]
    root = tmp_path / "sources"
    result = receiver(root, TRANSFER, entries, inference.MANIFEST_SHA256)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert receipt(result)["manifest_sha256"] == inference.MANIFEST_SHA256
    landed = root / TRANSFER
    before = {str(p.relative_to(landed)): (p.stat().st_ino, p.read_bytes())
              for p in landed.rglob("*") if p.is_file()}
    repeated = receiver(root, TRANSFER, entries, inference.MANIFEST_SHA256)
    assert repeated.returncode != 0
    assert receipt(repeated)["error"] == "destination_exists"
    assert {str(p.relative_to(landed)): (p.stat().st_ino, p.read_bytes())
            for p in landed.rglob("*") if p.is_file()} == before


def test_receiver_rejects_symlinked_landing_root(tmp_path):
    destination = tmp_path / "destination"
    destination.mkdir(mode=0o700)
    root = tmp_path / "sources"
    root.symlink_to(destination, target_is_directory=True)
    raw = b"{}"
    result = receiver(root, TRANSFER, [("manifest.json", raw, sha(raw))], inference.MANIFEST_SHA256)
    assert result.returncode != 0
    assert list(destination.iterdir()) == []


def test_receiver_rejects_oversized_header_before_creating_landing(tmp_path):
    """Run the real frozen receiver's bounded line framing in isolation."""
    tree = ast.parse(inference.REMOTE_INFERENCE_RECEIVER)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "/scratch/":
            node.value = str(tmp_path) + "/"
    root = tmp_path / "sources"
    script = (f"sys.argv = ['receiver', {str(root)!r}, {TRANSFER!r}]\n"
              + ast.unparse(tree))
    oversized_header = b" " * (262144 + 1) + b"\n"
    result = isolated(tmp_path, script, oversized_header)
    assert result.returncode == 64, result.stderr.decode(errors="replace")
    assert not (root / TRANSFER).exists()


def test_prepare_never_writes_an_unreviewed_runtime_catalog(provision_tree):
    root, bundle = provision_tree
    first = prepare(root, bundle)
    value = receipt(first)
    assert value["reason"] == "runtime_catalog_candidate_awaits_independent_human_review"
    candidate_sha = sha((root / "runtime-catalog.candidate.json").read_bytes())
    assert not (root / "runtime-catalog.json").exists()
    # Matching the candidate hash in configuration is NOT authority to create
    # its reviewed catalog bytes. The human still has to place them explicitly.
    second = prepare(root, bundle, digest=candidate_sha)
    declined = receipt(second)
    assert second.returncode == 3, (declined, second.stderr.decode())
    assert any(v.startswith("configured_catalog_bytes_missing")
               for v in declined["blockers"])
    assert not (root / "runtime-catalog.json").exists()
    assert not (root / "inference-env").exists()


def test_prepare_refuses_mutated_script_at_immediate_exec_recheck(tmp_path):
    """Execute the actual final digest decision, not a mock receipt."""
    main = next(node for node in ast.parse(inference.REMOTE_PROVISION_PREPARE).body
                if isinstance(node, ast.FunctionDef) and node.name == "main")
    branch = next(node for node in ast.walk(main)
                   if isinstance(node, ast.If)
                   and contains(node, "reviewed_script_changed_before_execution"))
    source = (inference.REMOTE_PROVISION_COMMON
              + '\nscript_sha = "0" * 64\n'
              + 'preflight_sha = PINNED_BUNDLE_SCRIPTS["runtime_preflight.py"]\n'
              + ast.unparse(branch)
              + '\nraise AssertionError("tampered script accepted")')
    result = isolated(tmp_path, source)
    value = receipt(result)
    assert result.returncode == 65, (value, result.stderr.decode())
    assert value["error"] == "reviewed_script_changed_before_execution"
    assert value["environment_provisioned"] is False


@pytest.mark.parametrize("mutated_path", ["source", "staged"])
def test_prepare_driver_executes_verified_bytes_despite_path_mutation(tmp_path, mutated_path):
    tree = ast.parse(inference.REMOTE_PROVISION_PREPARE)
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    stage_block = next(
        node for node in main.body if isinstance(node, ast.Try)
        and any(isinstance(child, ast.Name) and child.id == "verified_runtime_files"
                for child in ast.walk(node))
    )

    code_root = tmp_path / "code"
    code_root.mkdir(mode=0o700)
    provisional = {
        "prepare_runtime.sh": b'SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)\n'
                              b'test -f "$SCRIPT_ROOT/runtime_preflight.py"\n'
                              b'test -f "$SCRIPT_ROOT/../sources/laya_provenance.py"\n'
                              b'printf verified > "$1"\n',
        "runtime_preflight.py": b"pass\n",
        "handoff.py": b"pass\n",
        "offline_runner.py": b"pass\n",
        "requirements-inference.lock": b"pass\n",
    }
    pins = {}
    for name, data in provisional.items():
        private_file(code_root / name, data)
        pins[name] = sha(data)
    sources = {"laya_provenance.py": b"pass\n"}
    source_pins = {name: sha(data) for name, data in sources.items()}
    for name, data in sources.items():
        private_file(tmp_path / "sources" / name, data)
    provision_cache = tmp_path / "provision-cache"
    (provision_cache / "tmp").mkdir(parents=True, mode=0o700)
    output_path = tmp_path / "executed.txt"
    real_subprocess = subprocess
    source_script = code_root / "prepare_runtime.sh"

    def mutate_original_then_run(argv, **kwargs):
        assert argv[1].startswith("/proc/self/fd/"), argv
        fd, = kwargs["pass_fds"]
        assert argv[1] == f"/proc/self/fd/{fd}"
        # The inherited descriptor is sealed against writes and truncation.
        with pytest.raises(OSError):
            os.write(fd, b"altered")
        with pytest.raises(OSError):
            os.ftruncate(fd, 0)
        staged_script, = (provision_cache / "tmp").glob("*/code/prepare_runtime.sh")
        changed = source_script if mutated_path == "source" else staged_script
        changed.chmod(0o600)
        changed.write_bytes(b'printf altered > "$1"\n')
        return real_subprocess.run(argv, **kwargs)

    helpers = {}
    exec(inference.REMOTE_PROVISION_COMMON, helpers)
    namespace = {
        "sealed_runtime_script": helpers["sealed_runtime_script"],
        "os": os,
        "hashlib": hashlib,
        "stat": __import__("stat"),
        "subprocess": type("SubprocessProxy", (), {
            "run": staticmethod(mutate_original_then_run),
            "PIPE": subprocess.PIPE,
            "DEVNULL": subprocess.DEVNULL,
            "TimeoutExpired": subprocess.TimeoutExpired,
        }),
        "OFFLINE_ENV": {"PATH": "/usr/bin:/bin"},
        "provision_cache": str(provision_cache),
        "scratch": str(output_path),
        "bootstrap": "/usr/bin/python3",
        "wheelhouse": str(tmp_path / "wheelhouse"),
        "cache": str(tmp_path / "cache"),
        "catalog": str(tmp_path / "catalog.json"),
        "catalog_digest": "none",
        "code_root": str(code_root),
        "bundle": str(tmp_path),
        "PINNED_BUNDLE_SCRIPTS": pins,
        "PINNED_BUNDLE_SOURCES": source_pins,
        "read_pinned_bytes": lambda path, digest, bound: (
            (lambda data: data if len(data) <= bound and sha(data) == digest
             else (_ for _ in ()).throw(ValueError("digest mismatch")))(Path(path).read_bytes())
        ),
        "emit": lambda *args: (_ for _ in ()).throw(AssertionError(args)),
    }
    exec(compile(ast.Module(body=[stage_block], type_ignores=[]),
                 "<prepare-driver-test>", "exec"), namespace)
    assert namespace["prepared"].returncode == 0
    assert output_path.read_text() == "verified"
    if mutated_path == "source":
        assert source_script.read_bytes() == b'printf altered > "$1"\n'
    else:
        assert source_script.read_bytes() == provisional["prepare_runtime.sh"]
    assert list((provision_cache / "tmp").iterdir()) == []


@pytest.mark.parametrize("target_kind", ["model_cache", "wheelhouse"])
def test_secure_makedirs_rejects_symlinked_ancestor_before_leaf_creation(tmp_path, target_kind):
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    if target_kind == "model_cache":
        cache = scratch / "model-cache"
        cache.mkdir(mode=0o700)
        link = cache / "models--convaiinnovations--laya"
        target = link / "snapshots" / inference.REVISION
    else:
        link = scratch / "wheelhouse"
        target = link / "nested-leaf"
    link.symlink_to(outside, target_is_directory=True)
    code = inference.REMOTE_PROVISION_COMMON + f'''\ntry:
 secure_makedirs({str(target)!r})
except OSError:
 print("rejected")
else:
 raise AssertionError("symlinked path ancestor was accepted")
'''
    result = isolated(tmp_path, code)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.decode().strip() == "rejected"
    assert list(outside.iterdir()) == []
    assert not target.exists()


@pytest.mark.parametrize("kind", ["wheelhouse", "model-cache"])
@pytest.mark.parametrize("timing", ["ancestor_open", "leaf_open"])
@pytest.mark.parametrize("existing", [False, True])
def test_copy_destination_ancestor_swap_never_writes_outside(tmp_path, kind, timing, existing):
    source = private_file(tmp_path / "source", b"verified source")
    parent = tmp_path / kind / "nested"
    parent.mkdir(parents=True, mode=0o700)
    parent.parent.chmod(0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    target = parent / "artifact"
    if existing:
        private_file(target, source.read_bytes())
    code = inference.REMOTE_PROVISION_COMMON + f'''
source, target = {str(source)!r}, {str(target)!r}
parent, outside = {str(parent)!r}, {str(outside)!r}
real_open = os.open
swapped = False
def racing_open(path, flags, *args, **kwargs):
    global swapped
    trigger = "nested" if {timing!r} == "ancestor_open" else "artifact"
    if not swapped and path == trigger and kwargs.get("dir_fd") is not None:
        swapped = True
        os.rename(parent, parent + "-original")
        os.symlink(outside, parent)
    return real_open(path, flags, *args, **kwargs)
os.open = racing_open
try:
    result = copy_regular_file(source, target, 1024)
except (OSError, ValueError):
    if {timing!r} != "ancestor_open":
        raise
else:
    assert {timing!r} == "leaf_open"
    assert result == (hashlib.sha256(b"verified source").hexdigest(), 15)
assert swapped
assert os.listdir(outside) == []
print('{{"outside_untouched":true}}')
'''
    result = isolated(tmp_path, code)
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == {"outside_untouched": True}
    assert list(outside.iterdir()) == []
    if timing == "leaf_open":
        assert (parent.with_name("nested-original") / "artifact").read_bytes() == source.read_bytes()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "public"])
def test_copy_existing_destination_refuses_unsafe_inode(tmp_path, kind):
    source = private_file(tmp_path / "source")
    outside = private_file(tmp_path / "outside", b"outside unchanged")
    target = tmp_path / "target"
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, target)
    elif kind == "fifo":
        os.mkfifo(target, 0o600)
    else:
        private_file(target, source.read_bytes()).chmod(0o644)
    result = isolated(tmp_path, inference.REMOTE_PROVISION_COMMON + f'''
try:
    copy_regular_file({str(source)!r}, {str(target)!r}, 1024)
except (OSError, ValueError):
    print('{{"refused":true}}')
else:
    raise AssertionError("unsafe destination accepted")
''')
    assert result.returncode == 0, result.stderr.decode()
    assert receipt(result) == {"refused": True}
    assert outside.read_bytes() == b"outside unchanged"


@pytest.mark.parametrize("wheel_state", ["empty", "other_wheel", "valid_laya"])
def test_inspect_actual_driver_blocks_missing_laya_wheel(provision_tree, wheel_state):
    root, _ = provision_tree
    wheelhouse = root / "runs" / RUN / "wheelhouse"
    wheel = wheelhouse / "laya-0.3.28-py3-none-any.whl"
    if wheel_state != "valid_laya":
        wheel.unlink()
    if wheel_state == "other_wheel":
        private_file(wheelhouse / "unrelated-1.0-py3-none-any.whl", b"other wheel")
    setup = f'''
SCRATCH_RE = re.compile(re.escape({str(root)!r}) + r"(?:/[A-Za-z0-9_./-]+)?\\Z")
CHECKPOINT_SHA256 = {sha(b"tiny model")!r}
WEIGHTS_BYTES = {len(b"tiny model")}
LAYA_WHEEL_SHA256 = {sha(b"tiny wheel")!r}
LAYA_WHEEL_BYTES = {len(b"tiny wheel")}
subprocess.run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"3.12.9\\n", b"")
sys.argv = ["inspect", "inspect", "/usr/bin/python3", {str(root)!r},
            {str(root / "model-cache")!r}, {RUN!r}]
'''
    result = isolated(root.parent, inference.REMOTE_PROVISION_COMMON + setup
                      + inference.REMOTE_PROVISION_INSPECT[len(inference.REMOTE_PROVISION_COMMON):])
    value = receipt(result)
    assert result.returncode == 0, (value, result.stderr.decode())
    assert value["laya_wheel_present"] is (wheel_state == "valid_laya")
    assert value["blocked"] is (wheel_state != "valid_laya"), value
    assert ("laya_wheel_missing_from_previous_wheelhouse" in value["blockers"]) is (
        wheel_state != "valid_laya")


def test_sealed_wrapper_changes_only_reviewed_root_assignment(reviewed_bundle, tmp_path):
    namespace = {}
    exec(inference.REMOTE_PROVISION_COMMON, namespace)
    original = (FROZEN / "code/prepare_runtime.sh").read_bytes()
    # A quoted root must remain a literal shell value.
    script_root = str(tmp_path / "private ' stage" / "code")
    fd = namespace["sealed_runtime_script"](original, script_root)
    try:
        import shlex
        actual = os.read(fd, len(original) + 4096)
        root_line = b'SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)'
        assert actual == original.replace(root_line, ("SCRIPT_ROOT=" + shlex.quote(script_root)).encode(), 1)
        result = subprocess.run(["/bin/bash", "-n", f"/proc/self/fd/{fd}"],
                                pass_fds=(fd,), capture_output=True, check=False)
        assert result.returncode == 0, result.stderr
        assert sha(original) == reviewed_bundle["files"]["code/prepare_runtime.sh"]
    finally:
        os.close(fd)
    with pytest.raises(ValueError, match="SCRIPT_ROOT"):
        namespace["sealed_runtime_script"](original.replace(root_line, b"# changed"), script_root)
