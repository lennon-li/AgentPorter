"""Standalone security checks; no root, credentials or service changes."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

source_file = Path(__file__).resolve().parents[1] / "scripts/provision-development-runtime.py"
spec = importlib.util.spec_from_file_location("shared_tools_provision", source_file)
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


def fixture(root: Path):
    for name in (
        "AgentSystem/agent-memory/skills/INDEX.md",
        "AgentSystem/agent-memory/skills/sample.md",
        "AgentSystem/agent-memory/boot/AGENT_STARTUP_PROTOCOL.md",
        "tools/agent-tool-policy.json",
        "tools/AGENT_TOOL_HANDOFF.md",
        "Toolbox/claude-skills/sample/SKILL.md",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("sample")
    for folder in ("AgentSystem/agent-memory/policies",
                   "AgentSystem/agent-memory/loaders"):
        (root / folder).mkdir(parents=True)
    policy = {"tools": {"required": [f"fixture-tool-{i}" for i in range(38)]}}
    (root / "tools/agent-tool-policy.json").write_text(json.dumps(policy))
    # These are explicitly shareable synthetic catalogue fixtures. Do not let
    # the operator's private umask turn the positive fixture into a private tree.
    for path in root.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)


with tempfile.TemporaryDirectory() as root_name:
    root = Path(root_name)
    source = root / "source"
    fixture(source)
    one, two = root / "snapshot-1", root / "snapshot-2"
    a = provision.stage_shared_obsidian(source, one)
    b = provision.stage_shared_obsidian(source, two)
    assert a["files"] == b["files"] == 6
    assert a["hashes"] == b["hashes"]
    assert (one / "Toolbox/claude-skills/sample/SKILL.md").read_text() == "sample"
    assert not (one / "tools/install-agent-tools.sh").exists()
    assert not ((one / "AgentSystem/agent-memory/skills/INDEX.md").stat().st_mode & 0o222)
    print("PASS: bounded, repeatable Obsidian skills and policies data snapshot")
    policy = one / "tools/agent-tool-policy.json"
    tools = provision.stage_standalone_tools(policy, root / "toolkit")
    assert tools["required"] == 38
    assert len(tools["not_bundled"]) == 38
    assert not tools["bundled_elf"]
    print("PASS: missing executables not advertised as available")
    forbidden = source / "AgentSystem/agent-memory/skills" / "unsafe.md"
    forbidden.symlink_to("/etc/passwd")
    try:
        provision.stage_shared_obsidian(source, root / "unsafe")
    except ValueError:
        print("PASS: external symlink payload rejected")
    else:
        raise AssertionError("Unsafe symlink was accepted")
    forbidden.unlink()
    (source / "AgentSystem/agent-memory/skills/fake.pyc").write_bytes(b"evil")
    result = provision.stage_shared_obsidian(source, root / "clean")
    assert result["files"] == 6
    print("PASS: compiled code excluded from shared skills data")
# Validate the actual bwrap launch topology without executing a model/host job.
import sys
import types
import importlib
src = Path(__file__).resolve().parents[1] / "src" / "agentporter"
for package, directory in (("agentporter", src),
                           ("agentporter.agents", src / "agents")):
    module = types.ModuleType(package)
    module.__path__ = [str(directory)]
    sys.modules[package] = module
DevelopmentRuntime = importlib.import_module("agentporter.agents.development").DevelopmentRuntime
with tempfile.TemporaryDirectory() as basedir:
    base = Path(basedir)
    workspace = base / "project"
    workspace.mkdir()
    (workspace / "README.md").write_text("test")
    auth = base / "synthetic-auth.json"
    auth.write_text("{}")
    auth.chmod(0o600)
    docs = base / "trusted-synthetic-docs"
    docs.mkdir()
    toolkit = base / "trusted-synthetic-tools"
    toolkit.mkdir()
    runtime = DevelopmentRuntime(base / "config", base / "state", None)
    # Positive topology uses synthetic paths only. The production validator is
    # independently tested to reject such non-root-owned source locations.
    runtime._shared_obsidian_source = lambda config: docs
    runtime._shared_toolkit_source = lambda config: toolkit
    interpreter = str(Path("/usr/bin/python3").resolve())
    spec = {"executable": interpreter,
            "credentials": {".codex/auth.json": str(auth)}}
    launcher = runtime._build("jax", {"network_enabled": False}, spec, workspace,
                              False, [interpreter, "--version"])
    try:
        command = launcher.command
        assert "--unshare-all" in command
        assert "--clearenv" in command
        assert "HOME=/home/yeli" not in str(command)
        for path in ("/opt/agentporter/shared/obsidian",
                     "/opt/agentporter/tools"):
            assert path in command
            assert command[max(i for i, value in enumerate(command) if value == path) - 2] == "--ro-bind"
        assert any("/opt/agentporter/tools/bin" in item for item in command)
        assert "/workspace" in command
    finally:
        launcher.cleanup()
# A writable temp directory cannot masquerade as a trusted release source.
    for validator, configuration in (
        (DevelopmentRuntime._shared_obsidian_source, {"shared_obsidian": str(docs)}),
        (lambda config: DevelopmentRuntime._shared_toolkit_source(runtime, config), {"shared_toolkit": str(toolkit)}),
    ):
        try:
            validator(configuration)
        except PermissionError:
            pass
        else:
            raise AssertionError("Mutable workspace accepted as release asset")
print("PASS: release-source validation rejects mutable/untrusted paths")
print("PASS: shared resources mounted read-only inside the existing bwrap boundary")
print("PASS: shared agent resources offline security checks")
