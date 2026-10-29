"""Opt-in development worker runtime; every execution crosses a bwrap boundary.

This is deliberately separate from the offline generic sandbox.  Neither a
configuration flag nor a successful host CLI detection constitutes availability.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import tomllib
from typing import Callable

import yaml

from agentporter.agents.isolated_codex import _clean_profile_data
from agentporter.agents.roster import PUBLIC_AGENT_IDS


@dataclass
class PreparedLaunch:
    command: list[str]
    cleanup: Callable[[], None]
    pass_fds: tuple[int, ...] = ()


class DevelopmentRuntime:
    """Common launcher for explicitly configured, separately credentialed workers.

    ``development-runtime.yaml`` must name a separate ``gateway_user`` and the
    forbidden ``production_uid``.  Workers map credential destinations relative
    to their private HOME to explicit source files.  No host environment passes
    through this interface, including the broker's legacy CLI launch environment.
    """

    _MASK_DIRS = {".git", ".ssh", ".aws", ".codex", ".agents", ".development",
                  ".claude", ".copilot", ".copilot-phil", ".opencode", ".github-copilot",
                  ".antigravitycli", ".gemini", "runtime"}
    _CREDENTIAL_NAMES = {
        ".codex/auth.json", ".codex/config.toml", ".claude/.credentials.json",
        ".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
        ".copilot/config.json", ".local/share/opencode/auth.json",
        ".config/agy/auth.json", ".config/antigravity/auth.json", ".config/opencode/wei-key",
        ".copilot-phil/config.json", ".antigravitycli/auth.json",
        ".gemini/antigravity-cli/antigravity-oauth-token",
    }
    _GO_MODEL = "opencode-go/glm-5.3-flash"
    _GO_BASE_URL = "https://opencode.ai/inference/go/openai/v1"
    _RELEASES = Path("/opt/agentporter-development/versions")

    def __init__(self, config_dir: Path, state_dir: Path, workspace_registry):
        self.config_dir = Path(config_dir).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.workspace_registry = workspace_registry
        self._cache: dict[str, tuple[float, str]] = {}
        self._evidence: dict[str, dict] = {}
        self._probe_lock = threading.Lock()
        self._toolkit_lock = threading.Lock()
        self._toolkit_cache: tuple | None = None

    def _config(self) -> dict:
        try:
            value = yaml.safe_load((self.config_dir / "development-runtime.yaml").read_text())
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise PermissionError("development runtime configuration unavailable") from exc
        if not isinstance(value, dict) or value.get("enabled") is not True or value.get("profile") != "development":
            raise PermissionError("development runtime is not explicitly enabled")
        production_uid = value.get("production_uid")
        if isinstance(production_uid, bool) or not isinstance(production_uid, int) or production_uid < 0:
            raise PermissionError("development runtime requires an explicit production_uid")
        user = value.get("gateway_user")
        if not isinstance(user, str) or not user:
            raise PermissionError("development runtime requires a separate gateway_user")
        try:
            account = pwd.getpwnam(user)
        except KeyError as exc:
            raise PermissionError(f"development gateway account does not exist: {user}") from exc
        if account.pw_uid == production_uid or os.getuid() == production_uid:
            raise PermissionError("development workers cannot run as the production UID")
        if os.getuid() != account.pw_uid or os.geteuid() != account.pw_uid:
            raise PermissionError(f"development gateway must run as configured account: {user}")
        if account.pw_uid == 0:
            raise PermissionError("development workers cannot run as root")
        self._allowed_workspace_roots(value)
        self._sandbox_executable(value)
        # A worker must never be able to rewrite code or configuration that a
        # later gateway launch imports outside confinement. Editable checkout
        # installs are unsuitable when that checkout is a writable workspace.
        trusted_paths = {
            "launcher source": Path(__file__).resolve().parents[1],
            "runtime configuration": self.config_dir,
            "runtime state": self.state_dir,
        }
        for entry in self.workspace_registry.list_all():
            if not entry.get("writable") or not entry.get("permissions", {}).get("agent_dispatch"):
                continue
            workspace = Path(entry["path"]).resolve()
            for description, target in trusted_paths.items():
                if target == workspace or target.is_relative_to(workspace):
                    raise PermissionError(f"{description} overlaps a worker-writable workspace; install the development gateway outside authorized workspaces")
        return value

    @staticmethod
    def _sandbox_executable(config: dict) -> str:
        """Only operator-installed sandboxes outside worker-writable roots."""
        name = config.get('sandbox_executable', '/usr/bin/bwrap')
        if not isinstance(name, str) or name not in {'/usr/bin/bwrap', '/opt/agentporter-bcc/bin/bwrap'}:
            raise PermissionError('Unapproved OS confinement executable')
        path = Path(name)
        for parent in reversed(path.parents):
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                raise PermissionError('Sandbox ancestors require immutable root ownership')
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o6022 or not os.access(path, os.X_OK)):
            raise PermissionError('Sandbox executable requires immutable root ownership')
        return name

    @staticmethod
    def _regular(path: Path, *, credential: bool = False) -> Path:
        if not path.is_absolute() or path.is_symlink():
            raise PermissionError("worker file must be an absolute, non-symlink path")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError(f"worker file is not regular: {resolved.name}")
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise PermissionError(f"worker file requires trusted ownership/mode: {resolved.name}")
        if credential and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise PermissionError(f"worker credential requires private ownership/mode: {resolved.name}")
        return resolved

    def _spec(self, agent: str, config: dict) -> dict:
        if agent not in PUBLIC_AGENT_IDS:
            raise PermissionError(f"unknown named development worker: {agent}")
        workers = config.get("workers", {})
        spec = workers.get(agent) if isinstance(workers, dict) else None
        if not isinstance(spec, dict):
            raise PermissionError(f"development worker is not configured: {agent}")
        executable = spec.get("executable")
        if not isinstance(executable, str) or not executable:
            raise PermissionError(f"development executable is not configured: {agent}")
        # Installed CLI entry points are commonly symlinks. Only the resolved
        # executable is mounted; the containing host home is never exposed.
        exe = Path(executable)
        if not exe.is_absolute() or not exe.is_file() or not os.access(exe, os.X_OK):
            raise PermissionError(f"development worker executable unavailable: {agent}")
        executable = str(exe.resolve(strict=True))
        code_mode_host = spec.get("code_mode_host")
        if agent in {"jax", "liz", "prof"} and not code_mode_host:
            raise PermissionError(f"bundled Codex code-mode helper is not configured: {agent}")
        if code_mode_host is not None:
            helper = Path(code_mode_host)
            if not helper.is_absolute() or helper.is_symlink() or not helper.is_file():
                raise PermissionError("Codex code-mode helper requires an absolute regular non-symlink file")
            helper = helper.resolve(strict=True)
            metadata = helper.stat()
            if metadata.st_uid not in {0, os.getuid()} or metadata.st_mode & 0o022 or not os.access(helper, os.X_OK):
                raise PermissionError("Codex code-mode helper requires trusted executable ownership/mode")
            with helper.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    raise PermissionError("Codex code-mode helper must be a bundled native executable")
            if Path(executable).name == "codex" and helper.parent != Path(executable).parent:
                raise PermissionError("Codex code-mode helper must be installed beside the matching Codex executable")
            code_mode_host = str(helper)
        credentials = spec.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise PermissionError(f"separate development worker credentials unavailable: {agent}")
        canonical_credentials = {}
        for target, source in credentials.items():
            if target not in self._CREDENTIAL_NAMES or not isinstance(source, str):
                raise PermissionError(f"unsupported development credential destination: {target}")
            canonical_credentials[target] = str(self._regular(Path(source), credential=target != ".codex/config.toml"))
        codex_config = None
        if spec.get("codex_config") is not None:
            codex_config = str(self._regular(Path(spec["codex_config"])))
            if Path(codex_config).name != "config.toml":
                raise PermissionError("screened Codex configuration must be named config.toml")
        for entry in self.workspace_registry.list_all():
            registered = Path(entry["path"]).resolve()
            for source in [executable, *canonical_credentials.values(), *([codex_config] if codex_config else []),
                           *([code_mode_host] if code_mode_host else [])]:
                if Path(source) == registered or Path(source).is_relative_to(registered):
                    raise PermissionError("worker executable and credentials must be outside registered development workspaces")
        # Each identity has an independently provisioned authentication file.
        others = config.get("workers", {})
        def identity(source):
            info = Path(source).stat()
            return info.st_dev, info.st_ino

        own_auth = {identity(source) for target, source in credentials.items()
                    if target != ".codex/config.toml"}
        if not own_auth:
            raise PermissionError(f"separate development worker authentication unavailable: {agent}")
        for name, other in others.items():
            if name != agent and isinstance(other, dict):
                auth = other.get("credentials", {})
                # Missing credentials for another identity must not hide this
                # worker's individual availability. Existing hardlink aliases
                # still count as the same authentication material.
                other_auth = set()
                if isinstance(auth, dict):
                    for target, source in auth.items():
                        if target != ".codex/config.toml" and isinstance(source, str) and Path(source).is_file():
                            other_auth.add(identity(source))
                if own_auth.intersection(other_auth):
                    raise PermissionError(f"development worker credentials are shared: {agent}/{name}")
        if not isinstance(spec.get("runtime_mounts", []), list):
            raise PermissionError("runtime_mounts must be a list of installed code mounts")
        if ".config/opencode/wei-key" in canonical_credentials:
            self._opencode_route(spec)
        result = {**spec, "executable": executable, "credentials": canonical_credentials}
        if code_mode_host:
            result["code_mode_host"] = code_mode_host
        if codex_config:
            result["codex_config"] = codex_config
        if ".gemini/antigravity-cli/antigravity-oauth-token" in canonical_credentials and "model" in spec:
            model = spec["model"]
            if not isinstance(model, str) or not model.strip() or len(model) > 160 or any(ord(char) < 32 or ord(char) == 127 for char in model):
                raise PermissionError("Argie selected model must be a bounded printable model name")
        if agent in {'jax', 'liz', 'prof'}:
            profile = codex_config or canonical_credentials.get('.codex/config.toml')
            if profile:
                # This is the same screened configuration mounted by _build.
                # Advisory YAML metadata must never hide its actual default.
                text, _ = _clean_profile_data(Path(profile).parent)
                canonical = tomllib.loads(text)
                for field, key in [('model', 'model'), ('reasoning_effort', 'model_reasoning_effort')]:
                    value = canonical.get(key, 'unknown')
                    if (not isinstance(value, str) or not value.strip() or len(value) > 160
                            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                        raise PermissionError('Invalid canonical Codex routing metadata')
                    result[field] = value
                result['provider'] = 'OpenAI'
        return result

    @classmethod
    def _opencode_route(cls, spec: dict) -> tuple[str, str]:
        """An independently provisioned key authorizes one explicit route."""
        provider, model = spec.get("provider"), spec.get("model")
        if provider == "opencode-go" and model == cls._GO_MODEL:
            return provider, model
        if provider == "opencode" and isinstance(model, str) and model.startswith("opencode/") and model.endswith("-free"):
            return provider, model
        raise PermissionError("OpenCode key requires an explicit supported provider/model route; no fallback is allowed")

    @staticmethod
    def _pin_opencode_model(worker: list[str], model: str) -> list[str]:
        if len(worker) < 2 or worker[1] != "run":
            raise PermissionError("confined OpenCode profile supports only the run subcommand")
        requested = []
        arguments = iter(worker[2:])
        for argument in arguments:
            if argument == "--":
                break
            if argument in {"-m", "--model"}:
                requested.append(next(arguments, ""))
            elif argument.startswith("--model="):
                requested.append(argument.partition("=")[2])
            elif argument.startswith("-m") and len(argument) > 2:
                requested.append(argument[2:])
        if any(value != model for value in requested):
            raise PermissionError("requested OpenCode model differs from the provisioned credential route")
        return worker if requested else [*worker[:2], "--model", model, *worker[2:]]

    @staticmethod
    def _allowed_workspace_roots(config: dict) -> dict[Path, bool]:
        rows = config.get("allowed_workspace_roots")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
            raise PermissionError("Explicit development workspace allowlist is required")
        allowed = {}
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"path", "writable"}
                    or not isinstance(row["path"], str) or not isinstance(row["writable"], bool)):
                raise PermissionError("Malformed development workspace allowlist")
            path = Path(row["path"])
            if (not path.is_absolute() or not path.is_dir()
                    or str(path) != row["path"] or path.resolve(strict=True) != path
                    or path in allowed):
                raise PermissionError("Development workspace allowlist requires unique canonical directories")
            allowed[path] = row["writable"]
        return allowed

    def _workspace(self, workspace_path: str, writable: bool, config: dict) -> Path:
        path = Path(workspace_path).resolve(strict=True)
        if not path.is_dir():
            raise PermissionError("development workspace must be a directory")
        allowed = self._allowed_workspace_roots(config)
        if path not in allowed:
            raise PermissionError("workspace is outside the operator development allowlist")
        entries = self.workspace_registry.list_all()
        entry = next((item for item in entries if Path(item["path"]).resolve() == path), None)
        permissions = entry.get("permissions", {}) if entry else {}
        if not entry or not permissions.get("agent_dispatch") or not permissions.get("execute"):
            raise PermissionError("workspace is not authorized for development delegation")
        if writable and (not entry.get("writable") or not allowed[path]):
            raise PermissionError("workspace is authorized only for read-only delegation")
        # A registered host root is still too broad. Config/state/credential
        # parents must never become workspace mounts, even for read-only jobs.
        if path in {Path("/"), Path("/home"), Path("/tmp"), Path("/var"), Path("/usr"), Path("/opt"), Path.home()}:
            raise PermissionError("broad parent directories cannot be development workspaces")
        descendants = [other for other in allowed if other != path and other.is_relative_to(path)]
        # Nested project registrations may share a read-only mount only when
        # the operator has denied writes for the entire approved subtree.
        # Keep checking all descendants, including grandchildren: admitting a
        # writable leaf through a read-only parent would bypass that boundary.
        if descendants and (writable or allowed[path] or any(allowed[other] for other in descendants)):
            raise PermissionError("workspace is a broad parent of another approved workspace")
        protected = [self.config_dir, self.state_dir]
        for worker in config.get("workers", {}).values():
            if isinstance(worker, dict) and isinstance(worker.get("credentials"), dict):
                protected.extend(Path(p).resolve() for p in worker["credentials"].values() if isinstance(p, str))
                if isinstance(worker.get("codex_config"), str):
                    protected.append(Path(worker["codex_config"]).resolve())
        if any(item == path or path in item.parents for item in protected):
            raise PermissionError("workspace contains runtime configuration, state, or worker credentials")
        return path

    @staticmethod
    def _pin(path: Path, descriptors: list[int], root_fd: int | None = None) -> int:
        """Pin each component without following worker-controlled symlinks."""
        flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
        if root_fd is None:
            fd = os.open(path, flags | os.O_DIRECTORY)
            descriptors.append(fd)
            return fd
        current = root_fd
        for index, component in enumerate(path.parts):
            fd = os.open(component, flags, dir_fd=current)
            descriptors.append(fd)
            info = os.fstat(fd)
            if stat.S_ISLNK(info.st_mode) or (index < len(path.parts) - 1 and not stat.S_ISDIR(info.st_mode)):
                raise PermissionError("worker-controlled mount path changed to a symlink")
            current = fd
        return current

    @staticmethod
    def _secret_name(name: str) -> bool:
        return name.endswith(".env") or name == ".env" or name.startswith(".env.")

    def _masks(self, workspace: Path, writable: bool) -> list[tuple[Path, bool, bool, bool]]:
        masks: list[tuple[Path, bool, bool, bool]] = []
        real_root = workspace.resolve(strict=True)
        def failed(error):
            # An unreadable descendant stays inaccessible inside a read-only
            # worker. Never hide a failed root scan, a symlink error or another
            # I/O failure, and never relax a writable workspace's metadata scan.
            if not writable and isinstance(error, PermissionError) and isinstance(error.filename, str):
                failed_path = Path(error.filename)
                try:
                    relative = failed_path.relative_to(workspace)
                except ValueError:
                    pass
                else:
                    if (failed_path.is_absolute() and str(failed_path) == error.filename
                            and relative.parts and not any(part in {'.', '..'} for part in relative.parts)):
                        masks.append((relative, True, False, True))
                        return
            raise PermissionError("cannot inspect development workspace metadata") from error

        for root, dirs, files in os.walk(workspace, followlinks=False, onerror=failed):
            current = Path(root)
            for name in list(dirs):
                source = current / name
                if name in self._MASK_DIRS or name.startswith(".codex-") or self._secret_name(name):
                    if source.is_symlink() and name == ".git":
                        raise PermissionError("symlinked Git metadata cannot be delegated")
                    masks.append((source.relative_to(workspace), True, name == ".git", False))
                    dirs.remove(name)
            for name in files:
                source = current / name
                if name in self._MASK_DIRS or self._secret_name(name):
                    if source.is_symlink() and name == ".git":
                        raise PermissionError("symlinked Git metadata cannot be delegated")
                    # Git worktree control files can point outside this root.
                    # Read-only workers inspect files without receiving that
                    # external control path or any of its configuration.
                    if name == ".git" and not writable:
                        masks.append((source.relative_to(workspace), False, False, False))
                        continue
                    masks.append((source.relative_to(workspace), False, name == ".git", False))
                    if name == ".git" and not source.is_symlink():
                        text = source.read_text()
                        if not text.startswith("gitdir: "):
                            raise PermissionError("invalid Git worktree control file")
                        target = (source.parent / text[8:].strip()).resolve()
                        if target == real_root or target in real_root.parents:
                            raise PermissionError("Git control directory cannot be a workspace ancestor")
                        if not target.is_relative_to(real_root) or not target.is_dir():
                            raise PermissionError("external Git worktree metadata is not authorized for delegation")
                        common = target / "commondir"
                        if common.is_file() and not (target / common.read_text().strip()).resolve().is_relative_to(real_root):
                            raise PermissionError("external Git worktree common directory is not authorized for delegation")
                        masks.append((target.relative_to(real_root), True, True, False))
                elif not source.is_symlink() and source.stat().st_nlink > 1:
                    raise PermissionError(f"workspace contains hardlinked file: {source.relative_to(workspace)}")
        return masks

    @staticmethod
    def _code_mount(mount: dict, executable: str) -> tuple[str, str]:
        if not isinstance(mount, dict) or set(mount) != {"source", "target"}:
            raise PermissionError("runtime mount requires only source and target")
        source, target = Path(mount["source"]), PurePosixPath(mount["target"])
        if not source.is_absolute() or not source.exists() or ".." in target.parts or not str(target).startswith("/opt/agentporter/runtime/"):
            raise PermissionError("runtime mount must target /opt/agentporter/runtime/ installed code")
        source = source.resolve(strict=True)
        # A standalone native interpreter is narrow. Directory mounts must
        # identify one installed package, never /opt, home, config, or runtime
        # state. Reject control/credential-looking descendants too.
        installed = False
        if source.is_file() and os.access(source, os.X_OK):
            with source.open("rb") as handle:
                magic = handle.read(4)
            installed = magic == b"\x7fELF" or magic.startswith(b"#!")
        if "node_modules" in source.parts:
            suffix = source.parts[source.parts.index("node_modules") + 1:]
            exact_package = bool(suffix and len(suffix) == (2 if suffix[0].startswith("@") else 1))
            installed = exact_package and source.is_dir() and Path(executable).is_relative_to(source)
        # Native CLI version stores may live beneath ~/.local/share. Require a
        # named tool and versions subdirectory, never that entire shared tree.
        installed = installed or any(f"/.local/share/{tool}/versions/" in str(source)
                                     for tool in ("claude", "opencode", "copilot", "agy"))
        if not installed:
            raise PermissionError("runtime mount source is not a narrow installed code path")
        if source.is_dir():
            forbidden = {".git", ".aws", ".ssh", ".codex", ".agents", "auth.json", "credentials.json", "development-runtime.yaml"}
            for root, dirs, files in os.walk(source, followlinks=False):
                if any(name in forbidden or name.startswith(".env") or name.endswith(".env") for name in dirs + files):
                    raise PermissionError("runtime installed code mount contains credential or control data")
        return str(source), str(target)

    @staticmethod
    def _shared_obsidian_source(config: dict) -> Path | None:
        """Only immutable, root-owned release snapshots may supply shared data."""
        value = config.get("shared_obsidian")
        if value is None:
            return None
        if not isinstance(value, str):
            raise PermissionError("Invalid shared Obsidian snapshot configuration")
        path = Path(value)
        expected_prefix = Path("/opt/agentporter-development/versions")
        if not path.is_absolute() or path.name != "obsidian" or path.parent.name != "shared":
            raise PermissionError("Shared Obsidian data must be a named release snapshot")
        if not path.is_relative_to(expected_prefix) or len(path.relative_to(expected_prefix).parts) != 3:
            raise PermissionError("Shared Obsidian snapshot must be inside the installed release")
        # Reject symlinked components, writable ancestors and mutable data.
        for item in (path, *path.parents):
            meta = item.lstat()
            if stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise PermissionError("Shared Obsidian path must be root-owned and immutable")
        for rel in ("AgentSystem/agent-memory/skills/INDEX.md",
                    "AgentSystem/agent-memory/boot/AGENT_STARTUP_PROTOCOL.md",
                    "tools/agent-tool-policy.json", "tools/AGENT_TOOL_HANDOFF.md"):
            file = path / rel
            meta = file.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise PermissionError("Shared Obsidian resource is not immutable")
        return path

    @staticmethod
    def _resource_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _toolkit_snapshot(self, path: Path, config: dict):
        """Cheap cache identity; only root-managed read-only releases qualify.

        Root publishes a new unique version for every update. A privileged
        in-place deep edit without a manifest revision violates that contract;
        hostile workers cannot modify these nodes or their ancestors.
        """
        immutable = bool(re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z", path.parents[1].name))
        identities = []
        for item in (path, *path.parents):
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError("Shared tools must be root-owned and immutable")
            identities.append((str(item), self._resource_identity(info)))
            if item == path.parents[1] or item.is_relative_to(path.parents[1]):
                immutable &= not bool(info.st_mode & 0o222)
        for name in ("bin", "packages"):
            item = path / name
            try:
                info = item.lstat()
            except FileNotFoundError:
                if name == "packages":
                    identities.append((str(item), None))
                    continue
                raise
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError("Shared tool directory is untrusted")
            immutable &= not bool(info.st_mode & 0o222)
            identities.append((str(item), self._resource_identity(info)))
        fd = os.open(path / "manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_mode & 0o022 or before.st_size > 32 * 1024 * 1024):
                raise PermissionError("Tool manifest must be trusted and bounded")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                payload = stream.read(32 * 1024 * 1024 + 1)
            after = os.fstat(fd)
            if (len(payload) != before.st_size or
                    self._resource_identity(before) != self._resource_identity(after)):
                raise PermissionError("Tool manifest changed during validation")
        finally:
            os.close(fd)
        immutable &= not bool(before.st_mode & 0o222)
        config_path = self.config_dir / "development-runtime.yaml"
        config_identity = self._resource_identity(config_path.lstat())
        config_digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        token = (tuple(identities), self._resource_identity(before),
                 hashlib.sha256(payload).hexdigest(), config_identity, config_digest)
        return token, payload, immutable

    def _shared_toolkit_source(self, config: dict) -> Path | None:
        """Require checksum-matched ELF-only tools in a root-owned release."""
        value = config.get("shared_toolkit")
        if value is None:
            with self._toolkit_lock:
                self._toolkit_cache = None
            return None
        if not isinstance(value, str):
            raise PermissionError("Invalid shared tool release configuration")
        path = Path(value)
        prefix = self._RELEASES
        if (not path.is_absolute() or path.name != "toolkit"
                or path.parent.name != "shared"
                or not path.is_relative_to(prefix)
                or len(path.relative_to(prefix).parts) != 3):
            raise PermissionError("Shared tools must be part of the approved release")
        with self._toolkit_lock:
            token, payload, immutable = self._toolkit_snapshot(path, config)
            if immutable and self._toolkit_cache == token:
                return path
            self._toolkit_cache = None
            tree_immutable = self._validate_toolkit_contents(path, json.loads(payload))
            after_token, _, after_immutable = self._toolkit_snapshot(path, config)
            if after_token != token:
                raise PermissionError("Shared tool release changed during validation")
            if immutable and after_immutable and tree_immutable:
                self._toolkit_cache = token
        return path

    @staticmethod
    def _validate_toolkit_contents(path: Path, data: dict) -> bool:
        """Full first-use verification; report whether every node is read-only."""
        immutable = True
        if set(os.listdir(path)) - {"manifest.json", "bin", "packages"}:
            raise PermissionError("Unlisted shared toolkit resource")
        approved = data.get("bundled_elf")
        scripts = data.get("bundled_scripts", {})
        if (not isinstance(approved, dict) or len(approved) > 38
                or not isinstance(scripts, dict) or len(scripts) > 38):
            raise PermissionError("Malformed shared tool manifest")
        directory = path / "bin"
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Shared tool directory is untrusted")
        if set(os.listdir(directory)) != set(approved) | set(scripts):
            raise PermissionError("Unlisted executable in shared tool directory")
        for name, digest in {**approved, **scripts}.items():
            if (not isinstance(name, str) or not name or
                    not name.replace("-", "").isalnum()
                    or not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest)):
                raise PermissionError("Invalid shared tool manifest entry")
            target = directory / name
            info = target.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o6022 or not info.st_mode & 0o111):
                raise PermissionError("Shared tool is mutable, privileged or not executable")
            immutable &= not bool(info.st_mode & 0o222)
            with target.open("rb") as stream:
                payload = stream.read(128 * 1024 * 1024 + 1)
            signature_ok = (payload.startswith(b"\x7fELF") if name in approved
                            else name in scripts and
                            payload.startswith((b"#!/usr/bin/env bash\n", b"#!/bin/sh\n")) and len(payload) <= 8192)
            if (not signature_ok or len(payload) > 128 * 1024 * 1024
                    or hashlib.sha256(payload).hexdigest() != digest):
                raise PermissionError("Shared tool digest mismatch")
        packages = data.get("package_admissions", {})
        if not isinstance(packages, dict) or set(packages) - set(scripts):
            raise PermissionError("Invalid shared package declarations")
        package_root = path / "packages"
        if package_root.exists() or packages:
            if set(os.listdir(package_root)) != set(packages):
                raise PermissionError("Unlisted shared package")
        if packages:
            for package_name, admission in packages.items():
                expected = admission.get("files")
                if not isinstance(expected, dict) or len(expected) > 30000:
                    raise PermissionError("Invalid shared package manifest")
                base = package_root / package_name
                actual = set()
                for location, dirs, files in os.walk(base, followlinks=False):
                    for name in [".", *dirs, *files]:
                        item = Path(location) if name == "." else Path(location) / name
                        info = item.lstat()
                        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o6022):
                            raise PermissionError("Mutable shared package resource")
                        if not stat.S_ISLNK(info.st_mode):
                            immutable &= not bool(info.st_mode & 0o222)
                        if stat.S_ISDIR(info.st_mode):
                            continue
                        relative = str(item.relative_to(base))
                        actual.add(relative)
                        entry = expected.get(relative, {})
                        if stat.S_ISLNK(info.st_mode):
                            if not item.resolve(strict=True).is_relative_to(base) or entry != {"link": os.readlink(item)}:
                                raise PermissionError("Shared package symlink escapes or changed")
                        elif stat.S_ISREG(info.st_mode):
                            with item.open("rb") as stream:
                                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                            if entry != {"sha256": digest, "executable": bool(info.st_mode & 0o111)}:
                                raise PermissionError("Shared package digest mismatch")
                        else:
                            raise PermissionError("Special shared package file")
                if actual != set(expected):
                    raise PermissionError("Shared package file set mismatch")
        return immutable

    def _build(self, agent: str, config: dict, spec: dict, workspace: Path,
               writable: bool, cmd: list[str], *, probe: bool = False, launch_env: dict | None = None, workspace_transaction=None) -> PreparedLaunch:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = Path(tempfile.mkdtemp(prefix=f"development-{agent}-", dir=self.state_dir))
        os.chmod(root, 0o700)
        proxy = None
        headroom_proxy = None
        descriptors: list[int] = []
        cleaned = False

        def cleanup():
            nonlocal cleaned
            if cleaned:
                return
            cleaned = True
            if proxy is not None:
                proxy.close()
            if headroom_proxy is not None:
                headroom_proxy.close()
            for descriptor in descriptors:
                os.close(descriptor)
            try:
                (root / "opaque").chmod(0o700)
            except FileNotFoundError:
                pass
            shutil.rmtree(root, ignore_errors=True)

        try:
            home = root / "home"
            home.mkdir(mode=0o700)
            credentials = dict(spec["credentials"])
            if spec.get("codex_config"):
                credentials[".codex/config.toml"] = spec["codex_config"]
            for destination, source in credentials.items():
                target = home / destination
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if destination == ".codex/config.toml":
                    text, provider_env = _clean_profile_data(Path(source).parent)
                    if config.get("parallel_search_enabled") is True and agent in {"jax", "liz", "prof"}:
                        from agentporter.agents.parallel_search import codex_config_toml
                        text = codex_config_toml() + text
                    if provider_env:
                        raise PermissionError("provider environment credentials require a separately provisioned file profile")
                    target.write_text(text)
                elif destination in {".copilot/config.json", ".copilot-phil/config.json"}:
                    # Config doubles as the Copilot credential store. Preserve
                    # authentication only, never tools, hooks or MCP servers.
                    content = "\n".join(line for line in Path(source).read_text().splitlines() if not line.lstrip().startswith("//"))
                    data = json.loads(re.sub(r",\s*([}\]])", r"\1", content))
                    allowed = {"authTokens", "copilotTokens", "loggedInUsers", "lastLoggedInUser",
                               "copilot_tokens", "logged_in_users", "last_logged_in_user"}
                    if not isinstance(data, dict):
                        raise PermissionError("invalid Copilot authentication store")
                    target.write_text(json.dumps({k: v for k, v in data.items() if k in allowed}))
                else:
                    shutil.copyfile(source, target)
                target.chmod(0o600)
            if agent in {"jax", "liz", "prof"} and config.get("egress_policy") == "provider_origin":
                # Inspect every model request as bounded JSON, including when
                # the canonical account uses the CLI's default configuration.
                profile = home / ".codex/config.toml"
                profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                text = profile.read_text() if profile.exists() else ""
                profile.write_text("features = { enable_request_compression = false }\n" + text)
                profile.chmod(0o600)
            if ".gemini/antigravity-cli/antigravity-oauth-token" in credentials and spec.get("model"):
                settings = home / ".gemini/antigravity-cli/settings.json"
                    # Admit the entire vetted immutable snapshot, including canonical skills.
                # The CLI only reads skills; it must not execute their instructions as
                # commands. Native path matching remains an acceptance-test boundary.
                shared_reads = (
                    ["read_file(/opt/agentporter/shared/obsidian)"]
                    if self._shared_obsidian_source(config) is not None else []
                )
                permissions = {
                    "allow": ["read_file(/workspace)", *shared_reads],
                "deny": [
                        "command(*)",
                        "write_file(*)",
                        "read_url(*)",
                        "execute_url(*)",
                        "mcp(*)",
                        "read_file(/home/worker/.gemini/antigravity-cli)",
                        "read_file(/home/worker/.config)",
                        "read_file(/home/worker/.local/share)",
                    ],
                }
                settings.write_text(json.dumps({"model": spec["model"], "permissions": permissions}))
                settings.chmod(0o600)
            empty = root / "empty"
            empty.mkdir(mode=0o555)
            opaque = root / "opaque"
            opaque.mkdir(mode=0o000)
            empty_file = root / "empty-file"
            empty_file.touch(mode=0o444)
            (root / "passwd").write_text(f"worker:x:{os.getuid()}:{os.getgid()}:Development Worker:/home/worker:/bin/sh\n")
            (root / "group").write_text(f"worker:x:{os.getgid()}:\n")
            args = [self._sandbox_executable(config), "--unshare-all", "--unshare-user", "--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL",
                    "--new-session", "--die-with-parent", "--clearenv"]
            for path in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/alternatives", "/etc/ssl/certs"):
                if Path(path).exists():
                    args += ["--ro-bind", path, path]
            workspace_fd = self._pin(workspace, descriptors)
            args += ["--ro-bind", str(root / "passwd"), "/etc/passwd",
                     "--ro-bind", str(root / "group"), "/etc/group",
                     "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                     "--dir", "/home", "--bind", str(home), "/home/worker",
                     "--dir", "/run", "--dir", "/opt/agentporter/runtime",
                     "--bind" if writable else "--ro-bind", f"/proc/self/fd/{workspace_fd}", "/workspace"]
            # Scan the same pinned directory that will actually be mounted;
            # re-reading the host pathname after a concurrent root rename can
            # otherwise omit Git/secret masks from the original source tree.
            mask_fd = (workspace_transaction.inspection_fd
                       if workspace_transaction is not None else workspace_fd)
            for relative, directory, metadata, inaccessible in self._masks(Path(f"/proc/self/fd/{mask_fd}"), writable):
                if inaccessible:
                    # O_PATH does not read denied contents; reject symlinked
                    # components before placing the opaque denied mount.
                    self._pin(relative, descriptors, mask_fd)
                metadata_fd = self._pin(relative, descriptors, mask_fd) if metadata else None
                source = (str(opaque) if inaccessible else f"/proc/self/fd/{metadata_fd}" if metadata
                          else str(empty if directory else empty_file))
                args += ["--ro-bind", str(source), f"/workspace/{relative}"]
            shared = self._shared_obsidian_source(config)
            if shared is not None:
                # Pin the release directory itself against later path substitution;
                # no writable Obsidian checkout or host HOME is visible to workers.
                shared_fd = self._pin(shared, descriptors)
                args += ["--dir", "/opt/agentporter/shared",
                         "--ro-bind", f"/proc/self/fd/{shared_fd}",
                         "/opt/agentporter/shared/obsidian"]
            toolkit = self._shared_toolkit_source(config)
            if toolkit is not None:
                toolkit_fd = self._pin(toolkit, descriptors)
                args += ["--dir", "/opt/agentporter/tools",
                         "--ro-bind", f"/proc/self/fd/{toolkit_fd}",
                         "/opt/agentporter/tools"]
            if toolkit is not None and (toolkit / "packages/Rscript").is_dir():
                # Debian R's /usr/lib/R/etc entries point at /etc/R. Supply
                # only that exact reviewed configuration from this release.
                args += ["--ro-bind", str(toolkit / "packages/Rscript"), "/etc/R"]
            mapped_executable = None
            for mount in spec.get("runtime_mounts", []):
                source, target = self._code_mount(mount, spec["executable"])
                args += ["--ro-bind", source, target]
                if Path(spec["executable"]).is_relative_to(source):
                    mapped_executable = str(Path(target) / Path(spec["executable"]).relative_to(source))
            exe = spec["executable"]
            mounted_exe = mapped_executable or (exe if exe.startswith(("/usr/", "/bin/", "/sbin/")) else "/opt/agentporter/worker")
            if mounted_exe != exe and mapped_executable is None:
                args += ["--ro-bind", exe, mounted_exe]
            if spec.get("code_mode_host"):
                helper_root = self._pin(Path("/"), descriptors)
                helper_fd = self._pin(Path(spec["code_mode_host"]).relative_to("/"), descriptors, helper_root)
                args += ["--ro-bind", f"/proc/self/fd/{helper_fd}", "/opt/agentporter/codex-code-mode-host"]
            worker = ([mounted_exe, *cmd[1:]] if probe and cmd[:1] == [exe] else cmd[:]) if probe else self._normalize(cmd, exe, mounted_exe)
            environment = {"PATH": "/opt/agentporter/tools/bin:/opt/agentporter/runtime/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/worker",
                           "USER": "worker", "LOGNAME": "worker", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                           "CODEX_HOME": "/home/worker/.codex", "XDG_CONFIG_HOME": "/home/worker/.config",
                           "XDG_DATA_HOME": "/home/worker/.local/share", "GIT_CONFIG_NOSYSTEM": "1",
                           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
            if agent == "phil":
                environment.update(COPILOT_HOME="/home/worker/.copilot-phil", PHIL_COPILOT_HOME="/home/worker/.copilot-phil")
            if ".config/opencode/wei-key" in spec["credentials"] and not probe:
                # No ambient provider configuration or plugins. Build the
                # documented permission schema from the confined version probe.
                version = self._evidence.get(agent, {}).get("cli_version", "")
                match = re.fullmatch(r"(?:opencode\s+)?v?([12])\.\d+\.\d+(?:[-+][\w.-]+)?", version)
                if not match:
                    raise PermissionError("unsupported confined OpenCode permission schema version")
                if match[1] == "1":
                    safe = {"agent": {"dispatch": {"mode": "primary", "permission": {
                        "edit": "allow" if writable else "deny", "external_directory": "deny", "bash": "allow"}}}}
                else:
                    safe = {"agents": {"dispatch": {"mode": "primary", "permissions": [
                        {"action": "edit", "resource": "*", "effect": "allow" if writable else "deny"},
                        {"action": "external_directory", "resource": "*", "effect": "deny"},
                        {"action": "shell", "resource": "*", "effect": "allow"}]}}}
                key_path = home / ".config/opencode/wei-key"
                if not key_path.is_file() or not key_path.read_text().strip():
                    raise PermissionError("Wei separate credential file is unavailable or empty")
                provider, model = self._opencode_route(spec)
                worker = self._pin_opencode_model(worker, model)
                if match[1] == "2" and "--standalone" not in worker[2:]:
                    worker = [*worker[:2], "--standalone", *worker[2:]]
                key_reference = "{file:/home/worker/.config/opencode/wei-key}"
                provider_profile = {"options": {"apiKey": key_reference}}
                if provider == "opencode":
                    provider_profile.update({
                        "npm": "@ai-sdk/openai-compatible",
                        "options": {"apiKey": key_reference, "baseURL": "https://opencode.ai/inference/openai/v1"},
                        "models": {model.partition('/')[2]: {"name": model.partition('/')[2]}},
                    })
                if provider == "opencode-go":
                    provider_profile.update({
                        "npm": "@ai-sdk/openai-compatible",
                        "options": {"apiKey": key_reference, "baseURL": self._GO_BASE_URL},
                        "models": {"glm-5.3-flash": {"name": "GLM-5.3-Flash"}},
                    })
                safe.update(provider={provider: provider_profile}, model=model, small_model=model)
                # API keys stay in the private 0600 profile, never bwrap argv,
                # worker arguments, ambient environment, or gateway receipts.
                private_config = home / ".config/opencode/agentporter-development.json"
                private_config.write_text(json.dumps(safe, separators=(",", ":")))
                private_config.chmod(0o600)
                environment["OPENCODE_CONFIG"] = "/home/worker/.config/opencode/agentporter-development.json"
            if (config.get("parallel_search_enabled") is True and agent == "wei"
                    and ".config/opencode/wei-key" in spec["credentials"] and not probe):
                from agentporter.agents.parallel_search import opencode_mcp_config
                safe.update(opencode_mcp_config())
                private_config.write_text(json.dumps(safe, separators=(",", ":")))
                private_config.chmod(0o600)
            if agent == "phil" and not probe:
                # The broker's host package path is not visible in a namespace.
                # Only the fixed approved MCP definition may enter the worker.
                while "--additional-mcp-config" in worker:
                    index = worker.index("--additional-mcp-config")
                    del worker[index:index + 2]
                if config.get("parallel_search_enabled") is True:
                    from agentporter.agents.parallel_search import PARALLEL_MCP_URL, PARALLEL_MCP_TOOLS
                    target = home / ".config/agentporter/parallel-search-copilot.json"
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    target.write_text(json.dumps({"mcpServers": {"parallel-search": {
                        "type": "http", "url": PARALLEL_MCP_URL, "tools": list(PARALLEL_MCP_TOOLS)}}}))
                    target.chmod(0o600)
                    worker += ["--additional-mcp-config", "@/home/worker/.config/agentporter/parallel-search-copilot.json"]
            if config.get("network_enabled") is True:
                policy = config.get("egress_policy", "public_https")
                if policy == "provider_origin":
                    from agentporter.agents.provider_egress import ProviderEgress
                    proxy = ProviderEgress(root / "egress.sock", agent=agent,
                        parallel_search=config.get("parallel_search_enabled") is True).start()
                    ca_path = "/run/agentporter-provider-ca.pem"
                    args += ["--ro-bind", str(proxy.ca_bundle), ca_path]
                    environment.update(SSL_CERT_FILE=ca_path, CODEX_CA_CERTIFICATE=ca_path, REQUESTS_CA_BUNDLE=ca_path,
                        CURL_CA_BUNDLE=ca_path, NODE_EXTRA_CA_CERTS=ca_path)
                elif policy == "public_https":
                    from agentporter.agents.development_egress import PublicEgress
                    proxy = PublicEgress(root / "egress.sock").start()
                else:
                    raise PermissionError("Unknown development egress policy")
                helper = Path(__file__).with_name("development_egress.py").resolve()
                args += ["--ro-bind", str(root / "egress.sock"), "/run/agentporter-egress.sock",
                         "--ro-bind", str(helper), "/opt/agentporter/development_egress.py"]
                worker = ["/usr/bin/python3", "/opt/agentporter/development_egress.py", "bridge",
                          "--socket", "/run/agentporter-egress.sock", "--port", "18765", "--", *worker]
                # Preserve the canonical provider and account. Only this exact
                # approved URL grants access to the fixed Headroom service.
                codex_profile = home / ".codex/config.toml"
                if agent in {"jax", "liz", "prof"} and codex_profile.is_file():
                    import tomllib
                    profile = tomllib.loads(codex_profile.read_text())
                    provider = profile.get("model_provider", "openai")
                    route = profile.get("model_providers", {}).get(provider, {}).get("base_url")
                    headroom_ports = {'http://127.0.0.1:9787/v1': 9787,
                                      'http://127.0.0.1:8787/v1': 8787}
                    if route in headroom_ports:
                        headroom_port = headroom_ports[route]
                        from agentporter.agents.development_egress import HeadroomEgress
                        headroom_proxy = HeadroomEgress(root / "headroom.sock",
                            enforce_provider_tools=policy == "provider_origin", port=headroom_port).start()
                        args += ["--ro-bind", str(root / "headroom.sock"), "/run/agentporter-headroom.sock"]
                        worker = ["/usr/bin/python3", "/opt/agentporter/development_egress.py",
                                  "headroom-bridge", "--socket", "/run/agentporter-headroom.sock",
                                  "--port", str(headroom_port), "--", *worker]
            # bwrap preserves inherited descriptors when --ro-bind sources use
            # /proc/self/fd. They are setup handles, never worker capabilities:
            # a leaked workspace directory descriptor bypasses Git overmounts.
            # Run only this fixed, isolated Python bootstrap before any CLI or
            # proxy helper code and close every non-stdio descriptor first.
            close_descriptors = """import os, sys
for item in os.listdir('/proc/self/fd'):
    descriptor = int(item)
    if descriptor > 2:
        try:
            os.close(descriptor)
        except OSError:
            pass
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
"""
            worker = ["/usr/bin/python3", "-I", "-S", "-c", close_descriptors, *worker]
            for key, value in environment.items():
                args += ["--setenv", key, value]
            args += ["--chdir", "/workspace"]
            if workspace_transaction is not None:
                args = workspace_transaction.wrap_command(args, workspace_fd=workspace_fd)
            args += ["--", *worker]
            transaction_fds = (() if workspace_transaction is None
                               else workspace_transaction.launch_fds)
            return PreparedLaunch(args, cleanup, tuple(sorted(set(descriptors).union(transaction_fds))))
        except BaseException:
            cleanup()
            raise

    def require_production_egress(self, agent: str | None = None) -> frozenset[str]:
        config = self._config()
        if config.get("network_enabled") is not True or config.get("egress_policy") != "provider_origin":
            raise PermissionError("Production relay requires operation-scoped provider egress")
        approved = config.get("production_relay_agents")
        if (not isinstance(approved, list) or not approved
                or any(not isinstance(name, str) or name not in PUBLIC_AGENT_IDS for name in approved)
                or len(set(approved)) != len(approved)):
            raise PermissionError("Production relay requires an explicit admitted agent list")
        if agent is not None and agent not in approved:
            raise PermissionError("Agent is not admitted for production delegation")
        if config.get('public_client_policy_required') is not True or not isinstance(config.get('job_resources'), dict):
            raise PermissionError('Production relay requires public-client isolation and job resource envelopes')
        return frozenset(approved)

    @staticmethod
    def _normalize(cmd: list[str], executable: str, mounted_exe: str) -> list[str]:
        if not cmd or any(not isinstance(part, str) for part in cmd):
            raise PermissionError("worker command must be a nonempty string argv")
        if "agentporter.agents.isolated_codex" in cmd:
            try:
                cmd = cmd[cmd.index("--") + 1:]
            except ValueError as exc:
                raise PermissionError("invalid isolated Codex wrapper") from exc
        if cmd[:1] == ["env"]:
            cmd = cmd[1:]
            allowed = {"CODEX_HOME", "COPILOT_HOME", "PHIL_COPILOT_HOME"}
            while cmd and "=" in cmd[0] and cmd[0].split("=", 1)[0] in allowed:
                cmd = cmd[1:]
        if not cmd or not Path(cmd[0]).is_absolute() or str(Path(cmd[0]).resolve()) != executable:
            raise PermissionError("worker command does not match configured executable")
        if any(part.startswith("--dangerously-") or part in {"--yolo"} for part in cmd):
            raise PermissionError("worker sandbox bypass flags are forbidden")
        result = [mounted_exe]
        it = iter(cmd[1:])
        for item in it:
            if item in {"-C", "--cd"}:
                next(it, None)
                result += [item, "/workspace"]
            elif item.startswith("--cd="):
                result.append("--cd=/workspace")
            elif item in {"--sandbox", "-s"} and "exec" in cmd[1:3]:
                next(it, None)
                # The independently verified outer bwrap is the filesystem and
                # network boundary. Nested CLI sandboxes need not permit netns.
                result += [item, "danger-full-access"]
            else:
                result.append(item)
        return result

    def _signature(self, config: dict, spec: dict) -> str:
        files = [Path(spec["executable"]), self.config_dir / "development-runtime.yaml",
                 Path(self._sandbox_executable(config)), *map(Path, spec["credentials"].values())]
        if spec.get("codex_config"):
            files.append(Path(spec["codex_config"]))
        if spec.get("code_mode_host"):
            files.append(Path(spec["code_mode_host"]))
        files.extend(Path(mount["source"]) for mount in spec.get("runtime_mounts", []))
        return repr([(str(p), p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_size) for p in files])

    def _verified(self, agent: str) -> tuple[dict, dict]:
        config = self._config()
        spec = self._spec(agent, config)
        signature = self._signature(config, spec)
        with self._probe_lock:
            cached = self._cache.get(agent)
            if cached and time.monotonic() - cached[0] < 30 and cached[1] == signature:
                return config, spec
            self._probe(agent, config, spec)
            self._cache[agent] = (time.monotonic(), signature)
        return config, spec

    @staticmethod
    def _run_probe(command: list[str], pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        """Bound time and memory even when a broken CLI floods version output."""
        proc = subprocess.Popen(command, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, process_group=0, pass_fds=pass_fds)
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 15
        try:
            with selectors.DefaultSelector() as selector:
                for name in streams:
                    stream = getattr(proc, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PermissionError("confined worker probe timed out")
                    for key, _ in selector.select(remaining):
                        block = os.read(key.fileobj.fileno(), 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        streams[key.data].extend(block)
                        if sum(map(len, streams.values())) > 64 * 1024:
                            raise PermissionError("confined worker probe exceeded output limit")
                code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            return subprocess.CompletedProcess(command, code, streams["stdout"].decode(errors="replace"), streams["stderr"].decode(errors="replace"))
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()

    def _probe(self, agent: str, config: dict, spec: dict):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix="development-probe-", dir=self.state_dir) as temporary:
            scratch = Path(temporary)
            (scratch / ".git").mkdir()
            (scratch / ".git" / "protected").write_text("not exposed")
            namespaces = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("net", "mnt", "pid")}
            for writable in (True, False):
                script = f"""import os, pathlib
ns = {namespaces!r}
assert all(os.stat('/proc/self/ns/'+k).st_ino != v for k,v in ns.items())
assert pathlib.Path('/workspace/.git/protected').read_text() == 'not exposed'
assert not pathlib.Path({str(self.config_dir)!r}).exists()
assert not pathlib.Path({str(self.state_dir)!r}).exists()
def denied(path):
    try:
        pathlib.Path(path).write_text('forbidden')
    except OSError:
        return
    raise AssertionError('protected write succeeded')
denied('/workspace/.git/protected')
denied('/workspace/.git/new-control')
denied('/usr/agentporter-forbidden')
if {writable!r}:
    pathlib.Path('/workspace/writable-probe').write_text('ok')
else:
    denied('/workspace/writable-probe')
print('AGENTPORTER_OS_CONFINEMENT_OK')
"""
                launch = self._build(agent, config, spec, scratch, writable,
                                     ["/usr/bin/python3", "-c", script], probe=True)
                try:
                    outcome = self._run_probe(launch.command, launch.pass_fds)
                    if outcome.returncode or "AGENTPORTER_OS_CONFINEMENT_OK" not in outcome.stdout:
                        raise PermissionError("live OS confinement probe failed: " + outcome.stderr.strip()[:300])
                finally:
                    launch.cleanup()
            launch = self._build(agent, config, spec, scratch, False, [spec["executable"], "--version"], probe=True)
            try:
                outcome = self._run_probe(launch.command, launch.pass_fds)
                if outcome.returncode:
                    raise PermissionError(f"confined {agent} executable probe failed (exit {outcome.returncode}): " + outcome.stderr.strip()[:300])
            finally:
                launch.cleanup()
            version = (outcome.stdout or outcome.stderr).strip().splitlines()[0][:160] if (outcome.stdout or outcome.stderr).strip() else "unknown"
            if spec.get("code_mode_host"):
                launch = self._build(agent, config, spec, scratch, False,
                                     ["/opt/agentporter/codex-code-mode-host", "--help"], probe=True)
                try:
                    helper_outcome = self._run_probe(launch.command, launch.pass_fds)
                    if helper_outcome.returncode:
                        raise PermissionError("confined bundled Codex code-mode helper probe failed")
                finally:
                    launch.cleanup()
            if ".config/opencode/wei-key" in spec["credentials"] and not re.fullmatch(r"(?:opencode\s+)?v?([12])\.\d+\.\d+(?:[-+][\w.-]+)?", version):
                raise PermissionError("unsupported confined OpenCode permission schema version")
            self._evidence[agent] = {"verified_at": time.time(), "namespace_checks": list(namespaces),
                                     "verified_modes": ["read-only", "writable"],
                                     "cli_version": version}

    def status(self, agent: str, adapter=None, detection=None) -> dict:
        try:
            config, spec = self._verified(agent)
            dispatch_workspaces = []
            writable_workspaces = []
            for entry in self.workspace_registry.list_all():
                try:
                    self._workspace(entry["path"], False, config)
                except (OSError, ValueError):
                    continue
                dispatch_workspaces.append(entry["workspace_id"])
                try:
                    self._workspace(entry["path"], True, config)
                except (OSError, ValueError):
                    continue
                writable_workspaces.append(entry["workspace_id"])
            return {"delegatable": True, "confinement_status": "verified_development_bwrap",
                    "availability_reason": "OS isolation and configured worker executable verified; authentication files provisioned",
                    "runtime_profile": config["profile"], "worker_executable": spec["executable"],
                    "sandbox_executable": self._sandbox_executable(config),
                    "shared_obsidian_path": "/opt/agentporter/shared/obsidian" if self._shared_obsidian_source(config) else None,
                    "toolkit_path": "/opt/agentporter/tools" if self._shared_toolkit_source(config) else None,
                    "configured_model": spec.get("model", "unknown"),
                    "provider": spec.get("provider") or getattr(adapter, 'provider', 'unknown'),
                    "reasoning_effort": spec.get("reasoning_effort", "unknown"),
                    **self._evidence.get(agent, {}),
                    "runtime_dispatch_workspaces": sorted(dispatch_workspaces),
                    "runtime_writable_dispatch_workspaces": sorted(writable_workspaces)}
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
            return {"delegatable": False, "confinement_status": "blocked_development_runtime",
                    "availability_reason": str(exc), "runtime_profile": "development"}

    def executable_for(self, agent: str) -> str | None:
        """Resolve configuration without executing the host worker binary."""
        try:
            config = self._config()
            return self._spec(agent, config)["executable"]
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            return None

    def prepare(self, agent: str, workspace_path: str, writable: bool,
                cmd: list[str], env: dict | None = None, *, workspace_transaction=None) -> PreparedLaunch:
        config, spec = self._verified(agent)
        workspace = self._workspace(workspace_path, writable, config)
        options = {} if workspace_transaction is None else {'workspace_transaction': workspace_transaction}
        return self._build(agent, config, spec, workspace, writable, cmd, launch_env=env, **options)
