"""Configuration resolution and path management for AgentPorter."""

import os
import re
import yaml
import secrets
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger("agentporter.config")

# Standard XDG base directory defaults
DEFAULT_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "agentporter"
DEFAULT_STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "agentporter"
DEFAULT_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "agentporter"


@dataclass
class ServerSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    name: str = "AgentPorter"
    # Optional deployment URL used for generated OpenAPI `servers` metadata.
    # The reusable package stays tunnel-agnostic when this is unset.
    public_url: str = field(default_factory=lambda: os.environ.get("AGENTPORTER_PUBLIC_URL", "").strip())
    action_prefix: str = field(default_factory=lambda: os.environ.get("AGENTPORTER_ACTION_PREFIX", "").strip())


@dataclass
class SecuritySettings:
    header_name: str = "X-AgentPorter-Key"
    # Client-specific compatibility headers are opt-in local configuration.
    legacy_header_name: str = ""
    allowed_hosts: list[str] = field(default_factory=lambda: [
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
    ])
    rate_limit_max_requests: int = 120
    rate_limit_window_seconds: float = 60.0
    max_payload_bytes: int = 10 * 1024 * 1024  # 10 MB


@dataclass
class SandboxSettings:
    workspace_transactions: bool = False
    backend: str = "bubblewrap"
    # Networked direct execution is intentionally unsupported in the alpha.
    network: bool = False
    default_timeout_seconds: int = 30
    max_timeout_seconds: int = 900
    max_output_bytes: int = 100 * 1024  # synchronous stdout/stderr cap
    max_job_log_bytes: int = 10 * 1024 * 1024  # per stream, async jobs


@dataclass
class ParallelSearchSettings:
    enabled: bool = False


@dataclass
class ScinetSettings:
    """Private deployment-supplied endpoint and training policy settings."""

    host: str = ""
    user: str = ""
    # AgentPorter talks to the broker, never to the user's SSH control socket.
    # The broker owns the authenticated SSH session and its private transport.
    broker_socket: str = ""
    broker_control_socket: str = ""
    control_socket: str = ""
    machine: str = ""
    # Authorized human reviewer for scinet_record_approvals; defaults to `user`.
    approval_reviewer: str = ""
    training_remote_root: str = ""
    training_account: str = ""
    training_partition: str = ""
    training_python: str = ""
    # Repeated here for operator visibility; implementation accepts only code pin.
    inference_manifest_sha256: str = ""
    # Inference-only deployment paths are separate from the A/B training setup.
    inference_scratch_root: str = ""
    inference_python: str = ""
    inference_hf_cache: str = ""
    # Catalog path is fixed beneath scratch; digest must be independently reviewed.
    inference_runtime_catalog_sha256: str = ""
    inference_approval_reviewer: str = ""
    training_bootstrap_python: str = "/usr/bin/python3"
    training_cpus_per_task: int = 4
    training_max_stage_bytes: int = 512 * 1024 * 1024
    # Full Experiment A/B submission is off unless a human enables it privately.
    training_allow_full_runs: bool = False
    training_full_walltime: str = "02:00:00"


class Config:
    """Central configuration manager for AgentPorter."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        state_dir: Optional[Path] = None,
        cache_dir: Optional[Path] = None,
    ):
        self.config_dir = Path(config_dir or os.environ.get("AGENTPORTER_CONFIG_DIR", DEFAULT_CONFIG_DIR)).resolve()
        self.state_dir = Path(state_dir or os.environ.get("AGENTPORTER_STATE_DIR", DEFAULT_STATE_DIR)).resolve()
        self.cache_dir = Path(cache_dir or os.environ.get("AGENTPORTER_CACHE_DIR", DEFAULT_CACHE_DIR)).resolve()

        self.server = ServerSettings()
        self.security = SecuritySettings()
        self.sandbox = SandboxSettings()
        self.parallel_search = ParallelSearchSettings()
        self.scinet = ScinetSettings()
        self.workspaces: dict[str, dict[str, Any]] = {}
        self.api_key: str = ""

        self._ensure_dirs()
        self._load_config_file()
        self._load_workspaces_file()
        self._load_scinet_environment()
        self._load_or_generate_api_key()

    def _load_scinet_environment(self) -> None:
        for field in (
            "host",
            "user",
            "broker_socket",
            "broker_control_socket",
            "control_socket",
            "machine",
            "approval_reviewer",
            "inference_scratch_root",
            "inference_python",
            "inference_hf_cache",
            "inference_runtime_catalog_sha256",
            "inference_approval_reviewer",
        ):
            value = os.environ.get("AGENTPORTER_SCINET_" + field.upper())
            if value is not None:
                setattr(self.scinet, field, value.strip())
        for field in (
            "training_remote_root",
            "training_account",
            "training_partition",
            "training_python",
            "training_bootstrap_python",
        ):
            value = os.environ.get("AGENTPORTER_SCINET_" + field.upper())
            if value is not None:
                setattr(self.scinet, field, value.strip())
        value = os.environ.get("AGENTPORTER_SCINET_INFERENCE_MANIFEST_SHA256")
        if value is not None:
            self.scinet.inference_manifest_sha256 = value.strip()
        value = os.environ.get("AGENTPORTER_SCINET_TRAINING_CPUS_PER_TASK")
        if value is not None:
            self.scinet.training_cpus_per_task = int(value)
        workspace = os.environ.get("AGENTPORTER_SCINET_WORKSPACE", "").strip()
        if workspace:
            if workspace not in self.workspaces:
                raise ValueError("SciNet workspace override must name a registered workspace")
            self.workspaces[workspace]["allow_scinet_diagnostic"] = True

    @staticmethod
    def _ensure_private_dir(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            logger.warning("Could not set private permissions on %s", path)

    def _ensure_dirs(self) -> None:
        """Create config/state directories with private permissions."""
        self._ensure_private_dir(self.config_dir)
        self._ensure_private_dir(self.state_dir)
        self._ensure_private_dir(self.cache_dir)
        self._ensure_private_dir(self.state_dir / "jobs")
        self._ensure_private_dir(self.state_dir / "logs")
        self._ensure_private_dir(self.state_dir / "etc")

    def _load_config_file(self) -> None:
        """Load server/security/sandbox options from config.yaml if present."""
        config_file = self.config_dir / "config.yaml"
        if not config_file.is_file():
            return

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            parallel = data.get("parallel_search", {})
            if not isinstance(parallel, dict) or set(parallel) - {"enabled"}:
                raise ValueError("parallel_search accepts only enabled")
            if "enabled" in parallel:
                if not isinstance(parallel["enabled"], bool):
                    raise ValueError("parallel_search.enabled must be a boolean")
                self.parallel_search.enabled = parallel["enabled"]

            srv = data.get("server", {})
            if "host" in srv:
                self.server.host = str(srv["host"])
            if "port" in srv:
                self.server.port = int(srv["port"])
            if "name" in srv:
                self.server.name = str(srv["name"])
            if "public_url" in srv:
                self.server.public_url = str(srv["public_url"] or "").strip()
            if "action_prefix" in srv:
                self.server.action_prefix = str(srv["action_prefix"] or "").strip()

            sec = data.get("security", {})
            auth_mode = sec.get("auth", "api_key")
            if auth_mode != "api_key":
                raise ValueError("Only security.auth='api_key' is supported")
            if "header_name" in sec:
                self.security.header_name = str(sec["header_name"])
            if "legacy_header_name" in sec:
                self.security.legacy_header_name = str(sec["legacy_header_name"] or "")
            if "allowed_hosts" in sec and isinstance(sec["allowed_hosts"], list):
                self.security.allowed_hosts = [str(h) for h in sec["allowed_hosts"]]
            if "rate_limit" in sec and isinstance(sec["rate_limit"], dict):
                rl = sec["rate_limit"]
                self.security.rate_limit_max_requests = int(
                    rl.get("max_requests", self.security.rate_limit_max_requests)
                )
                self.security.rate_limit_window_seconds = float(
                    rl.get("window_seconds", self.security.rate_limit_window_seconds)
                )
            if "max_payload_bytes" in sec:
                self.security.max_payload_bytes = int(sec["max_payload_bytes"])

            sbx = data.get("sandbox", {})
            if 'workspace_transactions' in sbx:
                if type(sbx['workspace_transactions']) is not bool:
                    raise ValueError('sandbox.workspace_transactions must be boolean')
                self.sandbox.workspace_transactions = sbx['workspace_transactions']
            if "backend" in sbx:
                self.sandbox.backend = str(sbx["backend"])
            if self.sandbox.backend != "bubblewrap":
                raise ValueError("Only sandbox.backend='bubblewrap' is currently supported")
            if "network" in sbx:
                self.sandbox.network = bool(sbx["network"])
            if self.sandbox.network:
                raise ValueError("Direct-execution network access is not supported; set sandbox.network=false")
            if "default_timeout_seconds" in sbx:
                self.sandbox.default_timeout_seconds = int(sbx["default_timeout_seconds"])
            if "max_timeout_seconds" in sbx:
                self.sandbox.max_timeout_seconds = int(sbx["max_timeout_seconds"])
            if "max_output_bytes" in sbx:
                self.sandbox.max_output_bytes = int(sbx["max_output_bytes"])
            if "max_job_log_bytes" in sbx:
                self.sandbox.max_job_log_bytes = int(sbx["max_job_log_bytes"])

            sci = data.get("scinet", {})
            self.scinet.host = str(sci.get("host", self.scinet.host) or "").strip()
            self.scinet.user = str(sci.get("user", self.scinet.user) or "").strip()
            self.scinet.broker_socket = str(
                sci.get("broker_socket", self.scinet.broker_socket) or ""
            ).strip()
            self.scinet.broker_control_socket = str(
                sci.get("broker_control_socket", self.scinet.broker_control_socket) or ""
            ).strip()
            self.scinet.control_socket = str(
                sci.get("control_socket", self.scinet.control_socket) or ""
            ).strip()
            self.scinet.machine = str(sci.get("machine", self.scinet.machine) or "").strip()
            self.scinet.training_remote_root = str(
                sci.get("training_remote_root", self.scinet.training_remote_root) or ""
            ).strip()
            self.scinet.training_account = str(
                sci.get("training_account", self.scinet.training_account) or ""
            ).strip()
            self.scinet.training_partition = str(
                sci.get("training_partition", self.scinet.training_partition) or ""
            ).strip()
            self.scinet.training_python = str(
                sci.get("training_python", self.scinet.training_python) or ""
            ).strip()
            self.scinet.inference_manifest_sha256 = str(
                sci.get("inference_manifest_sha256", self.scinet.inference_manifest_sha256)
                or ""
            ).strip()
            self.scinet.inference_scratch_root = str(
                sci.get("inference_scratch_root", self.scinet.inference_scratch_root) or ""
            ).strip()
            self.scinet.inference_python = str(
                sci.get("inference_python", self.scinet.inference_python) or ""
            ).strip()
            self.scinet.inference_hf_cache = str(
                sci.get("inference_hf_cache", self.scinet.inference_hf_cache) or ""
            ).strip()
            self.scinet.inference_runtime_catalog_sha256 = str(
                sci.get("inference_runtime_catalog_sha256",
                        self.scinet.inference_runtime_catalog_sha256) or ""
            ).strip()
            if self.scinet.inference_runtime_catalog_sha256 and not re.fullmatch(
                r"[0-9a-f]{64}", self.scinet.inference_runtime_catalog_sha256
            ):
                raise ValueError("scinet.inference_runtime_catalog_sha256 must be lowercase SHA-256")
            self.scinet.inference_approval_reviewer = str(
                sci.get("inference_approval_reviewer", self.scinet.inference_approval_reviewer)
                or ""
            ).strip()
            if self.scinet.inference_manifest_sha256 and not re.fullmatch(
                r"[0-9a-f]{64}", self.scinet.inference_manifest_sha256
            ):
                raise ValueError("scinet.inference_manifest_sha256 must be lowercase SHA-256")
            self.scinet.training_bootstrap_python = str(
                sci.get("training_bootstrap_python", self.scinet.training_bootstrap_python) or ""
            ).strip()
            if "training_cpus_per_task" in sci:
                self.scinet.training_cpus_per_task = int(sci["training_cpus_per_task"])
            if "training_max_stage_bytes" in sci:
                self.scinet.training_max_stage_bytes = int(sci["training_max_stage_bytes"])
            if "training_allow_full_runs" in sci:
                if not isinstance(sci["training_allow_full_runs"], bool):
                    raise ValueError("scinet.training_allow_full_runs must be a boolean")
                self.scinet.training_allow_full_runs = sci["training_allow_full_runs"]
            if "training_full_walltime" in sci:
                walltime = str(sci["training_full_walltime"])
                if not re.fullmatch(r"(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]", walltime):
                    raise ValueError("scinet.training_full_walltime must be HH:MM:SS below 24h")
                self.scinet.training_full_walltime = walltime

            if self.sandbox.default_timeout_seconds <= 0:
                raise ValueError("sandbox.default_timeout_seconds must be > 0")
            if self.sandbox.max_timeout_seconds < self.sandbox.default_timeout_seconds:
                raise ValueError("sandbox.max_timeout_seconds must be >= default_timeout_seconds")
            if self.sandbox.max_output_bytes <= 0 or self.sandbox.max_job_log_bytes <= 0:
                raise ValueError("sandbox output limits must be > 0")
            if self.security.max_payload_bytes <= 0:
                raise ValueError("security.max_payload_bytes must be > 0")
            if self.scinet.training_cpus_per_task <= 0:
                raise ValueError("scinet.training_cpus_per_task must be > 0")
            if self.scinet.training_max_stage_bytes <= 0:
                raise ValueError("scinet.training_max_stage_bytes must be > 0")

        except Exception as e:
            # Invalid security configuration must fail closed rather than be silently ignored.
            raise ValueError(f"Failed to load config file {config_file}: {e}") from e

    def _load_workspaces_file(self) -> None:
        """Load registered workspaces from workspaces.yaml or config.yaml."""
        ws_file = self.config_dir / "workspaces.yaml"
        if ws_file.is_file():
            try:
                with open(ws_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                self.workspaces = data.get("workspaces", {})
                return
            except Exception as e:
                raise ValueError(f"Failed to parse {ws_file}: {e}") from e

        config_file = self.config_dir / "config.yaml"
        if config_file.is_file():
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self.workspaces = data.get("workspaces", {})

    def _load_or_generate_api_key(self) -> None:
        """Retrieve AgentPorter API key from env or secrets.env, generating one if absent."""
        env_key = os.environ.get("AGENTPORTER_API_KEY")
        if env_key:
            self.api_key = env_key.strip()
            return

        secrets_file = self.config_dir / "secrets.env"
        if secrets_file.is_file():
            try:
                os.chmod(secrets_file, 0o600)
            except OSError:
                logger.warning("Could not enforce 0600 on %s", secrets_file)
            with open(secrets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("AGENTPORTER_API_KEY="):
                        self.api_key = line.split("=", 1)[1].strip()
                        if self.api_key:
                            return
                    if line.startswith("API_KEY="):
                        self.api_key = line.split("=", 1)[1].strip()
                        if self.api_key:
                            return
            raise ValueError(f"{secrets_file} exists but contains no API key")

        new_key = secrets.token_urlsafe(32)
        fd = os.open(secrets_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("# AgentPorter generated API key\n")
            f.write(f"AGENTPORTER_API_KEY={new_key}\n")
        self.api_key = new_key
        logger.info("Generated new API key at %s (mode 0600)", secrets_file)

    def _write_workspaces_file(self) -> None:
        ws_file = self.config_dir / "workspaces.yaml"
        with open(ws_file, "w", encoding="utf-8") as f:
            yaml.safe_dump({"workspaces": self.workspaces}, f, sort_keys=True)

    def add_workspace(
        self,
        ws_id: str,
        path: str,
        writable: bool = True,
        description: str = "",
        allow_execute: bool = True,
        allow_git: bool = True,
        allow_artifacts: bool = True,
        allow_agent_dispatch: bool = False,
        local_http_ports: Optional[list[int]] = None,
    ) -> None:
        self.workspaces[ws_id] = {
            "path": str(Path(path).expanduser().resolve()),
            "writable": bool(writable),
            "description": description,
            "allow_execute": bool(allow_execute),
            "allow_git": bool(allow_git),
            "allow_artifacts": bool(allow_artifacts),
            "allow_agent_dispatch": bool(allow_agent_dispatch),
            "local_http_ports": sorted({int(p) for p in (local_http_ports or []) if 1 <= int(p) <= 65535}),
        }
        self._write_workspaces_file()

    def remove_workspace(self, ws_id: str) -> bool:
        if ws_id not in self.workspaces:
            return False
        del self.workspaces[ws_id]
        self._write_workspaces_file()
        return True
