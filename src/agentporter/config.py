"""Configuration resolution and path management for AgentPorter."""

import os
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


@dataclass
class SecuritySettings:
    auth_enabled: bool = True
    header_name: str = "X-AgentPorter-Key"
    legacy_header_name: str = "X-M3-MCP-Key"
    allowed_hosts: list[str] = field(default_factory=lambda: [
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
        "*.trycloudflare.com",
        "*.trycloudflare.com:*",
        "*.devtunnels.ms",
        "*.devtunnels.ms:*",
        "*.lhr.life",
        "*.lhr.life:*",
        "*.pinggy.link",
        "*.pinggy.link:*",
        "*.pinggy.net",
        "*.pinggy.net:*",
        "*.ts.net",
        "*.ts.net:*",
    ])
    rate_limit_max_requests: int = 120
    rate_limit_window_seconds: float = 60.0
    max_payload_bytes: int = 10 * 1024 * 1024  # 10 MB



@dataclass
class SandboxSettings:
    backend: str = "bubblewrap"
    network: bool = False
    default_timeout_seconds: int = 30
    max_output_bytes: int = 100 * 1024  # 100 KB


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
        self.workspaces: dict[str, dict[str, Any]] = {}
        self.api_key: str = ""

        # Initialize directories and load configurations
        self._ensure_dirs()
        self._load_config_file()
        self._load_workspaces_file()
        self._load_or_generate_api_key()

    def _ensure_dirs(self) -> None:
        """Create config and state directories if they don't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "jobs").mkdir(parents=True, exist_ok=True)
        (self.state_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.state_dir / "etc").mkdir(parents=True, exist_ok=True)

    def _load_config_file(self) -> None:
        """Load server options from config.yaml if present."""
        config_file = self.config_dir / "config.yaml"
        if not config_file.is_file():
            return

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            srv = data.get("server", {})
            if "host" in srv:
                self.server.host = str(srv["host"])
            if "port" in srv:
                self.server.port = int(srv["port"])
            if "name" in srv:
                self.server.name = str(srv["name"])

            sec = data.get("security", {})
            if "header_name" in sec:
                self.security.header_name = str(sec["header_name"])
            if "legacy_header_name" in sec:
                self.security.legacy_header_name = str(sec["legacy_header_name"])
            if "allowed_hosts" in sec and isinstance(sec["allowed_hosts"], list):
                self.security.allowed_hosts = [str(h) for h in sec["allowed_hosts"]]

            env_hosts = os.environ.get("ALLOWED_HOSTS", "")
            if env_hosts:
                for h in env_hosts.split(","):
                    h_clean = h.strip()
                    if h_clean and h_clean not in self.security.allowed_hosts:
                        self.security.allowed_hosts.append(h_clean)

            if "rate_limit" in sec and isinstance(sec["rate_limit"], dict):
                rl = sec["rate_limit"]
                self.security.rate_limit_max_requests = int(rl.get("max_requests", self.security.rate_limit_max_requests))
                self.security.rate_limit_window_seconds = float(rl.get("window_seconds", self.security.rate_limit_window_seconds))
            if "max_payload_bytes" in sec:
                self.security.max_payload_bytes = int(sec["max_payload_bytes"])

            sbx = data.get("sandbox", {})
            if "backend" in sbx:
                self.sandbox.backend = str(sbx["backend"])
            if "network" in sbx:
                self.sandbox.network = bool(sbx["network"])
            if "default_timeout_seconds" in sbx:
                self.sandbox.default_timeout_seconds = int(sbx["default_timeout_seconds"])
            if "max_output_bytes" in sbx:
                self.sandbox.max_output_bytes = int(sbx["max_output_bytes"])

        except Exception as e:
            logger.warning("Failed to load config file %s: %s", config_file, e)

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
                logger.warning("Failed to parse %s: %s", ws_file, e)

        # Fallback to workspaces key in config.yaml
        config_file = self.config_dir / "config.yaml"
        if config_file.is_file():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                self.workspaces = data.get("workspaces", {})
            except Exception:
                pass

    def add_workspace(self, ws_id: str, path: str, writable: bool = True, description: str = "") -> None:
        """Register and persist a workspace to workspaces.yaml."""
        real_path = os.path.realpath(os.path.expanduser(path))
        self.workspaces[ws_id] = {
            "path": real_path,
            "writable": writable,
            "description": description,
        }
        self.config_dir.mkdir(parents=True, exist_ok=True)
        ws_file = self.config_dir / "workspaces.yaml"
        with open(ws_file, "w", encoding="utf-8") as f:
            yaml.safe_dump({"workspaces": self.workspaces}, f, sort_keys=False)

    def remove_workspace(self, ws_id: str) -> bool:
        """Remove a workspace from workspaces.yaml. Returns True if removed."""
        if ws_id in self.workspaces:
            del self.workspaces[ws_id]
            self.config_dir.mkdir(parents=True, exist_ok=True)
            ws_file = self.config_dir / "workspaces.yaml"
            with open(ws_file, "w", encoding="utf-8") as f:
                yaml.safe_dump({"workspaces": self.workspaces}, f, sort_keys=False)
            return True
        return False


    def _load_or_generate_api_key(self) -> None:
        """Retrieve API key from env or secrets.env, generating one if absent."""
        self.api_keys = []
        env_key = os.environ.get("AGENTPORTER_API_KEY")
        if env_key and env_key.strip():
            self.api_keys.append(env_key.strip())
        env_m3 = os.environ.get("M3_MCP_KEY")
        if env_m3 and env_m3.strip() and env_m3.strip() not in self.api_keys:
            self.api_keys.append(env_m3.strip())

        secrets_file = self.config_dir / "secrets.env"
        if secrets_file.is_file():
            try:
                with open(secrets_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("AGENTPORTER_API_KEY="):
                            k = line.split("=", 1)[1].strip()
                            if k and k not in self.api_keys:
                                self.api_keys.append(k)
                        elif line.startswith("M3_MCP_KEY="):
                            k = line.split("=", 1)[1].strip()
                            if k and k not in self.api_keys:
                                self.api_keys.append(k)
                        elif line and not line.startswith("#") and "=" not in line:
                            if line not in self.api_keys:
                                self.api_keys.append(line)
            except Exception as e:
                logger.warning("Could not read secrets file %s: %s", secrets_file, e)

        if not self.api_keys:
            # Generate a new random 32-byte key
            new_key = secrets.token_urlsafe(32)
            try:
                with open(secrets_file, "w", encoding="utf-8") as f:
                    f.write(f"# AgentPorter generated API key\n")
                    f.write(f"AGENTPORTER_API_KEY={new_key}\n")
                    f.write(f"M3_MCP_KEY={new_key}\n")
                os.chmod(secrets_file, 0o600)
                logger.info("Generated new API key at %s (mode 0600)", secrets_file)
            except Exception as e:
                logger.error("Failed to write secrets file %s: %s", secrets_file, e)
            self.api_keys.append(new_key)

        self.api_key = self.api_keys[0]
