"""Base agent adapter interface for AgentPorter."""

import os
import shutil
from abc import ABC, abstractmethod
from typing import Optional

from agentporter.agents.policy import ExecutionPolicy


class AgentAdapter(ABC):
    """Abstract contract for an AI coding-agent CLI worker."""

    name: str = ""
    alias: str = ""
    provider: str = "unknown"
    description: str = ""

    # Adapters must explicitly advertise controls they can actually enforce.
    supports_read_only: bool = False
    supports_model_override: bool = False
    supports_reasoning_override: bool = False

    def __init__(self, executable_override: Optional[str] = None):
        self.executable_override = executable_override

    def find_executable(self, default_names: list[str]) -> Optional[str]:
        if (
            self.executable_override
            and os.path.isfile(self.executable_override)
            and os.access(self.executable_override, os.X_OK)
        ):
            return self.executable_override

        for name in default_names:
            p = shutil.which(name)
            if p:
                return p
            expanded = os.path.expanduser(name)
            if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
                return expanded
        return None

    @abstractmethod
    def detect(self) -> dict:
        """Detect installation, CLI version, and configured routing when reliably observable."""
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> list[str]:
        """Return a coarse capability list for discovery/UI purposes."""
        raise NotImplementedError

    @abstractmethod
    def build_argv(
        self,
        workspace_path: str,
        packet: str,
<<<<<<< HEAD
        model: str = "",
        reasoning_effort: str = "",
        writable: bool = True,
    ) -> list[str]:
        """Construct argv using only controls this adapter can actually enforce."""
        raise NotImplementedError
=======
        model: str,
        reasoning_effort: str,
        policy: Optional[ExecutionPolicy] = None,
    ) -> list[str]:
        """Construct process command arguments enforcing the execution policy."""
        pass
>>>>>>> origin/main
