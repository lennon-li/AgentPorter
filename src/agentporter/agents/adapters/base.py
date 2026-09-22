"""Base agent adapter interface for AgentPorter."""

import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

from agentporter.agents.policy import ExecutionPolicy


class AgentAdapter(ABC):
    """Abstract contract for an AI coding agent CLI worker."""

    name: str = ""
    alias: str = ""
    provider: str = ""
    default_model: str = ""
    reasoning_effort: str = "medium"
    description: str = ""

    def __init__(self, executable_override: Optional[str] = None):
        self.executable_override = executable_override

    def find_executable(self, default_names: list[str]) -> Optional[str]:
        if self.executable_override and os.path.isfile(self.executable_override) and os.access(self.executable_override, os.X_OK):
            return self.executable_override

        for name in default_names:
            p = shutil.which(name)
            if p:
                return p
            # Check user home bin locations
            expanded = os.path.expanduser(name)
            if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
                return expanded

        return None

    @abstractmethod
    def detect(self) -> dict:
        """Detect installation status, CLI version, configured model, and reasoning effort."""
        pass

    @abstractmethod
    def capabilities(self) -> list[str]:
        """Return list of agent capabilities."""
        pass

    @abstractmethod
    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str,
        reasoning_effort: str,
        policy: Optional[ExecutionPolicy] = None,
    ) -> list[str]:
        """Construct process command arguments enforcing the execution policy."""
        pass
