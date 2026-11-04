"""Base sandbox abstraction for AgentPorter."""

from abc import ABC, abstractmethod
from typing import Optional


class SandboxBackend(ABC):
    """Abstract sandbox backend contract."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this sandbox backend is supported and installed on host."""
        pass

    @abstractmethod
    def run(
        self,
        workspace_path: str,
        argv: list[str],
        cwd: str = "",
        timeout_seconds: int = 30,
        writable: bool = True,
        max_output_bytes: int = 100 * 1024,
    ) -> dict:
        """Execute command inside sandbox and return execution status dict."""
        pass
