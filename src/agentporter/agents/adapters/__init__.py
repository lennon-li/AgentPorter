"""Agent adapters package."""

from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.adapters.codex_identity import CodexReviewAdapter, CodexImplementationAdapter, CodexResearchAdapter
from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter, OpenCodeFreeAdapter
from agentporter.agents.adapters.copilot import CopilotAdapter
from agentporter.agents.adapters.agy import AgyAdapter

__all__ = [
    "AgentAdapter",
    "CodexAdapter",
    "CodexReviewAdapter",
    "CodexImplementationAdapter",
    "CodexResearchAdapter",
    "ClaudeAdapter",
    "OpenCodeAdapter",
    "OpenCodeFreeAdapter",
    "CopilotAdapter",
    "AgyAdapter",
]
