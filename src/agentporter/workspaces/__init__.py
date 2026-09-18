"""Workspaces module for AgentPorter."""

from agentporter.workspaces.paths import validate_workspace_path
from agentporter.workspaces.registry import WorkspaceRegistry

__all__ = ["validate_workspace_path", "WorkspaceRegistry"]
