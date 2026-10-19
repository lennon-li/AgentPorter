"""Agent broker delegation tools."""

from typing import Optional
from agentporter.agents.broker import AgentBroker


def create_agent_tools(broker: AgentBroker):
    def list_agents() -> list[dict]:
        """List available CLI agent workers (Codex, Claude, OpenCode, Agy)."""
        return broker.list_agents()

    def dispatch_agent(
        agent: str,
        task: str,
        workspace_id: str,
        purpose: str = "",
        model: Optional[str] = None,
        reasoning_effort: Optional[str] = None,
        allow_commit: bool = False,
        allow_push: bool = False,
        read_only: bool = True,
    ) -> dict:
        """Dispatch a worker asynchronously; defaults to enforced read-only mode."""
        return broker.dispatch_agent(
            agent=agent,
            task=task,
            workspace_id=workspace_id,
            purpose=purpose,
            model=model,
            reasoning_effort=reasoning_effort,
            allow_commit=allow_commit,
            allow_push=allow_push,
            read_only=read_only,
        )

    return list_agents, dispatch_agent
