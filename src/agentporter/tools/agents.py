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
        reasoning_effort: Optional[str] = None
    ) -> dict:
        """Dispatch an authorized CLI agent worker asynchronously."""
        return broker.dispatch_agent(
            agent=agent,
            task=task,
            workspace_id=workspace_id,
            purpose=purpose,
            model=model,
            reasoning_effort=reasoning_effort
        )

    return list_agents, dispatch_agent
