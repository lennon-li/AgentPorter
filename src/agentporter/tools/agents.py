"""Agent broker delegation tools."""

from typing import Optional
from agentporter.agents.broker import AgentBroker
from agentporter.agents.roster import PUBLIC_AGENT_IDS, public_agent_inventory


def create_agent_tools(broker: AgentBroker):
    def list_agents() -> list[dict]:
        """List the seven named workers; generic runtimes remain internal."""
        return public_agent_inventory(broker.list_agents())

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
        """Dispatch an approved named worker; read-only by default."""
        if agent.lower().strip() not in PUBLIC_AGENT_IDS:
            raise PermissionError(
                "Unapproved public agent identity: use one of "
                + ", ".join(sorted(PUBLIC_AGENT_IDS))
            )
        selected = next(item for item in public_agent_inventory(broker.list_agents())
                        if item["agent"] == agent.lower().strip())
        # Report the same verified launch blocker exposed by inventory.
        detail = "; ".join(
            str(selected[key]) for key in ("confinement_status", "availability_reason")
            if selected.get(key)
        )
        suffix = ("; " + detail) if detail else ""
        if not selected.get("registered") or not selected.get("available"):
            raise PermissionError(
                "Named agent is unavailable, unregistered, or misrouted: "
                + agent.lower().strip() + "; no alternate runtime will be substituted" + suffix
            )
        if selected.get("delegatable") is False:
            raise PermissionError(
                "Named agent registered but delegation blocked: "
                + str(selected.get("confinement_status") or "OS confinement unavailable")
                + ("; " + str(selected["availability_reason"]) if selected.get("availability_reason") else "")
            )
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
