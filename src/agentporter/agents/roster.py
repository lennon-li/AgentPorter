"""The seven operator-approved public identities, distinct from CLI runtimes.

Do not infer that a named worker is available merely because its runtime exists.
Never substitute a different provider/model when the selected identity is unavailable.
"""

from __future__ import annotations

PUBLIC_AGENT_ROSTER = (
    ("codex_review", "codex_review", "codex"),
    ("codex_impl", "codex_impl", "codex"),
    ("codex_research", "codex_research", "codex"),
    ("copilot_agent", "copilot_agent", "copilot_agent"),
    ("opencode_free", "opencode_free", "opencode"),
    ("claude_agent", "claude_agent", "claude"),
    ("agy_agent", "agy_agent", "agy"),
)
PUBLIC_AGENT_IDS = frozenset(entry[0] for entry in PUBLIC_AGENT_ROSTER)


def public_agent_inventory(discovered: list[dict]) -> list[dict]:
    """Return exactly the named roster; preserve truthful discovery state.

    Unconfigured identities are shown as unavailable rather than borrowing
    the generic runtime, switching providers, or silently disappearing.
    """
    found = {entry["agent"]: entry for entry in discovered}
    result = []
    for agent_id, alias, worker_cli in PUBLIC_AGENT_ROSTER:
        if agent_id in found:
            entry = dict(found[agent_id])
            entry["registered"] = True
            if entry.get("worker_cli") != worker_cli:
                entry["available"] = False
                entry["routing_error"] = (
                    "Named identity runtime mismatch: expected "
                    + worker_cli + ", got " + str(entry.get("worker_cli"))
                )
        else:
            entry = {
                "agent": agent_id,
                "alias": alias,
                "worker_cli": worker_cli,
                "provider": "unknown",
                "configured_model": "unknown",
                "effective_model": "unknown",
                "actual_model_used": "unknown",
                "available": False,
                "registered": False,
                "capabilities": [],
                "supports_read_only": False,
                "description": "Named identity is not configured; no runtime fallback.",
            }
        result.append(entry)
    return result
