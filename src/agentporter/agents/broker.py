"""Agent broker orchestrating CLI agent discovery and delegation."""

import os
import subprocess
import logging
from typing import Optional, Dict
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.adapters.codex_identity import JaxAdapter, LizAdapter
from agentporter.agents.adapters.copilot import CopilotAdapter
from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter
from agentporter.agents.adapters.agy import AgyAdapter
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.tools.jobs import JobManager

logger = logging.getLogger("agentporter.agents.broker")


class AgentBroker:
    """Manages agent discovery, health inspection, and asynchronous delegation."""

    def __init__(self, workspace_registry: WorkspaceRegistry, job_manager: JobManager):
        self.workspace_registry = workspace_registry
        self.job_manager = job_manager
        self.adapters: Dict[str, AgentAdapter] = {
            "codex": CodexAdapter(),
            "jax": JaxAdapter(),
            "liz": LizAdapter(),
            "claude": ClaudeAdapter(),
            "opencode": OpenCodeAdapter(),
            "copilot": CopilotAdapter(),
            "agy": AgyAdapter(),
        }

    def register_adapter(self, adapter: AgentAdapter) -> None:
        self.adapters[adapter.name.lower()] = adapter

    def list_agents(self) -> list[dict]:
        """List available CLI agent workers, distinguishing configured/default routing from actual model."""
        results = []
        for key, adapter in self.adapters.items():
            detection = adapter.detect()
            results.append({
                "agent": key,
                "worker_cli": key,
                "alias": adapter.alias,
                "provider": detection["provider"],
                "configured_model": detection["configured_model"],
                "default_routing": f"{detection['provider']} -> {detection['configured_model']}",
                "actual_model_used": "unknown (resolved at runtime per dispatch)",
                "reasoning_level": detection["reasoning_effort"],
                "cli_version": detection["cli_version"],
                "available": detection["is_installed"],
                "capabilities": adapter.capabilities(),
                "description": adapter.description,
                "isolation_note": "Runs with host user credentials; scoped by cwd and control block.",
                "effective_model": detection["configured_model"],
                "default_model": detection["configured_model"],
            })
        return results

    def dispatch_agent(
        self,
        agent: str,
        task: str,
        workspace_id: str,
        purpose: str = "",
        model: Optional[str] = None,
        reasoning_effort: Optional[str] = None,
    ) -> dict:
        """Dispatch an authorized worker agent asynchronously."""
        agent_key = agent.lower().strip()
        if agent_key not in self.adapters:
            raise ValueError(f"Unknown agent: '{agent}'. Authorized agents: {list(self.adapters.keys())}")

        adapter = self.adapters[agent_key]
        detection = adapter.detect()
        if not detection["is_installed"]:
            raise RuntimeError(f"Agent '{agent_key}' is not installed or available on host")

        ws = self.workspace_registry.get(workspace_id)
        ws_path = ws.path

        # Preflight git check
        git_clean = True
        git_dir = os.path.join(ws_path, ".git")
        if os.path.exists(git_dir):
            try:
                res = subprocess.run(["git", "status", "--short"], cwd=ws_path, capture_output=True, text=True, timeout=5)
                if res.stdout.strip():
                    git_clean = False
            except Exception:
                pass

        effective_model = model or detection["configured_model"]
        effective_effort = reasoning_effort or detection["reasoning_effort"]
        cli_ver = detection["cli_version"]
        provider = detection["provider"]

        # Structured control packet
        packet = (
            f"Permission Level: 1\n"
            f"Interaction Mode: AUTONOMOUS\n"
            f"Authorization: {'MAY MODIFY FILES WITHIN SCOPE' if ws.writable else 'READ-ONLY'}\n"
            f"Step budget: 30\n"
            f"Project Root: {ws_path}\n"
            f"Purpose: {purpose or 'Worker delegation via AgentPorter'}\n"
            f"Task:\n{task}\n"
        )

        cmd = adapter.build_argv(
            workspace_path=ws_path,
            packet=packet,
            model=effective_model,
            reasoning_effort=effective_effort
        )

        job_id = self.job_manager.start_raw_job(
            workspace_id=workspace_id,
            workspace_path=ws_path,
            cmd=cmd,
            agent=agent_key,
            provider=provider,
            model=effective_model,
            requested_model=effective_model,
            reasoning_level=effective_effort,
            cli_version=cli_ver,
            timeout_seconds=900
        )

        return {
            "dispatch_id": job_id,
            "job_id": job_id,
            "worker_cli": agent_key,
            "provider": provider,
            "requested_model": effective_model,
            "actual_model": "unknown",
            "reasoning_level": effective_effort,
            "cli_version": cli_ver,
            "exit_status": None,
            "duration": 0.0,
            # Backward compatibility fields
            "status": "running",
            "selected_agent": agent_key,
            "alias": adapter.alias,
            "model": effective_model,
            "thinking_level": effective_effort,
            "workspace_id": workspace_id,
            "git_clean_at_dispatch": git_clean,
        }
