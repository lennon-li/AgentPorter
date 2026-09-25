"""Agent broker orchestrating CLI agent discovery and delegation."""

import os
import subprocess
import logging
from typing import Optional, Dict
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter
from agentporter.agents.adapters.agy import AgyAdapter
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.tools.jobs import JobManager

logger = logging.getLogger("agentporter.agents.broker")


class AgentBroker:
    """Manages agent discovery, capability enforcement, and asynchronous delegation."""

    def __init__(self, workspace_registry: WorkspaceRegistry, job_manager: JobManager):
        self.workspace_registry = workspace_registry
        self.job_manager = job_manager
        self.adapters: Dict[str, AgentAdapter] = {
            "codex": CodexAdapter(),
            "claude": ClaudeAdapter(),
            "opencode": OpenCodeAdapter(),
            "agy": AgyAdapter(),
        }

    def register_adapter(self, adapter: AgentAdapter) -> None:
        self.adapters[adapter.name.lower()] = adapter

    def list_agents(self) -> list[dict]:
        """List installed/known CLI workers without claiming unverified runtime models."""
        results = []
        for key, adapter in self.adapters.items():
            detection = adapter.detect()
            configured_model = detection.get("configured_model") or "unknown"
            reasoning = detection.get("reasoning_effort") or "unknown"
            provider = detection.get("provider") or adapter.provider or "unknown"
            results.append({
                "agent": key,
                "worker_cli": key,
                "alias": adapter.alias or key,
                "provider": provider,
                "configured_model": configured_model,
                "default_routing": f"{provider} -> {configured_model}",
                "actual_model_used": "unknown (resolved only from trusted runtime metadata)",
                "reasoning_level": reasoning,
                "cli_version": detection.get("cli_version", "unknown"),
                "available": bool(detection.get("is_installed")),
                "capabilities": adapter.capabilities(),
                "description": adapter.description,
                "isolation_note": "Runs with host user credentials; not kernel-isolated by AgentPorter.",
                "supports_read_only": adapter.supports_read_only,
                "supports_model_override": adapter.supports_model_override,
                "supports_reasoning_override": adapter.supports_reasoning_override,
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
        """Dispatch an authorized worker agent asynchronously with enforceable controls."""
        agent_key = agent.lower().strip()
        if agent_key not in self.adapters:
            raise ValueError(
                f"Unknown agent: '{agent}'. Authorized agents: {list(self.adapters.keys())}"
            )

        adapter = self.adapters[agent_key]
        detection = adapter.detect()
        if not detection.get("is_installed"):
            raise RuntimeError(f"Agent '{agent_key}' is not installed or available on host")

        ws = self.workspace_registry.get(workspace_id)
        if not ws.allow_agent_dispatch:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow agent dispatch")
        if not ws.writable and not adapter.supports_read_only:
            raise PermissionError(
                f"Agent '{agent_key}' cannot be dispatched to read-only workspace "
                f"'{workspace_id}' because this adapter cannot enforce read-only execution"
            )
        if model and not adapter.supports_model_override:
            raise ValueError(f"Agent '{agent_key}' does not support enforceable model override")
        if reasoning_effort and not adapter.supports_reasoning_override:
            raise ValueError(f"Agent '{agent_key}' does not support enforceable reasoning override")

        configured_model = detection.get("configured_model") or "unknown"
        configured_reasoning = detection.get("reasoning_effort") or "unknown"
        provider = detection.get("provider") or adapter.provider or "unknown"
        cli_ver = detection.get("cli_version", "unknown")

        git_clean = True
        git_dir = os.path.join(ws.path, ".git")
        if os.path.exists(git_dir):
            try:
                env = os.environ.copy()
                env.update({
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_PAGER": "cat",
                    "GIT_EXTERNAL_DIFF": "",
                })
                res = subprocess.run(
                    ["git", "-c", "core.fsmonitor=false", "status", "--short"],
                    cwd=ws.path,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=env,
                )
                git_clean = not bool(res.stdout.strip())
            except Exception:
                pass

        packet = (
            "Permission Level: 1\n"
            "Interaction Mode: AUTONOMOUS\n"
            f"Authorization: {'MAY MODIFY FILES WITHIN SCOPE' if ws.writable else 'READ-ONLY'}\n"
            "Step budget: 30\n"
            f"Project Root: {ws.path}\n"
            f"Purpose: {purpose or 'Worker delegation via AgentPorter'}\n"
            f"Task:\n{task}\n"
        )

        # Only explicit caller overrides are passed as overrides. Local CLI defaults/config
        # remain "configured", not misreported as a request made by AgentPorter.
        requested_model = (model or "").strip()
        requested_reasoning = (reasoning_effort or "").strip()

        cmd = adapter.build_argv(
            workspace_path=ws.path,
            packet=packet,
            model=requested_model,
            reasoning_effort=requested_reasoning,
            writable=ws.writable,
        )

        job_id = self.job_manager.start_raw_job(
            workspace_id=workspace_id,
            workspace_path=ws.path,
            cmd=cmd,
            agent=agent_key,
            provider=provider,
            model=configured_model,
            requested_model=requested_model,
            reasoning_level=requested_reasoning or configured_reasoning,
            cli_version=cli_ver,
            timeout_seconds=900,
        )

        return {
            "worker_cli": agent_key,
            "provider": provider,
            "configured_model": configured_model,
            "requested_model": requested_model,
            "actual_model": "unknown",
            "reasoning_level": requested_reasoning or configured_reasoning,
            "cli_version": cli_ver,
            "job_id": job_id,
            "exit_status": None,
            "duration": 0.0,
            "status": "running",
            "selected_agent": agent_key,
            "alias": adapter.alias or agent_key,
            "model": configured_model,
            "thinking_level": requested_reasoning or configured_reasoning,
            "workspace_id": workspace_id,
            "git_clean_at_dispatch": git_clean,
        }
