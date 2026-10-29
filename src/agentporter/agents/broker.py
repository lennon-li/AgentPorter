"""Agent broker orchestrating CLI agent discovery and delegation."""

from __future__ import annotations

import os
import logging
import re
import sys
import yaml
import copy
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Dict
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.adapters.codex_identity import JaxAdapter, LizAdapter, ProfAdapter
from agentporter.agents.adapters.copilot import CopilotAdapter, PhilAdapter
from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter, WeiAdapter
from agentporter.agents.adapters.agy import AgyAdapter
from agentporter.agents.policy import ExecutionPolicy
from agentporter.qman import shadow_consult, record_shadow
from agentporter.workspaces.registry import WorkspaceRegistry

if TYPE_CHECKING:
    from agentporter.tools.jobs import JobManager

logger = logging.getLogger("agentporter.agents.broker")

PROHIBITED_MODEL_PREFIXES = ("gpt-5.6",)
OPENAI_FALLBACK_MODEL = "gpt-6-luna"

class AgentBroker:
    """Manages agent discovery, capability enforcement, and asynchronous delegation."""

    def __init__(
        self,
        workspace_registry: WorkspaceRegistry,
        job_manager: JobManager,
        *,
        config_dir: Optional[str | os.PathLike] = None,
        parallel_search_enabled: bool = False,
        production_no_host_detection: bool = False,
    ):
        if type(production_no_host_detection) is not bool:
            raise ValueError('Production discovery flag must be boolean')
        self.production_no_host_detection = production_no_host_detection
        self.workspace_registry = workspace_registry
        self.job_manager = job_manager
        self.parallel_search_enabled = parallel_search_enabled
        # An explicitly selected AgentPorter configuration takes precedence
        # over host environment or HOME, including for CLI diagnostics/tests.
        self.config_dir = os.fspath(config_dir) if config_dir is not None else None
        self.adapters: Dict[str, AgentAdapter] = {
            "codex": CodexAdapter(),
            "jax": JaxAdapter(),
            "liz": LizAdapter(),
            "prof": ProfAdapter(),
            "phil": PhilAdapter(),
            "claude": ClaudeAdapter(),
            "opencode": OpenCodeAdapter(),
            "wei": WeiAdapter(),
            "agy": AgyAdapter(),
            "ming": ClaudeAdapter(),
            "argie": AgyAdapter(),
        }
        self.adapters["ming"].alias = "Ming"
        self.adapters["argie"].alias = "Argie"
        self.development_runtime = None
        if self.job_manager is not None:
            self.job_manager.development_runtime = None
        runtime_config = Path(self.config_dir or os.environ.get("AGENTPORTER_CONFIG_DIR") or (
            Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "agentporter"
        ))
        if self.job_manager is not None and (runtime_config / "development-runtime.yaml").is_file():
            if self.production_no_host_detection:
                raise PermissionError('Production cannot initialize development workers')
            from agentporter.agents.development import DevelopmentRuntime
            self.development_runtime = DevelopmentRuntime(
                runtime_config, job_manager.state_dir, workspace_registry
            )
            self.job_manager.development_runtime = self.development_runtime

    def _runtime_adapter(self, agent: str, adapter: AgentAdapter) -> AgentAdapter:
        if self.development_runtime is not None:
            executable = self.development_runtime.executable_for(agent)
            if executable:
                adapter = copy.copy(adapter)
                adapter.executable_override = executable
        return adapter

    def _detection(self, agent: str, adapter: AgentAdapter, *, runtime_status: dict | None = None) -> dict:
        if self.development_runtime is None:
            if self.production_no_host_detection:
                # Even --version/config detection is host execution. Production
                # reports static registration only until a confined tier exists.
                return {'executable': None, 'is_installed': False, 'cli_version': 'unknown',
                        'provider': adapter.provider or 'unknown',
                        'configured_model': 'unknown', 'reasoning_effort': 'unknown'}
            return adapter.detect()
        # Never execute even --version on the host when confinement failed.
        status = self._runtime_status(agent, adapter, None) if runtime_status is None else runtime_status
        return {
            "executable": status.get("worker_executable"),
            "is_installed": bool(status.get("worker_executable") or status.get("delegatable")),
            "cli_version": status.get("cli_version", "unknown"),
            "provider": status.get("provider") or adapter.provider,
            "configured_model": status.get("configured_model", "unknown"),
            "reasoning_effort": status.get("reasoning_effort", "unknown"),
        }

    def _runtime_status(self, agent: str, adapter: AgentAdapter, detection: dict | None) -> dict:
        if self.development_runtime is None:
            return {
                "delegatable": False,
                "confinement_status": "blocked_pending_os_confinement",
                "availability_reason": "No development confinement runtime configured",
            }
        try:
            return self.development_runtime.status(agent, adapter, detection)
        except Exception as exc:
            logger.warning("Development runtime check failed for %s: %s", agent, exc)
            return {
                "delegatable": False,
                "confinement_status": "blocked_runtime_verification_failed",
                "availability_reason": str(exc),
            }

    def register_adapter(self, adapter: AgentAdapter) -> None:
        self.adapters[adapter.name.lower()] = adapter

    def _configured_workers(self) -> tuple[dict, dict]:
        """Apply private identity metadata to existing adapters, without new controls."""
        # Explicit private identities retain precedence over built-in aliases.
        adapters, identities = dict(self.adapters), {}
        config_dir = self.config_dir or os.environ.get("AGENTPORTER_CONFIG_DIR") or os.path.join(
            os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "agentporter"
        )
        try:
            with open(os.path.join(config_dir, "agents.yaml"), encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
        except FileNotFoundError:
            return adapters, identities
        if not isinstance(document, dict) or set(document) != {"agents"}:
            raise ValueError("agents.yaml must contain an agents mapping")
        definitions = document["agents"]
        if not isinstance(definitions, dict):
            raise ValueError("agents.yaml agents must be a mapping")
        for name, spec in definitions.items():
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
                raise ValueError("agent identity names must be lowercase identifiers")
            if not isinstance(spec, dict) or set(spec) - {"runtime", "alias", "description", "persona_reference"}:
                raise ValueError("agent identities accept only runtime, alias, description, persona_reference")
            runtime = spec.get("runtime")
            if not isinstance(runtime, str) or runtime not in self.adapters:
                raise ValueError("agent identity runtime must name an existing adapter")
            adapter = self.adapters[runtime]
            if name in adapters and adapters[name] is not adapter and name not in {"ming", "argie"}:
                # Older installations defined Wei/Prof before they became
                # built-ins. Accept their old metadata, but NEVER replace
                # the built-in adapters' account or model restrictions.
                if (name, runtime) in {("wei", "opencode"), ("prof", "codex")}:
                    adapter = adapters[name]
                else:
                    raise ValueError("agent identities cannot redirect an existing adapter")
            alias = spec.get("alias", name)
            role = spec.get("description", adapter.description)
            persona = spec.get("persona_reference", "")
            if any(not isinstance(value, str) for value in (alias, role, persona)) or not alias.strip():
                raise ValueError("agent identity metadata must be text with a nonempty alias")
            cli = ("codex" if isinstance(adapter, CodexAdapter) else
                   "opencode" if isinstance(adapter, OpenCodeAdapter) else adapter.name)
            adapters[name] = adapter
            identities[name] = (cli, alias, role, persona)
        return adapters, identities

    @staticmethod
    def _model_is_prohibited(model: str) -> bool:
        normalized = (model or "").strip().lower()
        return any(normalized.startswith(prefix) for prefix in PROHIBITED_MODEL_PREFIXES)

    @classmethod
    def _resolve_default_model(cls, provider: str, configured_model: str) -> str:
        if not cls._model_is_prohibited(configured_model):
            return configured_model
        if (provider or "").strip().lower() == "openai":
            return OPENAI_FALLBACK_MODEL
        raise ValueError(
            f"Configured model '{configured_model}' is prohibited by AgentPorter delegation policy "
            f"and cannot be remapped safely for provider '{provider}'."
        )

    def list_agents(self) -> list[dict]:
        """List installed/known CLI workers without claiming unverified runtime models."""
        results = []
        adapters, identities = self._configured_workers()
        for key, adapter in adapters.items():
            adapter = self._runtime_adapter(key, adapter)
            runtime, alias, role, _ = identities.get(
                key, ("codex" if isinstance(adapter, CodexAdapter) else "opencode" if isinstance(adapter, OpenCodeAdapter) else
                "claude" if isinstance(adapter, ClaudeAdapter) else
                "agy" if isinstance(adapter, AgyAdapter) else key,
                      adapter.alias or key, adapter.description, "")
            )
            runtime_status = (self._runtime_status(key, adapter, None)
                              if self.development_runtime is not None else None)
            detection = self._detection(key, adapter, runtime_status=runtime_status)
            configured_model = detection.get("configured_model") or "unknown"
            reasoning = detection.get("reasoning_effort") or "unknown"
            provider = detection.get("provider") or adapter.provider or "unknown"
            routing_blocked = False
            try:
                effective_model = self._resolve_default_model(provider, configured_model)
            except ValueError as exc:
                routing_blocked = True
                effective_model = None
                routing_note = f" (blocked: {exc})"
            else:
                routing_note = ""
                if effective_model != configured_model:
                    routing_note = f" (policy override from {configured_model})"
            route_target = effective_model or "BLOCKED"
            if runtime_status is None:
                runtime_status = self._runtime_status(key, adapter, detection)
            delegatable = bool(runtime_status.get("delegatable") and not routing_blocked)
            if routing_blocked:
                runtime_status["availability_reason"] = routing_note.strip()
            results.append({
                # CLI discovery is not an authorization to launch the worker.
                **runtime_status,
                "delegatable": delegatable,
                "agent": key,
                "worker_cli": runtime,
                "alias": alias,
                "provider": provider,
                "configured_model": configured_model,
                "default_routing": f"{provider} -> {route_target}{routing_note}",
                "actual_model_used": "unknown (resolved only from trusted runtime metadata)",
                "reasoning_level": reasoning,
                "cli_version": detection.get("cli_version", "unknown"),
                "available": bool(detection.get("is_installed") and not routing_blocked and (
                    self.development_runtime is None or delegatable
                )),
                "capabilities": adapter.capabilities(),
                "description": role,
                "isolation_note": ("Verified development OS confinement with separate worker credentials"
                                   if delegatable else "Delegation blocked: OS confinement unavailable"),
                "supports_read_only": bool(adapter.supports_read_only or delegatable),
                "supports_model_override": adapter.supports_model_override,
                "supports_reasoning_override": adapter.supports_reasoning_override,
                "effective_model": effective_model,
                "default_model": effective_model,
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
        allow_commit: bool = False,
        allow_push: bool = False,
        read_only: bool = True,
    ) -> dict:
        """Dispatch an authorized worker agent asynchronously with enforceable controls."""
        agent_key = agent.lower().strip()
        adapters, identities = self._configured_workers()
        if agent_key not in adapters:
            raise ValueError(
                f"Unknown agent: '{agent}'. Authorized agents: {list(adapters.keys())}"
            )

        adapter = self._runtime_adapter(agent_key, adapters[agent_key])
        detection = self._detection(agent_key, adapter)

        ws = self.workspace_registry.get(workspace_id)
        if not ws.allow_agent_dispatch:
            raise PermissionError(f"Workspace '{workspace_id}' does not allow agent dispatch")
        runtime_status = self._runtime_status(agent_key, adapter, detection)
        confined = bool(runtime_status.get("delegatable"))
        if self.development_runtime is not None and not confined:
            raise PermissionError(runtime_status.get("availability_reason") or "Development confinement unavailable")
        if not detection.get("is_installed"):
            raise RuntimeError(f"Agent '{agent_key}' is not installed or available on host")
        # Never downgrade to start_raw_job if a backend is missing or errors.
        # The future backend must enforce this exact policy.
        # The host-user Popen path has no kernel-enforced boundary; CLI flags
        # and prompt policy cannot prevent publication or reading host secrets.
        # Re-enable only via a verified, broker-owned confined launch method.
        if not callable(getattr(self.job_manager, "start_confined_agent_job", None)):
            raise PermissionError(
                "Delegated execution blocked: OS-confined agent launcher is not installed"
            )
        if allow_commit or allow_push:
            raise PermissionError("Delegated commit/push require a separate operator-verified approval; caller booleans are insufficient")
        if not read_only and getattr(self.workspace_registry, 'workspace_policy', None) is not None:
            from agentporter.task_authorization import ACTIVE_GRANT
            grant = ACTIVE_GRANT.get()
            if (grant is None or grant.claims.get('workspace_root') != ws.path
                    or grant.claims.get('agent') != agent_key
                    or 'write' not in grant.claims.get('operations', [])):
                raise PermissionError('Writable delegation requires verified task authority')
        effective_read_only = read_only or not ws.writable
        if (allow_commit or allow_push) and effective_read_only:
            raise PermissionError("Commit/push cannot be authorized for a read-only dispatch")
        if effective_read_only and not adapter.supports_read_only and not confined:
            raise PermissionError(
                f"Agent '{agent_key}' cannot be dispatched read-only in workspace "
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

        policy = ExecutionPolicy.for_workspace(
            writable=ws.writable and not effective_read_only,
            allow_commit=allow_commit,
            allow_push=allow_push,
        )

        explicit_model = (model or "").strip()
        if explicit_model and self._model_is_prohibited(explicit_model):
            raise ValueError(
                f"Model '{explicit_model}' is prohibited by AgentPorter delegation policy. "
                f"Use '{OPENAI_FALLBACK_MODEL}' or another allowed worker model."
            )
        effective_model = explicit_model or self._resolve_default_model(provider, configured_model)
        requested_model = (
            effective_model
            if explicit_model or effective_model != configured_model
            else ""
        )

        # Git cleanliness is not probed with host-user subprocesses from
        # this broker. The future confined worker backend may report a verified
        # snapshot or the client may request an independently sandboxed git_status
        # action. Unknown is safer than host execution or an invented "clean".
        git_clean = None

        runtime, alias, role, persona = identities.get(
            agent_key, ("codex" if isinstance(adapter, CodexAdapter) else "opencode" if isinstance(adapter, OpenCodeAdapter) else
            "claude" if isinstance(adapter, ClaudeAdapter) else
            "agy" if isinstance(adapter, AgyAdapter) else agent_key,
                        adapter.alias or agent_key, adapter.description, "")
        )
        identity = ""
        if agent_key in identities:
            identity = (
                f"Dispatch identity: {alias}\nRole: {role}\n"
                + (f"Persona reference: {persona}\n" if persona else "") +
                "Read that persona if available; do not claim it was loaded unless read. "
                "Follow project instructions and the execution policy below. "
                "Identity and role do not expand the authorized task or permissions.\n"
            )
        packet = identity + (
            "Permission Level: 1\n"
            "Interaction Mode: AUTONOMOUS\n"
            f"Authorization: {'MAY MODIFY FILES WITHIN SCOPE' if policy.workspace_write else 'READ-ONLY'}\n"
            "Step budget: 30\n"
            f"Project Root: {'/workspace' if confined else ws.path}\n"
            f"{policy.packet_text()}"
            f"Purpose: {purpose or 'Worker delegation via AgentPorter'}\n"
            f"Task:\n{task}\n"
        )

        if confined and runtime_status.get("shared_obsidian_path"):
            # Documentation is optional task context, never an authority upgrade.
            packet += ("\nApproved read-only shared Obsidian skill index: "
                       "/opt/agentporter/shared/obsidian/AgentSystem/agent-memory/skills/INDEX.md\n"
                       "Read only the skill needed for the task. The tool inventory is "
                       "/opt/agentporter/shared/obsidian/tools/agent-tool-policy.json. "
                       "Inventory membership does not grant executable availability or "
                       "permission to install or run privileged tools.\n")

        # Only explicit caller overrides are passed as overrides. Local CLI defaults/config
        # remain "configured", not misreported as a request made by AgentPorter.
        requested_reasoning = (reasoning_effort or "").strip()

        controls = (
            {"policy": policy}
            if isinstance(adapter, (CodexAdapter, CopilotAdapter, ClaudeAdapter, OpenCodeAdapter))
            else {"writable": policy.workspace_write}
        )
        if confined and not adapter.supports_read_only:
            # The read-only mount is enforced by the OS; these CLI adapters
            # only know how to request an edit-capable interaction mode.
            controls = {"writable": True}
        search_enabled = self.parallel_search_enabled and (
            agent_key in {"jax", "liz", "prof"} and isinstance(adapter, CodexAdapter)
            or agent_key == "phil" and isinstance(adapter, PhilAdapter)
            or agent_key == "wei" and isinstance(adapter, WeiAdapter)
        )
        if isinstance(adapter, CopilotAdapter):
            controls["parallel_search_enabled"] = search_enabled
        if confined and isinstance(adapter, OpenCodeAdapter):
            # Legacy profile construction probes host --version and reads host
            # credentials. The development runtime owns the isolated profile.
            executable = runtime_status.get("worker_executable")
            if not executable:
                raise PermissionError("Development runtime did not verify the OpenCode executable")
            cmd = [executable, "run", "--agent", "dispatch"]
            if requested_model:
                cmd.extend(["-m", requested_model])
            cmd.append(packet)
        else:
            cmd = adapter.build_argv(
                workspace_path=ws.path,
                packet=packet,
                model=requested_model,
                reasoning_effort=requested_reasoning,
                **controls,
            )
        if isinstance(adapter, CodexAdapter):
            # Import lazily to prevent duplicate sys.modules entry on -m launch.
            from agentporter.agents.isolated_codex import safe_launcher_environment

            # Force a temporary, screened CODEX_HOME and verify the actual MCP
            # roster before the CLI can start. The user's home config can
            # contain mutating MCP tools and inherited network permissions.
            source_home = getattr(adapter, "codex_home", None) or (
                os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")
            )
            if cmd[:1] == ["env"] and len(cmd) > 2 and cmd[1].startswith("CODEX_HOME="):
                cmd = cmd[2:]
            if not cmd or not os.path.isabs(cmd[0]):
                raise RuntimeError("Codex executable path must be absolute")
            cmd = [
                sys.executable, "-I", "-m", "agentporter.agents.isolated_codex",
                "--source-home", source_home, "--workspace", ws.path,
                *(["--parallel-search"] if search_enabled else []),
                "--", *cmd,
            ]
            launch_env = safe_launcher_environment(source_home)
        elif isinstance(adapter, OpenCodeAdapter) and not confined:
            # Preserve upstream's dedicated Wei/OpenCode ephemeral permissions
            # and credential handling without allowing them to inherit defaults.
            launch_env = adapter.runtime_env(
                workspace_path=ws.path, policy=policy,
                parallel_search_enabled=search_enabled,
            )
        else:
            launch_env = None

        qman_shadow = shadow_consult(agent_key, effective_model, self.workspace_registry)
        try:
            job_id = self.job_manager.start_confined_agent_job(
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
                policy=policy,
                env=launch_env,
            )
        except Exception:
            record_shadow(qman_shadow)
            raise
        record_shadow(qman_shadow, job_id=job_id, launched=True)

        return {
            "worker_cli": runtime,
            "provider": provider,
            "configured_model": configured_model,
            "requested_model": requested_model,
            "actual_model": "unknown",
            "reasoning_level": requested_reasoning or configured_reasoning,
            "cli_version": cli_ver,
            "job_id": job_id,
            "dispatch_id": job_id,
            "exit_status": None,
            "duration": 0.0,
            "status": "running",
            "selected_agent": agent_key,
            "alias": alias,
            "model": effective_model,
            "effective_model": effective_model,
            "thinking_level": requested_reasoning or configured_reasoning,
            "workspace_id": workspace_id,
            "read_only": not policy.workspace_write,
            "git_clean_at_dispatch": git_clean,
            "confinement_status": runtime_status["confinement_status"],
            "runtime_profile": runtime_status.get("runtime_profile"),
        }
