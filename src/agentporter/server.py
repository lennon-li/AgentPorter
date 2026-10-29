"""Model Context Protocol (MCP) Streamable HTTP server for AgentPorter."""

import os
import sys
import time
import json
import logging
import functools
from contextlib import asynccontextmanager
from typing import Optional, Any, Literal
from logging.handlers import RotatingFileHandler
from starlette.types import ASGIApp
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE, TransportSecuritySettings
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentporter import __version__
from agentporter.deployinfo import deploy_info
from agentporter.config import Config
from agentporter.auth import RateLimiter
from agentporter.middleware import SecurityMiddleware
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager, TERMINAL_JOB_STATUSES
from agentporter.agents.broker import AgentBroker
from agentporter.agents.production_relay import (
    ALLOWED_OPS, JOB_RE, ProductionDelegationClient, read_relay_key,
    relay_upstream_workspaces, read_relay_scope, validate_dispatch, validate_job_request,
)
from agentporter.action_policy import OperatorActionPolicy
from agentporter.client_policy import PublicClientPolicy
from agentporter.resources import JobResources, JobCapacityError
from agentporter.scoped_https import ScopedPublicHTTPS, ScopedPublicHTTPSPolicy
from agentporter.tools.system import create_system_tools
from agentporter.tools.files import create_file_tools
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.git import create_git_tools
from agentporter.tools.artifacts import create_artifact_tools
from agentporter.tools.local_http import create_local_http_tool
from mcp.types import ToolAnnotations
from agentporter.tools.agents import create_agent_tools
from agentporter.tools.venkata import create_venkata_tool, Diagnostic
from agentporter.tools.venkata_transfer import create_venkata_transfer_tool, TransferSource, TransferDestination
from agentporter.tools.scinet import (
    create_scinet_login_tool,
    create_scinet_tool,
    ScinetDiagnostic,
    ScinetLoginAction,
)
from agentporter.tools.scinet_training import (
    create_scinet_training_tool,
    ScinetExperiment,
    ScinetLogKind,
)
from agentporter.tools.scinet_inference import (
    create_scinet_inference_preflight_tool,
    create_scinet_inference_provision_tool,
    create_scinet_inference_tools,
)

logger = logging.getLogger("agentporter.server")


def setup_logging(state_dir) -> None:
    """Configure structured rotating file and console logging."""
    log_dir = state_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "agentporter.log"

    root_logger = logging.getLogger("agentporter")
    root_logger.setLevel(logging.INFO)
    if root_logger.handlers:
        return

    file_handler = RotatingFileHandler(str(log_file), maxBytes=10 * 1024 * 1024, backupCount=5)
    try:
        os.chmod(log_file, 0o600)
    except OSError:
        pass
    file_formatter = logging.Formatter('{"time":"%(asctime)s", "level":"%(levelname)s", "event":%(message)s}')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    root_logger.addHandler(stream_handler)


def log_tool_event(tool_name: str, kwargs: dict, result: Any, duration: float, error: Optional[Exception] = None):
    event = {
        "tool": tool_name,
        "workspace_id": kwargs.get("workspace_id"),
        "path": kwargs.get("path"),
        "job_id": kwargs.get("job_id"),
        "agent": kwargs.get("agent"),
        "network_access": kwargs.get("network_access"),
        "duration_sec": round(duration, 4),
        "status": "error" if error else "ok",
        "error": str(error) if error else None,
    }
    if isinstance(result, (dict, list, str)):
        raw_len = len(json.dumps(result)) if not isinstance(result, str) else len(result)
        event["bytes_returned"] = raw_len
    try:
        logger.info(json.dumps(event))
    except Exception:
        pass


def _monitored_tool(tool_name: str, policy=None, client_policy=None):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(**kwargs):
            t0 = time.time()
            try:
                if policy is not None:
                    policy.check(tool_name, kwargs)
                if client_policy is not None:
                    client_policy.check(tool_name, kwargs)
                res = fn(**kwargs)
                if client_policy is not None:
                    res = client_policy.result(tool_name, kwargs, res)
                log_tool_event(tool_name, kwargs, res, time.time() - t0)
                return res
            except Exception as e:
                log_tool_event(tool_name, kwargs, None, time.time() - t0, error=e)
                raise
        return wrapper
    return decorator


def build_mcp_server(config: Config) -> tuple[MCPServer, dict]:
    """Construct MCPServer and register all standard tools."""
    setup_logging(config.state_dir)

    mcp = MCPServer(config.server.name)
    registry = WorkspaceRegistry(config.workspaces)
    sandbox = BubblewrapSandbox(
        config.state_dir,
        default_timeout_seconds=config.sandbox.default_timeout_seconds,
        max_timeout_seconds=config.sandbox.max_timeout_seconds,
        max_output_bytes=config.sandbox.max_output_bytes,
        transactional_writes=config.sandbox.workspace_transactions,
    )
    job_manager = JobManager(
        config.state_dir,
        max_log_bytes=config.sandbox.max_job_log_bytes,
        transactional_writes=config.sandbox.workspace_transactions,
    )
    agent_broker = AgentBroker(
        registry, job_manager, config_dir=getattr(config, "config_dir", None),
        parallel_search_enabled=getattr(getattr(config, "parallel_search", None), "enabled", False),
    )

    # The same decorated callables are used by MCP and REST. An operator's
    # protected mode file is loaded at startup, not from an agent request.
    runtime = agent_broker.development_runtime
    runtime_settings = runtime._config() if runtime else {}
    required = runtime_settings.get('public_client_policy_required') is True
    client_policy = PublicClientPolicy(config.config_dir, config.state_dir, registry, required=required)
    if required and client_policy.internal_key is None:
        raise PermissionError('Hardened development startup requires a separate internal-client credential')
    from agentporter.resources import load_gateway_job_resources
    gateway_resources = load_gateway_job_resources(config.config_dir)
    if gateway_resources is not None and runtime is not None:
        raise PermissionError('Gateway and worker resource profiles cannot be combined')
    if gateway_resources is not None and client_policy.scopes is None:
        raise PermissionError('Gateway resource profile requires an explicit public-client policy')
    resource_settings = gateway_resources if gateway_resources is not None else runtime_settings.get('job_resources')
    if resource_settings is not None:
        resources = (JobResources(resource_settings, expected_service='agentporter-bcc-gateway.service')
                     if gateway_resources is not None else JobResources(resource_settings))
        job_manager.configure_resources(resources)
        sandbox.resources = resources
    if config.sandbox.workspace_transactions and sandbox.resources is None:
        raise PermissionError('Workspace transactions require hardened job resource supervision')

    def monitored_tool(tool_name: str):
        return _monitored_tool(tool_name, policy=operator_policy, client_policy=client_policy)

    # Instantiate tool sets
    _get_capabilities, _list_workspaces, _workspace_info = create_system_tools(
        registry, sandbox, tool_inventory=lambda: (
            tool.name for tool in mcp._tool_manager.list_tools()
        ),
    )
    (
        _list_files, _search_text, _read_file, _write_file,
        _apply_patch, _mkdir, _move_path, _trash_path
    ) = create_file_tools(
        registry, mutation_state_dir=(config.state_dir / 'workspace-transactions')
        if config.sandbox.workspace_transactions else None)
    # Owner-installed 0600 policy is the only route to public HTTPS metadata.
    # No policy file means the broker is disabled. No agent may install it.
    https_policy = ScopedPublicHTTPSPolicy(
        config.config_dir,
        workspace_roots=[row["path"] for row in registry.list_all()],
    )
    scoped_https = ScopedPublicHTTPS(https_policy)
    scoped_https.resources = job_manager.resources
    from agentporter.https_download import create_https_download_tool
    from agentporter.admission import synchronous_slot
    _https_download = create_https_download_tool(registry, https_policy, config.state_dir,
        resources=job_manager.resources, slot=lambda: synchronous_slot(job_manager))
    _exec_run, _exec_start = create_execution_tools(
        registry, sandbox, job_manager, scoped_https=scoped_https
    )
    from agentporter.git_commits import WorkspaceGitCommits
    approved_commits = (WorkspaceGitCommits(registry, sandbox, job_manager=job_manager)
                        if sandbox.transactional_writes and sandbox.resources is not None else None)
    from agentporter.git_remote_policy import load_owner_git_remotes
    from agentporter.git_pushes import ApprovedGitPushes
    from agentporter.git_fetches import ApprovedGitFetches
    remote_authority = load_owner_git_remotes(config.config_dir, registry, config.state_dir)
    approved_pushes = None  # Agents never publish, even with an old signed receipt.
    approved_fetches = None if remote_authority is None else ApprovedGitFetches(registry, sandbox, remote_authority, job_manager)
    operator_policy = OperatorActionPolicy(
        config.config_dir, workspace_roots=[row['path'] for row in registry.list_all()],
        approved_git_commits=approved_commits is not None, approved_git_pushes=approved_pushes is not None)
    git_tools = create_git_tools(registry, sandbox, approved_commits=approved_commits,
        approved_pushes=approved_pushes, approved_fetches=approved_fetches)
    _git_status = git_tools.git_status
    _git_diff = git_tools.git_diff
    _git_log = git_tools.git_log
    _git_show = git_tools.git_show
    _git_fetch = git_tools.git_fetch
    _git_pull = git_tools.git_pull
    _git_push = git_tools.git_push
    _git_commit = git_tools.git_commit
    _git_add = git_tools.git_add
    _git_branch = git_tools.git_branch
    _git_checkout = git_tools.git_checkout
    _list_artifacts, _read_artifact = create_artifact_tools(registry)
    _local_http_request = create_local_http_tool(registry)
    _list_agents, _dispatch_agent = create_agent_tools(agent_broker)
    delegation_relay_client = None
    # Production may call an independent service identity ONLY when the
    # operator installs an explicit narrow relay configuration and token.
    relay_allowed_workspaces = relay_upstream_workspaces(config.config_dir)
    if agent_broker.development_runtime is None and relay_allowed_workspaces:
        # Relay activation must not silently retain the legacy profile where
        # every authenticated client has unrestricted workspace tool access.
        # An explicit policy also supplies the separate dispatch_write grant.
        if client_policy.scopes is None:
            raise PermissionError("Production delegation relay requires an explicit public-client policy")
        relay_key = read_relay_key(config.config_dir)
        if relay_key == config.api_key:
            raise PermissionError("Relay credential must differ from general AgentPorter API key")
        if relay_key is None:
            raise PermissionError("Delegation upstream configured without dedicated relay key")
        workspace_paths = {
            item["workspace_id"]: item["path"] for item in registry.list_all()
            if (item["workspace_id"] in relay_allowed_workspaces
                and item["permissions"]["agent_dispatch"])
        }
        if set(workspace_paths) != set(relay_allowed_workspaces):
            raise PermissionError("Relay allowlist contains unauthorized production workspaces")
        write_scope = read_relay_scope(config.config_dir, writable=True)
        for name, path in write_scope.items():
            if (workspace_paths.get(name) != path or not registry.get(name).writable
                    or not {"dispatch", "write", "dispatch_write"} <= client_policy.scopes.get(name, ())):
                raise PermissionError("Writable relay scope requires matching workspace and public write grants")
        delegation_relay_client = ProductionDelegationClient(
            relay_key, workspace_paths, config.state_dir, write_workspace_paths=write_scope)
        local_dispatch = _dispatch_agent

        def _list_agents():
            return delegation_relay_client.call("list_agents")

        def _dispatch_agent(**kwargs):
            workspace_id = kwargs.get("workspace_id")
            workspace = registry.get(workspace_id)
            if not workspace.allow_agent_dispatch:
                raise PermissionError("Production workspace does not permit delegation")
            if not kwargs.get("read_only", True) and not workspace.writable:
                raise PermissionError("Production workspace is not authorized for edits")
            # Use the existing production roster, workspace and action-policy
            # gates; remote development repeats its own independent checks.
            from agentporter.agents.roster import PUBLIC_AGENT_IDS
            if kwargs.get("agent") not in PUBLIC_AGENT_IDS:
                raise PermissionError("Unknown named worker")
            return delegation_relay_client.call("dispatch_agent", kwargs)
    _venkata_diagnostic = create_venkata_tool(registry)
    _venkata_transfer = create_venkata_transfer_tool(registry)
    _scinet_diagnostic = create_scinet_tool(registry, getattr(config, "scinet", None))
    _scinet_login = create_scinet_login_tool(registry, getattr(config, "scinet", None))
    _scinet_training = create_scinet_training_tool(
        registry, getattr(config, "scinet", None), config.state_dir
    )
    _scinet_inference_preflight = create_scinet_inference_preflight_tool(
        registry, getattr(config, "scinet", None)
    )
    _scinet_inference = create_scinet_inference_tools(
        registry, getattr(config, "scinet", None), config.state_dir
    )
    _scinet_inference_provision = create_scinet_inference_provision_tool(
        registry, getattr(config, "scinet", None), config.state_dir
    )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("venkata_transfer")
    def venkata_transfer(workspace_id: str, source: TransferSource, files: list[str],
                         destination: TransferDestination = "laya-training") -> dict:
        """Transfer allowlisted training files from Asgard or workspace staging to Venkata."""
        return _venkata_transfer(workspace_id=workspace_id, source=source, files=files, destination=destination)

    @mcp.tool()
    @monitored_tool("venkata_diagnostic")
    def venkata_diagnostic(workspace_id: str, command: Diagnostic, args: list[str] | None = None) -> dict:
        """Run allowlisted read-only Venkata diagnostics using BCC's host SSH identity."""
        return _venkata_diagnostic(workspace_id=workspace_id, command=command, args=args)

    @mcp.tool()
    @monitored_tool("scinet_diagnostic")
    def scinet_diagnostic(workspace_id: str, command: ScinetDiagnostic) -> dict:
        """Run one fixed, read-only SciNet diagnostic through the host-side broker."""
        return _scinet_diagnostic(workspace_id=workspace_id, command=command)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_login")
    def scinet_login(workspace_id: str, action: ScinetLoginAction = "start") -> dict:
        """Request one fixed SciNet Duo push or check login status; approval stays human."""
        return _scinet_login(workspace_id=workspace_id, action=action)

    @mcp.tool()
    @monitored_tool("server_deploy_info")
    def server_deploy_info() -> dict:
        """Report the running AgentPorter code fingerprint and whether src/ changed since startup."""
        return deploy_info()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_stage")
    def scinet_stage(workspace_id: str) -> dict:
        """Stage the approved Laya handoff into a dedicated SciNet directory."""
        return _scinet_training["scinet_stage"](workspace_id=workspace_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_submit")
    def scinet_submit(
        workspace_id: str, stage_id: str, experiment: ScinetExperiment = "laya_smoke"
    ) -> dict:
        """Submit a bounded, approval-gated Laya job (smoke; full A/B only if privately enabled)."""
        return _scinet_training["scinet_submit"](
            workspace_id=workspace_id, stage_id=stage_id, experiment=experiment
        )

    @mcp.tool()
    @monitored_tool("scinet_job_status")
    def scinet_job_status(workspace_id: str, job_id: str) -> dict:
        """Read status only for a job submitted through this workspace."""
        return _scinet_training["scinet_job_status"](
            workspace_id=workspace_id, job_id=job_id
        )

    @mcp.tool()
    @monitored_tool("scinet_job_logs")
    def scinet_job_logs(
        workspace_id: str, job_id: str, kind: ScinetLogKind = "all"
    ) -> dict:
        """Read bounded logs and result metadata for an approved SciNet job."""
        return _scinet_training["scinet_job_logs"](
            workspace_id=workspace_id, job_id=job_id, kind=kind
        )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_setup")
    def scinet_setup(workspace_id: str, stage_id: str) -> dict:
        """Start/resume the fixed SHA-verified login-node setup for a staged run."""
        return _scinet_training["scinet_setup"](workspace_id=workspace_id, stage_id=stage_id)

    @mcp.tool()
    @monitored_tool("scinet_setup_status")
    def scinet_setup_status(workspace_id: str, stage_id: str) -> dict:
        """Read fixed setup status and a bounded log tail for a staged run."""
        return _scinet_training["scinet_setup_status"](workspace_id=workspace_id, stage_id=stage_id)


    @mcp.tool()
    @monitored_tool("scinet_inference_preflight")
    def scinet_inference_preflight(workspace_id: str) -> dict:
        """Verify the fixed local Laya inference bundle; never contacts SciNet or submits."""
        return _scinet_inference_preflight(workspace_id=workspace_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_inference_stage")
    def scinet_inference_stage(workspace_id: str) -> dict:
        """Stage only the digest-pinned standalone inference bundle to fixed SciNet scratch."""
        return _scinet_inference["scinet_inference_stage"](workspace_id=workspace_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_inference_provision")
    def scinet_inference_provision(
        workspace_id: str, previous_run_id: str,
        phase: Literal["inspect", "prepare"] = "inspect",
    ) -> dict:
        """Inspect (read-only) or prepare the fixed Laya inference runtime; destinations are server-generated."""
        return _scinet_inference_provision(
            workspace_id=workspace_id, phase=phase, previous_run_id=previous_run_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_inference_approve")
    def scinet_inference_approve(
        workspace_id: str, stage_id: str, reviewer: str, signature: str
    ) -> dict:
        """Verify an offline human Ed25519 signature for this exact stage challenge."""
        return _scinet_inference["scinet_inference_approve"](
            workspace_id=workspace_id, stage_id=stage_id,
            reviewer=reviewer, signature=signature,
        )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_inference_submit")
    def scinet_inference_submit(workspace_id: str, stage_id: str) -> dict:
        """Submit one approved fixed-template 1xH100, 30-minute inference allocation."""
        return _scinet_inference["scinet_inference_submit"](
            workspace_id=workspace_id, stage_id=stage_id
        )

    @mcp.tool()
    @monitored_tool("scinet_inference_results")
    def scinet_inference_results(workspace_id: str, job_id: str) -> dict:
        """Preflight ledger-bound result retrieval; fail closed until trusted receipt transport exists."""
        return _scinet_inference["scinet_inference_results"](
            workspace_id=workspace_id, job_id=job_id
        )

    @mcp.tool()
    @monitored_tool("scinet_preflight")
    def scinet_preflight(
        workspace_id: str, stage_id: str, experiment: ScinetExperiment = "laya_smoke"
    ) -> dict:
        """Read-only gate and human-approval visibility; never approves or submits."""
        return _scinet_training["scinet_preflight"](
            workspace_id=workspace_id, stage_id=stage_id, experiment=experiment
        )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("scinet_record_approvals")
    def scinet_record_approvals(
        workspace_id: str, stage_id: str, reviewer: str, confirmation: str,
        approved_fields: list[str], device: str = "cuda", experiment: str = "laya_smoke",
    ) -> dict:
        """Record explicit human approvals (laya_smoke, laya_expA or stage-bound laya_expB) for one staged SciNet run."""
        return _scinet_training["scinet_record_approvals"](
            workspace_id=workspace_id, stage_id=stage_id, reviewer=reviewer,
            confirmation=confirmation, approved_fields=approved_fields,
            device=device, experiment=experiment,
        )

    @mcp.tool()
    @monitored_tool("scinet_environment_check")
    def scinet_environment_check(workspace_id: str) -> dict:
        """Run the fixed, read-only SciNet training environment check."""
        return _scinet_training["scinet_environment_check"](workspace_id=workspace_id)

    # Tool definitions registered on MCPServer
    @mcp.tool()
    @monitored_tool("get_capabilities")
    def get_capabilities() -> dict:
        """Return gateway capabilities and effective owner-approved HTTPS scope."""
        result = _get_capabilities()
        scopes = https_policy.scopes
        result["scoped_public_https"] = {
            "enabled": bool(scopes),
            "workspaces": sorted(scopes),
            "methods": sorted(scopes["cranary"]["methods"]) if "cranary" in scopes else [],
            "hosts": sorted(scopes["cranary"]["hosts"]) if "cranary" in scopes else [],
            "generic_shell_network": False,
            "authorization": "owner-installed 0600 allowlist; no caller boolean grants access",
        }
        if "cranary" in scopes and "downloads" in scopes["cranary"]:
            result["scoped_public_https"]["downloads"] = dict(scopes["cranary"]["downloads"])
        return result

    @mcp.tool()
    @monitored_tool("list_workspaces")
    def list_workspaces() -> list[dict]:
        """List all configured workspaces with ID and status."""
        return _list_workspaces()

    @mcp.tool()
    @monitored_tool("workspace_info")
    def workspace_info(workspace_id: str) -> dict:
        """Return comprehensive development context (git, language, runtimes) for a workspace."""
        return _workspace_info(workspace_id)

    @mcp.tool()
    @monitored_tool("list_files")
    def list_files(workspace_id: str, path: str = "", depth: Optional[int] = 1) -> list[str]:
        """List files in the workspace, skipping internal cache and git directories."""
        return _list_files(workspace_id, path=path, depth=depth)

    @mcp.tool()
    @monitored_tool("search_text")
    def search_text(workspace_id: str, query: str, glob: str = "*", max_results: int = 50) -> list[dict]:
        """Search for text in workspace files using ripgrep."""
        return _search_text(workspace_id, query=query, glob=glob, max_results=max_results)

    @mcp.tool()
    @monitored_tool("read_file")
    def read_file(workspace_id: str, path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> dict:
        """Read full or sliced lines of a file, returning content and SHA-256."""
        return _read_file(workspace_id, path, start_line=start_line, end_line=end_line)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("write_file")
    def write_file(workspace_id: str, path: str, content: str, expected_sha256: Optional[str] = None) -> dict:
        """Write content to a file atomically with optional stale-file protection."""
        return _write_file(workspace_id, path, content, expected_sha256=expected_sha256)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("apply_patch")
    def apply_patch(workspace_id: str, patch: str) -> dict:
        """Apply a unified diff patch to the workspace."""
        return _apply_patch(workspace_id, patch)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("mkdir")
    def mkdir(workspace_id: str, path: str) -> dict:
        """Create a directory in the workspace."""
        return _mkdir(workspace_id, path)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("move_path")
    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        """Move or rename a file or folder within the workspace."""
        return _move_path(workspace_id, source, destination)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("trash_path")
    def trash_path(workspace_id: str, path: str) -> dict:
        """Move a file to the recoverable .trash folder rather than permanently deleting it."""
        return _trash_path(workspace_id, path)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("https_download")
    def https_download(workspace_id: str, url: str, filename: str,
                       expected_sha256: Optional[str] = None, max_bytes: int = 16777216,
                       timeout_seconds: int = 60) -> dict:
        """Download approved historical source bytes into owner-scoped receipts; never overwrite or execute."""
        return _https_download(workspace_id, url, filename, expected_sha256, max_bytes, timeout_seconds)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("exec_run")
    def exec_run(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 30, network_access: bool = False) -> dict:
        """Run offline Bubblewrap command. Approved cranary GET/HEAD public HTTPS metadata only when network_access=true."""
        return _exec_run(workspace_id, argv=argv, cwd=cwd, timeout_seconds=timeout_seconds, network_access=network_access)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("exec_start")
    def exec_start(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 300, network_access: bool = False) -> dict:
        """Start offline Bubblewrap job; approved cranary public HTTPS metadata uses a fixed-purpose bounded worker."""
        return _exec_start(workspace_id, argv=argv, cwd=cwd, timeout_seconds=timeout_seconds, network_access=network_access)

    @mcp.tool()
    @monitored_tool("job_status")
    def job_status(job_id: str) -> dict:
        """Query the status of an asynchronous job."""
        return (delegation_relay_client.call("job_status", {"job_id": job_id}) if delegation_relay_client and delegation_relay_client.owns(job_id) else job_manager.get_status(job_id))

    @mcp.tool()
    @monitored_tool("job_output")
    def job_output(job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        """Retrieve incremental output from a running or completed job."""
        return (delegation_relay_client.call("job_output", {"job_id": job_id, "cursor": cursor, "max_bytes": max_bytes}) if delegation_relay_client and delegation_relay_client.owns(job_id) else job_manager.get_output(job_id, cursor=cursor, max_bytes=max_bytes))

    @mcp.tool()
    @monitored_tool("job_result")
    def job_result(job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        """Retrieve full result and output of a job."""
        return (delegation_relay_client.call("job_result", {"job_id": job_id, "cursor": cursor, "max_bytes": max_bytes}) if delegation_relay_client and delegation_relay_client.owns(job_id) else job_manager.get_result(job_id, cursor=cursor, max_bytes=max_bytes))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("job_cancel")
    def job_cancel(job_id: str) -> dict:
        """Cancel a running job."""
        return (delegation_relay_client.call("job_cancel", {"job_id": job_id}) if delegation_relay_client and delegation_relay_client.owns(job_id) else job_manager.cancel(job_id))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("local_http_request")
    def local_http_request(workspace_id: str, port: int, method: str = "GET", path: str = "/", body: Optional[str] = None) -> dict:
        """Test a local application listening on loopback (127.0.0.1)."""
        return _local_http_request(workspace_id, port=port, method=method, path=path, body=body)

    @mcp.tool()
    @monitored_tool("git_status")
    def git_status(workspace_id: str) -> str:
        """Show git status in the workspace (read-only)."""
        return _git_status(workspace_id)

    @mcp.tool()
    @monitored_tool("git_diff")
    def git_diff(workspace_id: str, staged: bool = False) -> str:
        """Show git diff in the workspace (read-only)."""
        return _git_diff(workspace_id, staged=staged)

    @mcp.tool()
    @monitored_tool("git_log")
    def git_log(workspace_id: str, limit: int = 10) -> str:
        """Show git log history in the workspace (read-only)."""
        return _git_log(workspace_id, limit=limit)

    @mcp.tool()
    @monitored_tool("git_show")
    def git_show(workspace_id: str, ref: str = "HEAD") -> str:
        """Show git object or commit in the workspace (read-only)."""
        return _git_show(workspace_id, ref=ref)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_fetch")
    def git_fetch(workspace_id: str, remote: str = "origin", branch: str = "",
                  approval_receipt: str = '', prepare_only: bool = False) -> str:
        """Fetch one owner-approved protected branch into its tracking ref."""
        return _git_fetch(workspace_id, remote=remote, branch=branch,
                          approval_receipt=approval_receipt, prepare_only=prepare_only)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_pull")
    def git_pull(workspace_id: str, remote: str = "origin", branch: str = "") -> str:
        """Pull changes from remote repository into current branch."""
        return _git_pull(workspace_id, remote=remote, branch=branch)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_push")
    def git_push(workspace_id: str, remote: str = "origin", branch: str = "", set_upstream: bool = False,
                 approval_receipt: str = '', prepare_only: bool = False) -> str:
        """Agent pushes are disabled by operator policy."""
        return _git_push(workspace_id, remote=remote, branch=branch, set_upstream=set_upstream,
                         approval_receipt=approval_receipt, prepare_only=prepare_only)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_commit")
    def git_commit(workspace_id: str, message: str, all_files: bool = False,
                   approval_receipt: str = '', approval_timestamp: int | None = None,
                   prepare_only: bool = False) -> str:
        """Commit explicitly staged workspace changes without a phone receipt."""
        return _git_commit(workspace_id, message=message, all_files=all_files,
                           approval_receipt=approval_receipt, approval_timestamp=approval_timestamp,
                           prepare_only=prepare_only)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_add")
    def git_add(workspace_id: str, paths: list[str]) -> str:
        """Stage file paths for git commit."""
        return _git_add(workspace_id, paths=paths)

    @mcp.tool()
    @monitored_tool("git_branch")
    def git_branch(workspace_id: str) -> str:
        """List local and remote branches in workspace."""
        return _git_branch(workspace_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("git_checkout")
    def git_checkout(workspace_id: str, branch: str, create: bool = False) -> str:
        """Switch branches or create a new branch in workspace."""
        return _git_checkout(workspace_id, branch=branch, create=create)

    @mcp.tool()
    @monitored_tool("list_artifacts")
    def list_artifacts(workspace_id: str, path: str = "artifacts") -> list[dict]:
        """List artifacts in the workspace."""
        return _list_artifacts(workspace_id, path=path)

    @mcp.tool()
    @monitored_tool("read_artifact")
    def read_artifact(workspace_id: str, path: str) -> dict:
        """Read an artifact file (supports text and base64 images)."""
        return _read_artifact(workspace_id, path=path)

    @mcp.tool()
    @monitored_tool("list_agents")
    def list_agents(workspace_id: Optional[str] = None) -> list[dict]:
        """List worker runtime checks and public delegation scope, optionally for a workspace.

        Runtime readiness does not verify provider quota or successful execution.
        """
        return _list_agents()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    @monitored_tool("dispatch_agent")
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
        """Dispatch a worker; read_only defaults to true. Explicitly opt in to edits."""
        return _dispatch_agent(
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

    context = {
        "registry": registry,
        "sandbox": sandbox,
        "job_manager": job_manager,
        "agent_broker": agent_broker,
        "delegation_relay_client": delegation_relay_client,
        "operator_action_policy": operator_policy,
        "client_policy": client_policy,
        "tools": {
            "get_capabilities": get_capabilities,
            "server_deploy_info": server_deploy_info,
            "list_workspaces": list_workspaces,
            "workspace_info": workspace_info,
            "list_files": list_files,
            "search_text": search_text,
            "read_file": read_file,
            "write_file": write_file,
            "apply_patch": apply_patch,
            "mkdir": mkdir,
            "move_path": move_path,
            "trash_path": trash_path,
            "exec_run": exec_run,
            "https_download": https_download,
            "exec_start": exec_start,
            "job_status": job_status,
            "job_output": job_output,
            "job_result": job_result,
            "job_cancel": job_cancel,
            "git_status": git_status,
            "git_diff": git_diff,
            "git_log": git_log,
            "git_show": git_show,
            "git_fetch": git_fetch,
            "git_pull": git_pull,
            "git_push": git_push,
            "git_commit": git_commit,
            "git_add": git_add,
            "git_branch": git_branch,
            "git_checkout": git_checkout,
            "list_artifacts": list_artifacts,
            "read_artifact": read_artifact,
            "list_agents": list_agents,
            "dispatch_agent": dispatch_agent,
            "venkata_diagnostic": venkata_diagnostic,
            "venkata_transfer": venkata_transfer,
        "scinet_diagnostic": scinet_diagnostic,
        "scinet_login": scinet_login,
        "scinet_stage": scinet_stage,
        "scinet_submit": scinet_submit,
        "scinet_job_status": scinet_job_status,
        "scinet_job_logs": scinet_job_logs,
        "scinet_environment_check": scinet_environment_check,
        "scinet_setup": scinet_setup,
        "scinet_setup_status": scinet_setup_status,
        "scinet_inference_preflight": scinet_inference_preflight,
        "scinet_inference_stage": scinet_inference_stage,
        "scinet_inference_provision": scinet_inference_provision,
        "scinet_inference_approve": scinet_inference_approve,
        "scinet_inference_submit": scinet_inference_submit,
        "scinet_inference_results": scinet_inference_results,
        "scinet_preflight": scinet_preflight,
        "scinet_record_approvals": scinet_record_approvals,
        }
    }
    return mcp, context


from agentporter.rest.api import api_router, custom_generate_unique_id

def create_asgi_app(config: Config) -> ASGIApp:
    """Create Starlette ASGI application with Streamable HTTP and Security Middleware."""
    mcp, context = build_mcp_server(config)
    
    # Let the MCP SDK reject oversized streamed bodies before Starlette
    # generates a response; never relax its native four-MiB default.
    streamable_app = mcp.streamable_http_app(
        stateless_http=context['client_policy'].scopes is not None,
        max_request_body_size=min(
            config.security.max_payload_bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @asynccontextmanager
    async def lifespan(app):
        async with streamable_app.router.lifespan_context(streamable_app):
            yield
    
    app = FastAPI(
        title=f"{config.server.action_prefix.upper()} AgentPorter API" if config.server.action_prefix else "AgentPorter API",
        version="0.1.0",
        description="AgentPorter Local Tools and Subagent Gateway for ChatGPT and MCP clients",
        servers=([{"url": config.server.public_url}] if config.server.public_url else None),
        generate_unique_id_function=custom_generate_unique_id,
        lifespan=lifespan,
    )
    
    app.state.tools = context["tools"]
    relay_key = read_relay_key(config.config_dir)
    if relay_key is not None and relay_key == config.api_key:
        raise PermissionError("Relay credential must differ from general AgentPorter API key")
    relay_scope = (
        read_relay_scope(config.config_dir)
        if context["agent_broker"].development_runtime is not None else {}
    )
    if relay_key and context["agent_broker"].development_runtime is not None and not relay_scope:
        raise PermissionError("Isolated relay key installed without operator workspace scope")
    if relay_scope:
        available = {
            row["workspace_id"]: row["path"] for row in context["registry"].list_all()
            if row["permissions"]["agent_dispatch"]
        }
        if any(available.get(name) != path for name, path in relay_scope.items()):
            raise PermissionError("Isolated relay scope does not match approved registered workspaces")
    relay_write_scope = (read_relay_scope(config.config_dir, writable=True)
                         if relay_scope else {})
    if relay_write_scope:
        if not config.sandbox.workspace_transactions or context["job_manager"].resources is None:
            raise PermissionError("Writable relay requires supervised workspace transactions")
        if any(relay_scope.get(name) != path or not context["registry"].get(name).writable
               for name, path in relay_write_scope.items()):
            raise PermissionError("Writable relay scope must match a writable isolated workspace")
    relay_server_enabled = (
        relay_key is not None
        and bool(relay_scope)
        and context["agent_broker"].development_runtime is not None
        and context["delegation_relay_client"] is None
    )
    relay_ledger = None
    if relay_server_enabled:
        context["agent_broker"].development_runtime.require_production_egress()
        from agentporter.agents.production_relay import RelayLedger
        relay_ledger = RelayLedger(config.state_dir)
        import threading
        relay_dispatch_lock = threading.RLock()
    if relay_server_enabled:
        @app.post("/internal/delegation/v1", include_in_schema=False)
        async def internal_delegation(request: Request):
            # The dedicated credential and loopback client check are enforced
            # in SecurityMiddleware before the request reaches this handler.
            try:
                payload = await request.json()
                if not isinstance(payload, dict) or set(payload) != {"operation", "args"}:
                    raise PermissionError("Invalid relay envelope")
                operation, arguments = payload["operation"], payload["args"]
                if operation not in ALLOWED_OPS or not isinstance(arguments, dict):
                    raise PermissionError("Unsupported relay operation")
                if operation == "list_agents":
                    if arguments:
                        raise PermissionError("Unexpected inventory arguments")
                    approved = context["agent_broker"].development_runtime.require_production_egress()
                    result = [row if row.get("agent") in approved else {
                        **row, "delegatable": False,
                        "availability_reason": "Agent is not admitted for production delegation",
                    } for row in context["tools"]["list_agents"]()]
                elif operation == "lookup_dispatch":
                    if set(arguments) != {"request_id"}:
                        raise PermissionError("Invalid relay recovery request")
                    previous = relay_ledger.get_request(arguments["request_id"])
                    result = ({"job_id": previous[0], "status": "known"}
                              if previous is not None and previous[0] else
                              {"job_id": None, "status": "delivery_uncertain"})
                elif operation == "workspace_info":
                    if (set(arguments) != {"workspace_id"}
                            or not isinstance(arguments["workspace_id"], str)
                            or arguments["workspace_id"] not in relay_scope):
                        raise PermissionError("Workspace outside owner-approved relay scope")
                    workspace = context["registry"].get(arguments["workspace_id"])
                    context["agent_broker"].development_runtime.require_production_egress()
                    from agentporter.agents.production_relay import RECEIVING_SECURITY_PROFILE
                    result = {"workspace_id": workspace.id, "path": workspace.path,
                              "agent_dispatch": workspace.allow_agent_dispatch,
                              "security_profile": RECEIVING_SECURITY_PROFILE,
                              "writable_transactions": workspace.id in relay_write_scope}
                elif operation == "dispatch_agent":
                    context["agent_broker"].development_runtime.require_production_egress(arguments.get("agent", ""))
                    # The same idempotency token always selects the same job.
                    # Dispatch and registration are serialized within this
                    # gateway; no duplicate launch under concurrent requests.
                    registry = context["registry"]
                    scopes = set(relay_scope)
                    arguments = validate_dispatch(arguments, scopes,
                                                  write_workspace_ids=frozenset(relay_write_scope))
                    token = arguments.pop("request_id", None)
                    relay_ledger.validate_request_id(token)
                    with relay_dispatch_lock:
                        # Reconcile tracked completions so finished jobs do not
                        # consume the three-job admission capacity indefinitely.
                        manager = context["job_manager"]
                        for (known_jid,) in relay_ledger.active_jobs():
                            try:
                                observed = manager.get_status(known_jid)
                            except KeyError:
                                observed = {"status": "unknown"}
                            if observed["status"] in TERMINAL_JOB_STATUSES:
                                relay_ledger.mark_terminal(known_jid)
                            # A different gateway process may own an active
                            # worker; never infer termination from this
                            # process's empty active_processes mapping.

                        # Single SQLite BEGIN IMMEDIATE atomically arbitrates
                        # reservations across all worker gateway processes.
                        prior = relay_ledger.reserve(
                            token, arguments["workspace_id"], arguments["agent"],
                            max_active=3)
                        if prior is not None:
                            if prior[0] is None:
                                raise PermissionError("Previous relay launch outcome uncertain; no duplicate dispatch")
                            result = context["tools"]["job_status"](job_id=prior[0])
                            result = {**result, "job_id": prior[0], "dispatch_id": prior[0]}
                        else:
                            try:
                                result = context["tools"]["dispatch_agent"](**arguments)
                            except (PermissionError, ValueError, JobCapacityError):
                                # The broker raises these for rejected scopes,
                                # unsupported models and refused launch policies.
                                # The confined JobManager cleans up/kills its
                                # child before re-raising these exceptions.
                                # Preserve the spent idempotency key but free
                                # its capacity only when no job ID was issued.
                                relay_ledger.mark_no_launch(token)
                                raise
                            jid = result.get("job_id", "")
                            if not JOB_RE.fullmatch(jid):
                                raise RuntimeError("Confined backend did not issue a valid job")
                            relay_ledger.register(
                                token, jid, arguments["workspace_id"], arguments["agent"])
                else:
                    jid = validate_job_request(arguments)
                    if relay_ledger.get_remote(jid) is None:
                        raise PermissionError("Job was not created by relay")
                    if operation in {"job_output", "job_result"}:
                        arguments["max_bytes"] = min(arguments.get("max_bytes", 65536), 32768)
                    if operation == "job_status":
                        result = context["tools"]["job_status"](job_id=jid)
                    elif operation == "job_output":
                        result = context["tools"]["job_output"](**arguments)
                    elif operation == "job_result":
                        result = context["tools"]["job_result"](**arguments)
                    else:
                        raise PermissionError("Production relay cancellation is disabled pending PID-safe backend")
                    if result.get("status") in TERMINAL_JOB_STATUSES:
                        relay_ledger.mark_terminal(jid)
                    elif (result.get("status") == "running"
                          and jid not in context["job_manager"].active_processes):
                        # Cannot tell a restarted gateway from a worker owned
                        # by another process. Preserve durable capacity.
                        result = {**result, "status": "running_unverified"}
                return JSONResponse(result)
            except (PermissionError, ValueError, KeyError) as exc:
                logger.warning("Narrow relay request denied: %s", type(exc).__name__)
                return JSONResponse({"detail": "Delegation relay request denied"}, status_code=403)


    @app.exception_handler(PermissionError)
    async def permission_error_response(request, exc: PermissionError):
        """Return authorization denials as 403 rather than HTTP 500."""
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(JobCapacityError)
    async def capacity_error_response(request, exc):
        return JSONResponse(status_code=429, content={'detail': str(exc)}, headers={'Retry-After': '3'})

    @app.exception_handler(ValueError)
    async def invalid_tool_arguments_response(request, exc: ValueError):
        """Reject invalid tool paths/arguments without reflecting private data."""
        return JSONResponse(status_code=400, content={'detail': 'Invalid tool arguments'})


    @app.get("/health")
    async def health():
        return JSONResponse({"status": "healthy"})

    # Authenticated (not in the public allowlist) so source fingerprints and
    # host paths are never exposed through the tunnel without the API key.
    @app.get("/api/v1/server/deploy-info", operation_id="server_deploy_info")
    async def server_deploy_info():
        # Enforce the same operator policy as the MCP tool.
        return JSONResponse(context["tools"]["server_deploy_info"]())
    
    app.include_router(api_router, prefix="/api/v1")
    # streamable_http_app already serves its endpoint at /mcp. Mounting it at
    # /mcp would expose the effective route as /mcp/mcp and leave /mcp returning
    # a redirect followed by 404s. Mount at the root after the REST routes so
    # the MCP app keeps its canonical /mcp path.
    app.mount("/", streamable_app)

    # ChatGPT Actions strict validation: every object schema must have 'properties'
    original_openapi = app.openapi
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = original_openapi()
        def fix_objects(obj):
            if isinstance(obj, dict):
                if obj.get("type") == "object" and "properties" not in obj:
                    obj["properties"] = {}
                for v in obj.values():
                    fix_objects(v)
            elif isinstance(obj, list):
                for item in obj:
                    fix_objects(item)
        fix_objects(schema)
        # ChatGPT Actions rejects schemas with more than 30 operations; stay
        # below the limit with margin. Retain HTTP handlers and MCP tools; omit
        # only lower-priority operations from the imported REST schema, on
        # Asgard and BCC alike (read_file/exec_run cover artifacts).
        action_schema_exclusions = {
            "health",
            "server_deploy_info",
            "git_branch",
            "git_show",
        "git_status",
        "git_diff",
        "git_log",
        "git_fetch",
        "git_pull",
            "list_artifacts",
            "read_artifact",
        }
        for path, path_item in list(schema.get("paths", {}).items()):
            for method, operation in list(path_item.items()):
                if isinstance(operation, dict) and operation.get("operationId") in action_schema_exclusions:
                    del path_item[method]
            if not path_item:
                del schema["paths"][path]
        if "components" not in schema:
            schema["components"] = {}
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "API key bearer token"
            }
        }
        schema["security"] = [{"BearerAuth": []}]
        # Never tell GPT Actions to silently approve mutating operations.
        # Client approval is defense in depth, not a server-side human receipt.
        safe_read_operations = {
            "list_workspaces", "workspace_info", "list_files", "search_text",
            "read_file", "git_status", "git_diff", "git_log", "git_show",
            "list_agents", "job_status", "job_output", "job_result",
        }
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                if isinstance(operation, dict) and "operationId" in operation:
                    operation["x-openai-isConsequential"] = (
                        operation["operationId"] not in safe_read_operations
                    )
        if config.server.action_prefix:
            for path in schema.get("paths", {}).values():
                for operation in path.values():
                    if isinstance(operation, dict) and "operationId" in operation:
                        operation["operationId"] = f"{config.server.action_prefix}_{operation['operationId']}"
        app.openapi_schema = schema
        return app.openapi_schema
    app.openapi = custom_openapi

    rate_limiter = RateLimiter(
        max_requests=config.security.rate_limit_max_requests,
        window_seconds=config.security.rate_limit_window_seconds
    )
    return SecurityMiddleware(
        app=app,
        api_key=config.api_key,
        allowed_hosts=config.security.allowed_hosts,
        header_name=config.security.header_name,
        legacy_header_name=config.security.legacy_header_name,
        rate_limiter=rate_limiter,
        max_payload_bytes=config.security.max_payload_bytes,
        delegation_relay_key=relay_key if relay_server_enabled else None,
        internal_client_key=context['client_policy'].internal_key,
    )
