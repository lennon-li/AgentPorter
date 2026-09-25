"""Model Context Protocol (MCP) Streamable HTTP server for AgentPorter."""

import os
import sys
import time
import json
import logging
import functools
from contextlib import asynccontextmanager
from typing import Optional, Any
from logging.handlers import RotatingFileHandler
from starlette.types import ASGIApp
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from fastapi import FastAPI

from agentporter import __version__
from agentporter.config import Config
from agentporter.auth import RateLimiter
from agentporter.middleware import SecurityMiddleware
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.jobs import JobManager
from agentporter.agents.broker import AgentBroker
from agentporter.tools.system import create_system_tools
from agentporter.tools.files import create_file_tools
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.git import create_git_tools
from agentporter.tools.artifacts import create_artifact_tools
from agentporter.tools.local_http import create_local_http_tool
from agentporter.tools.agents import create_agent_tools

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


def monitored_tool(tool_name: str):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(**kwargs):
            t0 = time.time()
            try:
                res = fn(**kwargs)
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
    )
    job_manager = JobManager(
        config.state_dir,
        max_log_bytes=config.sandbox.max_job_log_bytes,
    )
    agent_broker = AgentBroker(registry, job_manager)

    # Instantiate tool sets
    _get_capabilities, _list_workspaces, _workspace_info = create_system_tools(registry, sandbox)
    (
        _list_files, _search_text, _read_file, _write_file,
        _apply_patch, _mkdir, _move_path, _trash_path
    ) = create_file_tools(registry)
    _exec_run, _exec_start = create_execution_tools(registry, sandbox, job_manager)
    _git_status, _git_diff, _git_log, _git_show = create_git_tools(registry, sandbox)
    _list_artifacts, _read_artifact = create_artifact_tools(registry)
    _local_http_request = create_local_http_tool(registry)
    _list_agents, _dispatch_agent = create_agent_tools(agent_broker)

    # Tool definitions registered on MCPServer
    @mcp.tool()
    @monitored_tool("get_capabilities")
    def get_capabilities() -> dict:
        """Return gateway capabilities, sandbox status, and available runtimes."""
        return _get_capabilities()

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
    def list_files(workspace_id: str, path: str = "", depth: Optional[int] = None) -> list[str]:
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

    @mcp.tool()
    @monitored_tool("write_file")
    def write_file(workspace_id: str, path: str, content: str, expected_sha256: Optional[str] = None) -> dict:
        """Write content to a file atomically with optional stale-file protection."""
        return _write_file(workspace_id, path, content, expected_sha256=expected_sha256)

    @mcp.tool()
    @monitored_tool("apply_patch")
    def apply_patch(workspace_id: str, patch: str) -> dict:
        """Apply a unified diff patch to the workspace."""
        return _apply_patch(workspace_id, patch)

    @mcp.tool()
    @monitored_tool("mkdir")
    def mkdir(workspace_id: str, path: str) -> dict:
        """Create a directory in the workspace."""
        return _mkdir(workspace_id, path)

    @mcp.tool()
    @monitored_tool("move_path")
    def move_path(workspace_id: str, source: str, destination: str) -> dict:
        """Move or rename a file or folder within the workspace."""
        return _move_path(workspace_id, source, destination)

    @mcp.tool()
    @monitored_tool("trash_path")
    def trash_path(workspace_id: str, path: str) -> dict:
        """Move a file to the recoverable .trash folder rather than permanently deleting it."""
        return _trash_path(workspace_id, path)

    @mcp.tool()
    @monitored_tool("exec_run")
    def exec_run(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 30) -> dict:
        """Execute command synchronously inside the bubblewrap sandbox with network disabled."""
        return _exec_run(workspace_id, argv=argv, cwd=cwd, timeout_seconds=timeout_seconds)

    @mcp.tool()
    @monitored_tool("exec_start")
    def exec_start(workspace_id: str, argv: list[str], cwd: str = "", timeout_seconds: int = 300) -> dict:
        """Start command asynchronously inside the sandbox, returning a job ID."""
        return _exec_start(workspace_id, argv=argv, cwd=cwd, timeout_seconds=timeout_seconds)

    @mcp.tool()
    @monitored_tool("job_status")
    def job_status(job_id: str) -> dict:
        """Query the status of an asynchronous job."""
        return job_manager.get_status(job_id)

    @mcp.tool()
    @monitored_tool("job_output")
    def job_output(job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        """Retrieve incremental output from a running or completed job."""
        return job_manager.get_output(job_id, cursor=cursor, max_bytes=max_bytes)

    @mcp.tool()
    @monitored_tool("job_result")
    def job_result(job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        """Retrieve full result and output of a job."""
        return job_manager.get_result(job_id, cursor=cursor, max_bytes=max_bytes)

    @mcp.tool()
    @monitored_tool("job_cancel")
    def job_cancel(job_id: str) -> dict:
        """Cancel a running job."""
        return job_manager.cancel(job_id)

    @mcp.tool()
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
    def list_agents() -> list[dict]:
        """List available CLI agent workers (Codex, Claude, OpenCode, Agy)."""
        return _list_agents()

    @mcp.tool()
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
    ) -> dict:
        """Dispatch an authorized CLI agent worker asynchronously."""
        return _dispatch_agent(
            agent=agent,
            task=task,
            workspace_id=workspace_id,
            purpose=purpose,
            model=model,
            reasoning_effort=reasoning_effort,
            allow_commit=allow_commit,
            allow_push=allow_push,
        )

    context = {
        "registry": registry,
        "sandbox": sandbox,
        "job_manager": job_manager,
        "agent_broker": agent_broker,
        "tools": {
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
            "exec_start": exec_start,
            "job_status": job_status,
            "job_output": job_output,
            "job_result": job_result,
            "job_cancel": job_cancel,
            "git_status": git_status,
            "git_diff": git_diff,
            "git_log": git_log,
            "git_show": git_show,
            "list_artifacts": list_artifacts,
            "read_artifact": read_artifact,
            "list_agents": list_agents,
            "dispatch_agent": dispatch_agent,
        }
    }
    return mcp, context


from agentporter.rest.api import api_router, custom_generate_unique_id

def create_asgi_app(config: Config) -> ASGIApp:
    """Create Starlette ASGI application with Streamable HTTP and Security Middleware."""
    mcp, context = build_mcp_server(config)
    
    streamable_app = mcp.streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )

    @asynccontextmanager
    async def lifespan(app):
        async with streamable_app.router.lifespan_context(streamable_app):
            yield
    
    server_list = [
        {"url": "https://5mvx3k0t-8765.use.devtunnels.ms", "description": "Asgard Dev Tunnel Gateway"}
    ]

    app = FastAPI(
        title="AgentPorter API",
        version="0.1.0",
        description="AgentPorter Local Tools and Subagent Gateway for ChatGPT and MCP clients",
        servers=server_list,
        generate_unique_id_function=custom_generate_unique_id,
        lifespan=lifespan,
    )
    
    app.state.tools = context["tools"]
    
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
        app.openapi_schema = schema
        return app.openapi_schema
    app.openapi = custom_openapi

    rate_limiter = RateLimiter(
        max_requests=config.security.rate_limit_max_requests,
        window_seconds=config.security.rate_limit_window_seconds
    )
    return SecurityMiddleware(
        app=app,
        api_key=config.api_keys,
        allowed_hosts=config.security.allowed_hosts,
        header_name=config.security.header_name,
        legacy_header_name=config.security.legacy_header_name,
        rate_limiter=rate_limiter,
        max_payload_bytes=config.security.max_payload_bytes
    )
