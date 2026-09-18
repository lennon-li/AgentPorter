"""Command-line interface for AgentPorter."""

import os
import sys
import shutil
import secrets
import subprocess
import click
import uvicorn

from agentporter import __version__
from agentporter.config import Config
from agentporter.server import create_asgi_app
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.tools.jobs import JobManager
from agentporter.agents.broker import AgentBroker


@click.group()
@click.version_option(version=__version__, prog_name="agentporter")
def main():
    """AgentPorter: Secure local MCP gateway for development workspaces and agent delegation."""
    pass


@main.command()
@click.option("--host", default=None, help="Host to bind server to (default: 127.0.0.1)")
@click.option("--port", default=None, type=int, help="Port to listen on (default: 8765)")
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
def serve(host, port, config_dir):
    """Start the AgentPorter MCP Streamable HTTP server."""
    cfg = Config(config_dir=config_dir)
    bind_host = host or cfg.server.host
    bind_port = port or cfg.server.port

    click.echo(f"Starting {cfg.server.name} v{__version__} on {bind_host}:{bind_port}")
    click.echo(f"Config Directory: {cfg.config_dir}")
    click.echo(f"State Directory:  {cfg.state_dir}")
    click.echo(f"Auth Header:      {cfg.security.header_name} (legacy: {cfg.security.legacy_header_name})")

    app = create_asgi_app(cfg)
    uvicorn.run(app, host=bind_host, port=bind_port, log_level="info")


@main.command()
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
def doctor(config_dir):
    """Run diagnostics on environment, sandbox backends, workspaces, and agents."""
    cfg = Config(config_dir=config_dir)
    click.echo("=" * 60)
    click.echo(f"AgentPorter Doctor Diagnostic (v{__version__})")
    click.echo("=" * 60)

    # 1. Python Environment
    click.echo(f"Python Version:       {sys.version.split()[0]} ({sys.executable})")

    # 2. Bubblewrap Sandbox Backend
    bwrap_path = shutil.which("bwrap")
    if bwrap_path:
        bwrap_ver = "unknown"
        try:
            res = subprocess.run([bwrap_path, "--version"], capture_output=True, text=True, timeout=3)
            bwrap_ver = res.stdout.strip()
        except Exception:
            pass
        click.echo(f"Sandbox Backend:      bubblewrap ({bwrap_ver} at {bwrap_path}) [OK]")
    else:
        click.echo(f"Sandbox Backend:      bubblewrap NOT FOUND. Install via: sudo apt install bubblewrap [WARN]")

    # 3. Path Diagnostics
    click.echo(f"Config Directory:     {cfg.config_dir} (exists: {cfg.config_dir.exists()})")
    click.echo(f"State Directory:      {cfg.state_dir} (exists: {cfg.state_dir.exists()})")
    click.echo(f"Secrets File:         {cfg.config_dir / 'secrets.env'} (exists: {(cfg.config_dir / 'secrets.env').exists()})")

    # 4. Registered Workspaces
    registry = WorkspaceRegistry(cfg.workspaces)
    workspaces = registry.list_all()
    click.echo(f"\nRegistered Workspaces ({len(workspaces)}):")
    if not workspaces:
        click.echo("  (None registered. Add to ~/.config/agentporter/workspaces.yaml)")
    for ws in workspaces:
        status_flag = "OK" if ws["exists"] else "MISSING PATH"
        writable_flag = "RW" if ws["writable"] else "RO"
        click.echo(f"  • {ws['workspace_id']} [{writable_flag}]: {ws['path']} ({status_flag})")

    # 5. Worker Agents
    job_mgr = JobManager(cfg.state_dir)
    broker = AgentBroker(registry, job_mgr)
    agents = broker.list_agents()
    click.echo(f"\nDetected Worker Agents ({len(agents)}):")
    for ag in agents:
        avail_flag = f"Available (v{ag['cli_version']})" if ag["available"] else "Not installed"
        click.echo(f"  • {ag['agent']:<10} [{ag['provider']}]: {avail_flag}")
        click.echo(f"    Configured Model: {ag['configured_model']} (reasoning: {ag['reasoning_level']})")

    # 6. Security Warnings
    click.echo("\nSecurity Invariants:")
    click.echo(f"  • Default Bind Address:  {cfg.server.host} (local only)")
    click.echo(f"  • Auth Mode:             API Key Header ({cfg.security.header_name})")
    click.echo(f"  • Network Isolation:     Disabled in sandbox (--unshare-net)")
    click.echo("=" * 60)


@main.command()
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
def workspaces(config_dir):
    """List registered workspaces."""
    cfg = Config(config_dir=config_dir)
    registry = WorkspaceRegistry(cfg.workspaces)
    ws_list = registry.list_all()
    click.echo(f"Registered Workspaces ({len(ws_list)}):")
    for ws in ws_list:
        click.echo(f"  • {ws['workspace_id']:<15} path={ws['path']} writable={ws['writable']}")


@main.command()
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
def agents(config_dir):
    """List available CLI agent workers."""
    cfg = Config(config_dir=config_dir)
    registry = WorkspaceRegistry(cfg.workspaces)
    job_mgr = JobManager(cfg.state_dir)
    broker = AgentBroker(registry, job_mgr)
    for ag in broker.list_agents():
        click.echo(f"Agent: {ag['agent']} ({ag['alias']})")
        click.echo(f"  Provider:         {ag['provider']}")
        click.echo(f"  Configured Model: {ag['configured_model']}")
        click.echo(f"  Actual Model:     {ag['actual_model_used']}")
        click.echo(f"  CLI Version:      {ag['cli_version']}")
        click.echo(f"  Available:        {ag['available']}")
        click.echo()


@main.group()
def key():
    """Manage AgentPorter API authentication keys."""
    pass


@key.command(name="show")
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
def key_show(config_dir):
    """Display the active API key and accepted header names."""
    cfg = Config(config_dir=config_dir)
    click.echo(f"Primary Header: {cfg.security.header_name}")
    click.echo(f"Legacy Header:  {cfg.security.legacy_header_name}")
    click.echo(f"API Key:        {cfg.api_key}")


@key.command(name="rotate")
@click.option("--config-dir", default=None, type=click.Path(), help="Custom configuration directory")
@click.option("--yes", "-y", is_flag=True, help="Confirm key rotation without prompt")
def key_rotate(config_dir, yes):
    """Rotate the API key and update secrets.env."""
    if not yes:
        click.confirm("Are you sure you want to rotate the API key? Existing clients will be disconnected.", abort=True)
    cfg = Config(config_dir=config_dir)
    new_key = secrets.token_urlsafe(32)
    secrets_file = cfg.config_dir / "secrets.env"
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    with open(secrets_file, "w", encoding="utf-8") as f:
        f.write("# AgentPorter generated API key\n")
        f.write(f"AGENTPORTER_API_KEY={new_key}\n")
        f.write(f"M3_MCP_KEY={new_key}\n")
    os.chmod(secrets_file, 0o600)
    click.echo("API key successfully rotated.")
    click.echo(f"New Key: {new_key}")


if __name__ == "__main__":
    main()

