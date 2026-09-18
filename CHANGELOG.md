# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0.dev0] - 2026-09-18

### Added
- Bootstrap generic AgentPorter architecture extracted from proven M3 gateway reference implementation.
- Standard Streamable HTTP Model Context Protocol (MCP) server implementation.
- API Key authentication middleware supporting constant-time verification and custom header support.
- Host-header validation for DNS rebinding protection and request rate limiting.
- Unprivileged `bubblewrap` (bwrap) direct code execution sandbox with zero-network isolation and scrubbed environments.
- Asynchronous job execution manager with SQLite tracking, incremental output cursors, and clean cancellation.
- Workspace-scoped filesystem operations with path traversal, symlink escape, and sensitive credential protection.
- Read-only Git inspection tools (`git_status`, `git_diff`, `git_log`, `git_show`).
- Artifact discovery and retrieval (supporting text and base64 images).
- Loopback-only local HTTP client for testing local web services.
- Extensible AI agent broker and adapter framework supporting Codex, Claude Code, OpenCode, and Antigravity.
- Real-time agent provenance telemetry: distinguishes configured routing from resolved runtime model and reports `"unknown"` when the underlying CLI does not expose it.
- Comprehensive CLI: `agentporter serve`, `agentporter doctor`, `agentporter init`, `agentporter workspaces (list/add/remove)`, `agentporter agents`.
- Key management CLI commands: `agentporter key show` and `agentporter key rotate`.
- Public unauthenticated `/health` endpoint for uptime monitoring and tunnel health checks.
- Transparent root path `/` to `/mcp` rewrite for Microsoft Copilot Studio Streamable HTTP compatibility.
- Expanded default host whitelist for tunnel providers (`*.devtunnels.ms`, `*.lhr.life`, `*.pinggy.net`, `*.ts.net`) and `ALLOWED_HOSTS` environment variable support.
- Full test suite covering unit, security, integration, and CLI entrypoints (61 passing tests).
- Systemd user service unit template (`examples/agentporter.service`).
- Comprehensive documentation: Architecture, Security Model, Package vs. Local separation, Local Setup, MCP Clients, Copilot Studio integration, and Dogfooding Lessons Learned.

### Changed
- Added 10 MB maximum file size ceiling to `read_file` to guard against unbounded memory consumption.
- Enhanced patch header parsing in `apply_patch` to robustly handle git diffs with timestamp and multi-space delimiters.
- Expanded workspace path sensitive denylist to explicitly protect user shell configuration files (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`) and `.gnupg`.
- Genericized author metadata in `pyproject.toml` to contributor collective.

