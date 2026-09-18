# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0.dev0] - 2026-09-18

### Added
- Bootstrap generic AgentPorter architecture extracted from a proven private gateway deployment.
- Standard Streamable HTTP Model Context Protocol (MCP) server implementation.
- API Key authentication middleware supporting constant-time verification and custom header support.
- Host-header validation for DNS rebinding protection and request rate limiting.
- Unprivileged `bubblewrap` (bwrap) direct code execution sandbox with zero-network isolation and scrubbed environments.
- Asynchronous job execution manager with SQLite tracking, incremental output cursors, and clean cancellation.
- Workspace-scoped filesystem operations with path traversal, symlink escape, and sensitive credential protection.
- Read-only Git inspection tools (`git_status`, `git_diff`, `git_log`, `git_show`).
- Artifact discovery and retrieval (supporting text and base64 images).
- Opt-in loopback HTTP client with per-workspace exact-port allowlists.
- Extensible AI agent broker and adapter framework supporting Codex, Claude Code, OpenCode, and Antigravity.
- Agent provenance telemetry that separates configured routing, explicit requested overrides, and verified runtime model; unverified runtime model remains `"unknown"`.
- Minimal CLI entrypoint: `agentporter serve`, `agentporter doctor`, `agentporter workspaces`, `agentporter agents`.
- Comprehensive documentation: Architecture, Security Model, Package vs. Local separation, Local Setup, MCP Clients, and Copilot Studio integration.


### Security hardening
- Closed the sensitive-file disclosure path through text search.
- Made host-level worker delegation opt-in and required enforceable read-only support for read-only workspaces.
- Removed personal aliases/model-routing defaults from reusable adapters.
- Added per-workspace execution, Git, artifact, agent-dispatch, and loopback-port controls.
- Enforced streamed request-body size limits.
- Bounded file, artifact, Git, synchronous execution, and async job output.
- Hardened state/log/database permissions.
- Stopped treating worker-generated stdout/stderr as trusted model provenance.
- Moved Git inspection into the read-only Bubblewrap sandbox.
- Added Python 3.11/3.12 CI and security regression coverage.
