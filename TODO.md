# AgentPorter TODO

AgentPorter is being developed by dogfooding: use it for real work, record friction or failures, then generalize only what real usage justifies.

## Current state

- Generic MCP package has been extracted from the original M3 gateway.
- Direct execution uses Bubblewrap with network disabled and a cleared environment.
- File, Git, artifact, async-job, and worker-agent tools exist.
- Worker CLI delegation is explicitly a different trust boundary from direct sandboxed execution.
- The public package is separated from machine-specific configuration/state.
- Audit hardening is in draft PR #1.
- Python 3.11/3.12 CI is green for tests that can run on GitHub-hosted runners.
- Bubblewrap namespace/security tests still need validation on a real Linux/WSL host because GitHub-hosted runners do not permit the required namespace operations.

## P0 — Before merging the audit-hardening PR

- [ ] Run the full test suite on the real WSL host, including all Bubblewrap security tests.
- [ ] Run the generic MCP smoke test against a live AgentPorter instance.
- [ ] Verify R, Python, async jobs, Git inspection, artifacts, and path-isolation behavior on WSL.
- [ ] Perform an independent code/security review of PR #1.
- [ ] Re-run secret/personal-data scan on the PR branch.
- [ ] Confirm no M3-specific aliases, model preferences, tunnel hostnames, private paths, or credentials remain in generic package code/docs.
- [ ] Review PR diff for accidental MCP contract changes.
- [ ] Merge only after the above checks are clean.

## P0 — Dogfood migration

Keep the existing M3 gateway available as rollback until AgentPorter proves parity in real use.

- [ ] Create/maintain the separate private M3 deployment repository.
- [ ] Move M3-specific instructions, aliases, routing preferences, tunnel setup, and local workflow policy into the M3 repo.
- [ ] Install AgentPorter in parallel with the existing M3 gateway.
- [ ] Translate local workspace registrations into `~/.config/agentporter/workspaces.yaml`.
- [ ] Translate local server/security settings into `~/.config/agentporter/config.yaml`.
- [ ] Keep secrets in `~/.config/agentporter/secrets.env`; never commit them to M3 or AgentPorter.
- [ ] Start AgentPorter on a separate local port.
- [ ] Run side-by-side parity checks against the old M3 gateway.
- [ ] Point M3 to AgentPorter only after parity passes.
- [ ] Keep the old gateway available for rollback during initial dogfooding.
- [ ] Retire the old gateway only after sustained successful use.

## P1 — Real-world dogfooding

Use AgentPorter for actual statistical/programming work rather than synthetic demos.

- [ ] Register one real repository with conservative permissions.
- [ ] Exercise read-only inspection first.
- [ ] Exercise edit → test → diff workflow.
- [ ] Exercise R analysis and plot/artifact retrieval.
- [ ] Exercise Python analysis and tests.
- [ ] Exercise long-running async jobs.
- [ ] Exercise independent worker review.
- [ ] Verify repo state before and after worker dispatch.
- [ ] Record every recurring annoyance, missing capability, ambiguous response, and unsafe workflow as an issue.
- [ ] Avoid adding abstractions until repeated real use demonstrates the need.

## P1 — Workspace permission model

Current capability flags are intentionally simple. Evolve only as usage requires.

- [ ] Evaluate whether `writable` should be split into explicit file read/write permissions.
- [ ] Evaluate separate permissions for execution, Git, artifacts, worker dispatch, and local HTTP.
- [ ] Add an approval model for higher-risk actions if real workflows need it.
- [ ] Consider explicit per-workspace executable/runtime allowlists.
- [ ] Consider per-workspace worker allowlists.
- [ ] Consider per-workspace maximum execution time/output limits.
- [ ] Preserve secure defaults: worker-agent dispatch and loopback HTTP remain opt-in.

## P1 — Worker-agent safety

Worker CLIs currently execute as the host user and are not kernel-isolated by AgentPorter.

- [ ] Investigate stronger containment for networked worker agents without breaking provider authentication.
- [ ] Evaluate container/sandbox patterns that mount only the target workspace plus narrowly scoped auth material.
- [ ] Add before/after Git-state verification around delegated mutation tasks.
- [ ] Add enforceable read-only support adapter-by-adapter.
- [ ] Reject read-only dispatch when an adapter cannot technically enforce it.
- [ ] Add explicit mutation reporting to worker results.
- [ ] Add worker timeout/output/resource controls separate from direct execution controls.
- [ ] Document residual host-user risk prominently until stronger isolation exists.

## P1 — Agent adapters and routing

AgentPorter core should know how to invoke workers, not the user's personal names or routing preferences.

- [ ] Keep Codex, Claude Code, OpenCode, and Agy as adapters rather than core assumptions.
- [ ] Move personal aliases, preferred models, and cost/routing policy to local/M3 configuration.
- [ ] Make adapter discovery robust across common installation paths.
- [ ] Add adapter capability declarations for read-only, model override, reasoning override, cancellation, and structured provenance.
- [ ] Add adapters only when there is a real user/test case.
- [ ] Define a small stable adapter contract before considering a plugin SDK.

## P1 — Provenance and observability

- [ ] Keep configured model, requested model, and actual/resolved model as separate fields.
- [ ] Continue reporting `actual_model: unknown` when the CLI does not expose trusted runtime metadata.
- [ ] Add trusted structured provenance parsers only for CLIs that provide machine-readable metadata.
- [ ] Never infer actual model from worker prose/stdout.
- [ ] Add structured tool/job audit events.
- [ ] Add useful correlation IDs between MCP calls, jobs, and worker dispatches.
- [ ] Define log retention/cleanup policy.

## P1 — Resource controls

Current timeout/output limits reduce risk but are not full resource isolation.

- [ ] Add CPU limits.
- [ ] Add memory limits.
- [ ] Add process/PID limits.
- [ ] Add disk/quota controls for job output and temporary files.
- [ ] Evaluate cgroups/systemd scopes for Linux.
- [ ] Keep platform-specific behavior explicit rather than pretending unsupported limits are enforced.

## P1 — MCP client compatibility

Preserve client independence.

- [ ] Continue validating Microsoft Copilot Studio / M365 Copilot.
- [ ] Test a second independent MCP client to catch client-specific assumptions.
- [ ] Test ChatGPT web custom MCP when the account/plan supports the required custom MCP capabilities.
- [ ] For ChatGPT web, verify remote MCP connection, authentication, tool discovery, read tools, write tools, async jobs, artifacts, and worker dispatch separately.
- [ ] Evaluate OpenAI Secure MCP Tunnel or another supported ingress option for ChatGPT instead of assuming Cloudflare Quick Tunnel.
- [ ] Test Claude/desktop or another local MCP client where practical.
- [ ] Keep client-specific setup instructions under `docs/`; do not put client assumptions into core modules.

## P1 — Remote ingress

- [ ] Keep localhost binding as the package default.
- [ ] Replace ephemeral Quick Tunnel usage in personal deployments with a stable ingress mechanism when needed.
- [ ] Document exact-host allowlisting.
- [ ] Document TLS/reverse-proxy expectations.
- [ ] Evaluate named Cloudflare Tunnel, Tailscale, and OpenAI Secure MCP Tunnel as deployment options rather than package dependencies.
- [ ] Never make public remote exposure automatic.

## P2 — Packaging and installation

- [ ] Keep versioning at pre-release status until dogfooding is stable.
- [ ] Add `agentporter init` only after the required local config shape stabilizes.
- [ ] Improve `agentporter doctor` to report actionable diagnostics without revealing secrets.
- [ ] Add workspace-management CLI commands only if manual config proves cumbersome.
- [ ] Decide supported Python versions from CI evidence.
- [ ] Decide official Linux/WSL support statement.
- [ ] Evaluate macOS support and a non-Bubblewrap sandbox backend.
- [ ] Consider Podman/container backend after the Bubblewrap path is stable.
- [ ] Do not publish to PyPI until security model, install flow, and license are settled.

## P2 — Testing and CI

- [ ] Add a self-hosted or suitable Linux runner capable of executing Bubblewrap namespace tests.
- [ ] Keep GitHub-hosted CI for portable unit/integration tests.
- [ ] Add explicit regression tests for every discovered security issue.
- [ ] Add MCP protocol-level integration tests, not only direct Python function tests.
- [ ] Add contract tests to detect accidental MCP tool name/schema changes.
- [ ] Add package install smoke tests from a clean environment.
- [ ] Add secret scanning.
- [ ] Add static analysis/linting only where it produces useful signal.
- [ ] Add coverage reporting after the suite stabilizes; do not optimize for a vanity percentage.

## P2 — API and MCP contract

Do not redesign the working tool surface prematurely.

- [ ] Keep current MCP tool names stable through early dogfooding unless a real problem requires change.
- [ ] Record tool-schema pain points encountered by M3/other clients.
- [ ] Define compatibility/versioning policy before a public stable release.
- [ ] Consider conceptual namespaces (`workspace.*`, `files.*`, `exec.*`, `jobs.*`, `git.*`, `agents.*`) without forcing a breaking rename.
- [ ] Add deprecation strategy before changing established tool names or fields.

## P2 — Documentation

- [ ] Keep package-vs-local separation documentation current.
- [ ] Keep the worker-agent trust boundary prominent.
- [ ] Add a minimal threat model for each newly exposed capability.
- [ ] Add a “dogfooding notes / lessons learned” document once enough real incidents accumulate.
- [ ] Add tested examples for R, Python, Git, artifacts, async jobs, and worker review.
- [ ] Keep personal M3 instructions in the private M3 repo; AgentPorter docs should remain generic.

## Decisions required before public release

- [ ] Choose a software license.
- [ ] Decide whether the package name/distribution name will remain `agentporter`.
- [ ] Decide release support policy and minimum Python version.
- [ ] Decide which operating systems are officially supported.
- [ ] Decide how security vulnerabilities should be privately reported.
- [ ] Decide whether worker-agent delegation is included in the first public release or clearly marked experimental.

## Release milestones

### v0.1 — Dogfoodable package
- Current MCP capabilities packaged generically.
- Linux/WSL local-first runtime.
- Stable local config/state separation.
- Security regression suite.
- M3 successfully migrated and used for real work.

### v0.2 — Hardened multi-client alpha
- Tested with multiple MCP clients.
- Better worker isolation/controls.
- Stronger resource limits.
- Stable adapter capability/provenance model.
- Stable remote-ingress documentation.

### v0.3 — Portable beta
- Additional sandbox backend where justified.
- Cleaner installer/init workflow.
- Broader platform testing.
- Contract/versioning policy.

### v1.0 — Public stable
- Documented and reviewed security model.
- Stable MCP contract.
- Reproducible install/update process.
- Release/license/support policy settled.
- Sustained dogfooding with no unresolved critical security blockers.
