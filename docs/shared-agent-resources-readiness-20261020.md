# Shared agent resources — development candidate, 2026-10-20

**NOT DEPLOYED. Not a 38/38 tool success claim.**

## Confirmed source inventory

- Canonical Obsidian workspace: /home/yeli/repos/obsidian
- 38 required commands: tools/agent-tool-policy.json
- Canonical task-triggered skills: AgentSystem/agent-memory/skills/INDEX.md
- Additional adapters: Toolbox/claude-skills
- Additional policy references: AgentSystem/agent-memory/boot, policies, loaders
- Initial A7Dev generic-sandbox audit: 13 of 38 required commands resolve;
  this is not a model worker smoke result.

## Candidate implementation (development checkout only)

1. The operator provisioner copies a bounded allowlist of Obsidian documentation,
   scripts-as-data, the canonical tool catalogue, and skills into a *root-owned,
   immutable release snapshot*. Symlinks and oversized files are rejected;
   compiled bytecode, live auth directories and arbitrary tool installers are not copied.
2. A separate toolkit stores standalone native ELF tools found in explicit local
   source directories, plus the narrowly reviewed first-party run-quiet shell
   utility. Every copied program receives a SHA-256 receipt.
   A required command with missing or unsupported dependencies remains
   **not_bundled**, not silently installed or called available.
3. The confined development worker checks root ownership, non-writability,
   allowed release paths and tool hashes, then mounts Obsidian resources and
   the toolkit read-only. No editable Obsidian source tree, host HOME or broad
   host executable directory is mounted.
4. Delegated task packets point to the task-triggered skills index only when
   the snapshot is actually configured. No skill is automatically executed.
5. The candidate verification script now runs the standalone shared resource
   checks after the existing full pytest and security suites.

## Proven offline

- Synthetic snapshot and digest repeatability
- Canonical skills and Toolbox adapter copying
- Symlink/file escape rejection, pyc exclusion, bounded file selection
- Tool inventory missing commands correctly classified
- Fail-closed trust check against mutable local resource paths
- Read-only bwrap mount argument topology with namespace isolation retained
- Static Python compilation and verifier shell syntax

Run: python3 tests/verify_shared_agent_resources_offline.py

## Remaining release gates

- Execute full scripts/verify-development-candidate.sh **on the Asgard host**
  with its Python 3.13 venv; A7Dev generic exec cannot access that venv.
- Review source and the tool manifest; install or package the remaining
  non-native/complex tools with their verified runtime closures before
  advertising all 38 tools as executable. Check actual tool execution as
  each named worker, not merely PATH discovery.
- Perform real worker smoke tests on at least two different project workspaces
  showing the pinned Obsidian skills index is visible and not writable.
- Jax's host Headroom (127.0.0.1:9787) remains inaccessible from isolated
  workers. No loopback/host-network exception is included in this patch.
  A tightly scoped, separately audited bridge and provider smoke are needed.
- Do not conflate provider credential refresh with tools. Provider-specific
  valid token/quota/routing checks must be recorded independently.
- Obtain independent security review and pin a release artifact. Only then
  perform controlled operator-only deployment with rollback.
- Production A7 remains unchanged; A7Dev is the staging gateway. The
  proposed steady state is two gateways delegating to one isolated worker
  service and the existing provider accounts.
