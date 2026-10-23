# Handoff — one AgentPorter development environment, two production hosts
Date: 2026-10-22
Decision: **one shared development environment on Asgard; two independent production deployments (Asgard and BCC).** No standing BCC-dev instance initially.
Status: **deployment PLAN only**. Do not install, restart, rotate keys, reconfigure tunnels, commit, or push while drafting or verifying this plan.

## Architecture and responsibility

```text
                    Source of truth: reviewed GitHub repository
                                      |
                         approved, immutable release
                                      |
                         +------------+-------------+
                         |                          |
Asgard host:             |                          |        BCC host:
  A7Dev (development)    |                          |
  separate UID/port 8876 |                          |
  developer tests        v                          v
                    A7 production              BCC production
                    port 8765 (verify)         host-local port (verify)
                    own UID/config/key         own UID/config/key
                    own tunnel + plugin        own tunnel + BCC plugin
                    Asgard workspaces          BCC workspaces / capabilities
```

Asgard development is the only *persistent* development gateway. Both production instances independently run a **reviewed immutable release**, with host-local workspaces, credentials, policies, logs, and rollback. Do **not** route BCC production's Git/files/exec operations through A7Dev on Asgard or share production credentials/state between hosts.

**When BCC-specific validation is needed**: create an ephemeral BCC staging/test instance or isolated test harness on BCC with a different port, service identity and keys; destroy it after acceptance. Add a permanent BCC-dev only if host-specific development becomes frequent, difficult to reproduce in ephemeral staging, or operationally justifies another always-running service. Source stays unified.

## Verified documentation versus unresolved current state
- Asgard A7Dev is an isolated development gateway; source docs identify development listener `127.0.0.1:8876` and A7 production `127.0.0.1:8765`.
- Prior Asgard production readiness reports HOLD: production agent delegation and network/publication controls were not cleared for live promotion. Recent independent v19/deployment evidence may supersede parts of those older reports, so **re-audit installed fingerprints and newest artifacts** before selecting a release.
- A proposed Asgard production→development separate-UID delegation relay exists only as an unactivated source design in `docs/production-relay-activation-gates.md`. Do **not** turn a mutable development gateway into an unreviewed production runtime dependency. For actual production delegation, choose a separately installed, immutable, appropriately confined worker execution tier; review and verify any relay design independently.
- BCC previously had BCC-specific AgentPorter actions and a port-8765 tunnel according to `docs/venkata-diagnostics.md`, but its **live installation status, current URL, OS, service identity, available tooling and policies have not been verified in this session**.
- `docs/deployment.md` forbids automated/agent-triggered production activation: deployments are owner-triggered using reviewed immutable source at an exact SHA. Retain this restriction on both hosts.
- A7Dev Git commit/push permissions have a separate handoff: `docs/HANDOFF_A7DEV_GIT_COMMIT_PUSH_REPAIR_20261022.md`. Treat Git repair as a publication prerequisite, not authority to deploy.

## Phase 0 — environment inventories and constraints (read-only)
1. Asgard: enumerate A7Dev/A7 systemd units, actual service user and process, health, bound port, tunnel identity/forwarding, live source fingerprint, installed release digest, workspace policy, agent roster, upstreams, Git checkout/remote/branch divergence, and rollback state. **Redact credentials**.
2. BCC: perform the same local inventory by a BCC-local operator/agent. Identify whether AgentPorter exists, whether old Agent7 actions are still active, Python/uv/bubblewrap/systemd prerequisites, bind ports, hardware/OS constraints, allowed repo roots, runtime identity, key storage, network egress, and host-specific integrations (e.g. Venkata SSH).
3. Compare host-specific configuration and data access. Distinguish public interfaces shared by package code from machine-specific tools/allowlists. No secret files inside the Git checkout or release artifact.
4. Identify current production users and jobs, maintenance/rollback constraints, any existing tunnels/plugins, and any available test windows; **no guessed BCC settings**.
Deliver a preflight inventory and unresolved differences before selecting a release.

## Phase 1 — establish a single release source of truth
1. Finish the A7Dev Git capability repair safely; classify outstanding edits, untracked artifacts/archives, secrets and multiple branches/worktrees; reconcile history and independently verify actual GitHub remote/branch. No bulk `git add -A`, no force-push.
2. Pick a reviewed, immutable source commit on an explicitly approved release branch/tag. Record full Git commit SHA, build inputs/lockfile, artifact SHA256, policy/template version, test results and independent audit.
3. Run full post-change unit/integration/security verification, negative authorization tests, sandbox boundary tests, network-egress tests, Git capability tests and authenticated tool smoke tests. Account for Python/OS differences between hosts; if binaries must differ, attest both builds against the same source.
4. Before release, clear outstanding production blockers: no unconfined agent execution under the production service identity; no uncontrolled publication/network egress; no unsafe relay or auto-activation route. Provider model availability is separately verified and may be partly blocked by quota/credentials.
5. Define a host-neutral installation artifact and **two distinct, owner-managed production configuration sets**. Restrict workspace IDs and permissions deliberately per host. Default deny.

## Phase 2 — canary and deploy Asgard A7 production (human-controlled)
1. Preserve current A7 production binary, service unit, config, tunnel, rollback release, job state and fingerprint. Confirm production deployment tool is immutable and outside all agent-writable repositories.
2. Test the approved exact-SHA artifact in a disposable isolated staging environment, then run owner-controlled immutable release activation using the reviewed `docs/deployment.md` mechanism (or a newly independently audited equivalent, if runtime architecture changed).
3. Verify health, authenticated/unauthenticated requests (401 expected without key), workspace authorization (403 for forbidden access), sandbox and separate-UID execution, bounded provider dispatch for approved identities, correct GitHub remote allowlist if production Git push is intentionally granted, and rollback.
4. Repoint/enable the **A7 production ChatGPT plugin/tunnel only after acceptance**; do not silently switch the A7Dev tunnel or reuse its API key.
5. Keep A7Dev running independently. No production execution from mutable A7Dev code.

## Phase 3 — stage and deploy BCC production
1. On the BCC machine itself, perform an **ephemeral BCC staging run** of the same reviewed source release with separate local test port, keys, state, and limited sample workspaces. Do not equate Asgard tests with BCC host acceptance.
2. Validate BCC-specific path mappings, filesystem owners, UID/GID, Bubblewrap and host restrictions, shell/Git abilities, model providers, allowed network destinations, local operations, and any explicitly approved Venkata SSH access. Unavailable capabilities should be disabled rather than inferred to work.
3. Install a separate production AgentPorter instance under a least-privilege service identity (subject to compatibility review for any BCC-host SSH integrations). Use distinct BCC secrets, service config, state, operator-managed immutable release, and rollback. Do not copy Asgard key files.
4. Create/connect a **separate BCC ChatGPT plugin** and isolated BCC tunnel (OpenAI secure tunnel with explicit header injection only if confirmed supported and configured; or another reviewed authenticated ingress). Verify exact intended host, URL, injected header, auth rejects, allowed workspaces and negative cross-environment tests. Never embed transient tunnel hostname in shared package code.
5. Canary BCC-specific read-only tools first; enable bounded write/Git tools only after adversarial and end-to-end acceptance. Protect BCC-local data and approvals separately.

## Phase 4 — promotion and operations
- Release flow: feature work → A7Dev tests → signed/reviewed exact commit/artifact → Asgard production acceptance → BCC host staging + production acceptance (or independent host rollout order based on risk).
- Production activation on each host remains **human initiated**; A7Dev may prepare and inspect candidates but must not have a writable path to production services/credentials or an activation trigger.
- Release may be **version aligned** without simultaneous cutover: each host has an independent release pin and rollback. Track deployment status/fingerprint independently.
- Health/alerts: tunnel status, API auth failures, workspace denials, unexpected deployment fingerprint, egress anomalies, model delegation success/quota, disk/runtime health and audit log integrity. Logs never contain keys.
- Rollback immediately for failed auth/scope/sandbox checks, wrong host/plugin route, fingerprint mismatch, abnormal worker privilege, or inability to account for Git remote/branch.
- If BCC needs continuous host-specific code changes, reconsider persistent BCC-dev using measured frequency and staging cost; avoid preemptive service sprawl.

## Exact acceptance gates
- [ ] One reviewed code line and artifact provenance; two independent production configs/credentials.
- [ ] A7Dev Git commit/push path fixed and tested without opening production file access.
- [ ] Asgard A7 production immutable release installed by authorized owner; negative/positive tool checks passed; rollback rehearsed.
- [ ] BCC on-host staging passed; immutable BCC production installed by authorized owner; distinct tunnel/plugin, auth, workspace permission, sandbox, Git and rollback checks passed.
- [ ] No production service depends on mutable development runtime or shares dev key material.
- [ ] Both ChatGPT plugins reach the **correct** host and workspace; cross-host and unauthenticated operations denied.
- [ ] Full evidence matrix: host, service, version SHA, artifact hash, fingerprint, tunnel ID/name (not secret), tested permissions, measured pass/fail and owner acceptance.

## Local agent instructions
Produce (a) an updated live two-host inventory, (b) a release/dependency blocker matrix with explicit HOLD/GO, (c) tested rollout and rollback procedures for each host, and (d) a BCC plugin creation/connection checklist. Avoid any deployment side effect until a reviewed candidate and owner approval exist. Record unverified items clearly. Separate BCC owner actions from Asgard actions.

Primary decision: **1 dev (Asgard) + 2 prod (Asgard, BCC). No long-running BCC dev for now.**
