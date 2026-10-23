# All-project A7Dev access — approved repair, installation pending authentication

**Latest checkpoint: live verified.** The owner completed corrected reactivation successfully; release `20261021T232414.837654Z` is active, public/local fingerprints match, 41 ordinary project scopes are enabled and Jax completed jobs in Qman/m3-poc. See the [final reactivation closeout](A7DEV_PROJECT_ACCESS_RETRY_20261021.md). **Do not rerun either installation or reactivation command after this success.** The original proposal and verification record below are retained as historical evidence.

Owner instruction: “can you mkae sure all repo/folders are unblocked? approved, get these done”. Approval is recorded. The repair is prepared and independently reviewed; live installation has not occurred because `sudo -n true` returns **a password is required**. This is local OS authentication, not a request for approval again. A7Dev remains on v19 and production A7 is unchanged.

## Exact owner action

Run as yeli in the existing terminal:

```bash
cd /home/yeli/agent-work/agentporter-dev
bash scripts/install-a7dev-project-access.sh
```

The script requests the sudo password locally. Repository Python/shell payloads never execute as root: the orchestrator runs as yeli, the existing immutable installer runs as root, and the frozen authorization/acceptance scripts run as `agentporter-dev`. No credential contents are printed. Pause other A7Dev callers for the installation window; an active job/admission check stops before disruption. Do not rerun blindly after a failure; retain the printed backup/evidence paths.

Runner SHA256: `97d9ed36e674c965a22c4cfd08e30e0f0e4bb28d306b179f8d524c665e2d8e87`.

## Frozen target and scope

- Version **`20261021T232414.837654Z`**.
- Archive `/tmp/a7dev-project-access.tgz`, SHA256 **`c2924acec4e2a5bb15b36c41891929179f614c211a79a5a57f5b53e258d28566`**.
- Package fingerprint **`099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315`**.
- Exact v19 base SHA256 `701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80`; 26,359 candidate payload entries. Six access modules, two inert operator scripts and two venv release-path relocations differ. All other payload entries are preserved.
- All **41 ordinary registered projects** retain read/write/offline execution and gain **read-only delegation**, including Qman, m3-poc, IRVRI, worktrees and the registered projects under shiny.
- `obsidian`, `agentporter`, `AgentPorter`, `asgard-hermes-review` and umbrella `repos` remain protected read-only public scopes. These are intentional boundaries, not unrestricted host-folder access.
- Public HTTPS remains Cranary-only; 16 MiB/60-second/no-redirect binary acquisition and strict provider networking stay unchanged. Wei remains `opencode/glm-5.3-flash-free`. Existing accounts, credentials, model routes, resource limits and production relay status are preserved.

Exact public policy proposal: [all-project policy](examples/a7dev-all-project-delegation-policy.yaml), SHA256 `b7fe90d3872896f114944affbce5a4c84ddcadf82c32e37b7b0f9f07e6121c0b`.

## Corrections

1. Public readiness intersects caller scope, registry flags and the launcher's exact admitted workspace roots. A workspace-specific `list_agents` can no longer promise public dispatch for an excluded project. MCP dispatch denials expose their authorization reason; REST retains 403.
2. The service-UID helper adds dispatch/execute grants for the exact 41 project roots and extends runtime admission without changing other runtime fields. Newly admitted roots are worker-read-only; shiny's parent admission becomes read-only so approved read-only child roots can coexist. Any writable parent/child/grandchild combination remains denied.
3. Bounded listings skip/log unreadable incidental child directories while explicit requests for private roots remain denied. Read-only worker launches mask unreadable descendants with empty mode-0000 read-only mounts. Host ACLs/modes are not relaxed. Root scan failures, path/symlink races, other I/O failures and writable requests still fail closed.
4. Read-only external worktree control files are masked empty; external Git metadata/configuration is never imported. Native workers can inspect the approved files, while Git inspection continues through the separately scoped offline Git tools. Writable external worktree delegation remains blocked.

Affected package files: `client_policy.py`, `server.py`, `rest/routers/agents.py`, `rest/schemas.py`, `agents/development.py`, `workspaces/bounded.py`. Operational files: authorization helper, public acceptance verifier, exact-delta candidate builder, owner runner, schema/policy examples, tests and evidence. Inherited/unrelated work remains uncommitted and preserved.

## Verification and current live evidence

- Complete source gate: `bash scripts/verify-development-candidate.sh`: **1,568 passed + 24 subtests**, all six standalone security verifiers passed. One upstream Starlette/AnyIO deprecation warning.
- Separate reviewer's native focused suite: **143 passed**; every candidate/base payload entry and both archive hashes independently streamed and verified. Four injected owner-runner failure cases passed. Two recovery gaps were corrected before final review.
- Author native launch/file-bound tests: **107 passed**. Authorization helper tests: **29 passed**. These use synthetic credentials, not provider accounts.
- Public baseline sweep across all 46 workspace IDs: all **41 ordinary projects passed offline Python and exclusive temporary create/read/delete probes**. Existing listings failed for m3, agentporter-dev, agentporter, AgentPorter and repos on private child directories; the prepared listing correction addresses those errors. Qman/m3-poc Git checks and protected execution/network denials passed.
- Exact frozen artifact full regression gate: **1,568 passed + 24 subtests**, all standalone verifiers passed, pytest 88.02 seconds; [artifact gate log](evidence/a7dev-project-access-20261021/artifact-gate.log). Its isolated harness permits only two recorded interpreter-path relocations and omits one unrelated unreadable historical build script. The immutable archive is unchanged by the harness.
- New installed public scope, native Jax dispatch in Qman/m3-poc and live rollback: **NOT verified / not installed**. The owner runner performs public access/scope/denial acceptance, then two real read-only Jax checksum challenges. External provider quota does not undo already validated access.

Provider quota and tool availability remain separate: Phil is deferred, Argie's unexplained ACL request stays blocked, and Ming's last attempt was quota-blocked. No account/model substitution is part of this repair.

Evidence: [build](evidence/a7dev-project-access-20261021/build.json), [independent review](evidence/a7dev-project-access-20261021/independent-review.json), [source gate](evidence/a7dev-project-access-20261021/source-gate.log), [public baseline](evidence/a7dev-project-access-20261021/public-access-before.json), [index](evidence/a7dev-project-access-20261021/sha256.json).

## Installation and rollback behavior

The runner freshly verifies pinned archive/installer/current policy/HTTPS hashes, zero active jobs and existing v19. It backs up the four affected configuration files under `/var/backups/agentporter-dev-project-access-20261021T232414.837654Z`, stops only A7Dev, rechecks jobs, installs the immutable candidate, and uses the service-UID helper to generate and apply a hash-bound policy plan. It waits for HTTP readiness before validating actual public/local fingerprints, all project access, effective delegation scope, free Wei's configured route and denials. Production PID/release must match the pre-install snapshot.

Configuration writes have private service ownership, fsync-backed backups and guarded partial-transaction recovery under `/var/lib/agentporter-dev/config/project-delegation-recovery-v1`. A pre-provider acceptance failure restores those exact policy/registry bytes and then the **new installation receipt's exact v19 runtime/release pair**. It never guesses an old v12 receipt or overwrites SQLite. If an interrupted immutable install has no receipt, a changed pointer/config prevents unsafe restart and requires inspection. Failure to stop the service prevents rollback writes.

After public scope/access acceptance, real-provider Jax challenges run separately. A provider quota/error leaves validated access active and records the failed job. Any live rollback is recorded by the runner; no live rollback demonstration has yet been performed.

## Binary tool exposure

The running v19 public MCP server already lists and successfully invokes `https_download`; it downloaded and verified the requested 2022-06-30 snapshot without this installation. ChatGPT must refresh its existing a7dev connection metadata and enable the discovered tool. See [live discovery, receipt and exact payload](A7DEV_BINARY_DOWNLOAD_DISCOVERY_20261021.md). That account refresh cannot be performed with the tools exposed in this Codex session.

Implemented → source/native tests passed → independently reviewed → **installation pending local sudo authentication** → new live delegation acceptance pending. No claim that all projects are already live-unblocked is made.
