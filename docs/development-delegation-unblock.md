# Development delegation unblock — seven workers

Status: separate development gateway is healthy and seven OS confinement checks
passed after operator provisioning. Authenticated smoke tests succeeded for Liz,
Prof and Ming, but Prof's file-reading audit returned `NOT_AUDITED` because the
installed snapshot lacks the Codex helper. The checkout includes helper packaging,
Wei proxy and Argie model-selection repairs; an operator refresh and subsequent
live checks remain required. Production fallback remains forbidden.

## Problem
All registered workers are advertised as blocked_pending_os_confinement. The
JobManager has no start_confined_agent_job implementation. The broker requires
that method, and the public tool refuses any worker marked non-delegatable.
A status-flag-only change cannot make delegation work.

## Required design
- Create a separately configured development-only agent launcher and identity.
  Never run arbitrary CLI workers as the production service user.
- Kernel-enforced filesystem isolation: writable only for the selected
  development workspace and a private per-worker scratch directory. Mount
  source code, tools and system libraries read-only; do not mount host home,
  SSH keys, cloud credentials, production config, or service sockets.
- Per-worker credential mounts, narrowly scoped and isolated from other
  workers. Do not inherit host environment, PATH hooks, proxies or auth agents.
- Network allowed for development model/API access only under an explicit
  operator-enabled development profile; production generic execution remains
  offline. Test DNS and network connectivity separately.
- A common confined launcher for jax, liz, prof, phil, wei, ming and argie;
  no fallback to raw host Popen. Detect missing executables or credentials
  individually; never claim unavailable workers are ready.
- Read-only and writable workspace modes enforced by mount topology, not
  CLI prompts. Git metadata read-only; commit, push, deploy, publish and
  production policy changes remain gated.
- Job timeouts, process group termination, bounded output, provenance and
  per-worker audit receipts.
- Enable public delegatable only after a live launcher probe confirms the
  backend and requested worker are executable under the selected profile.

## Acceptance tests
1. All seven agents can be dispatched when their CLI and credentials exist.
2. Read-only review cannot write to workspace, Git metadata or host paths.
3. Writable review can modify designated source files but not .git.
4. Cross-workspace and cross-worker credentials are inaccessible.
5. Networked development model calls work; production generic exec stays offline.
6. No direct unconfined host subprocess path, even when the launcher fails.
7. Async job status/results, cancellation and timeout work.
8. Fail closed when development profile disabled or confinement unavailable.
9. No change to installed production until separately approved.

## Immediate audit
Prof can audit the scoped HTTPS stage after the development launcher is
implemented and independently tested. Do not represent the current state
as unblocked.

## Implemented development boundary

`agents/development.py` is the common launcher. `JobManager` uses it only when an
explicit `development-runtime.yaml` exists. The offline generic Bubblewrap
backend retains its production policy. Missing identity, credentials, executable,
or a failed live isolation/executable probe keeps that worker non-delegatable.
The runtime checks the host UID, not merely the UID visible inside a namespace.

Each job receives a private home with only that worker's selected authentication
files, a selected workspace, read-only executable code and libraries, an isolated
PID/mount/network namespace, and bounded job logs. Git metadata is protected by
mounts; unsupported metadata layouts fail closed. Workspace secret directories
and environment files are hidden. No host home, auth-agent socket, or inherited
environment is passed to workers.

Network access uses a per-job Unix CONNECT endpoint and a loopback bridge inside
the worker network namespace. The host endpoint resolves DNS, rejects non-public
addresses, pins the selected address, and permits only port 443. The worker cannot
reach host loopback services or perform direct host-network connections. Clients
must support HTTPS proxy configuration; provider access still requires a real
authenticated launch test after provisioning.

## Asgard development instance

The separate development configuration, state, cache and evidence are staged at
`/tmp/agentporter-development-asgard/`. This is temporary operator staging, not a
production installation. The development systemd user unit is
`agentporter-development.service`, listening only on `127.0.0.1:8876`. Its API key
is newly generated and private in `config/secrets.env`; it is unrelated to the
production key. Never print it or copy production `secrets.env`.

Eight explicit workspaces are registered: `m3-poc`, `insider`, `PAGe`, `m3`,
`obsidian`, `shiny`, `cranary`, and `agentporter-dev`. Broad repository umbrella
registration, auto-discovery, production AgentPorter, SSH and SciNet training
authorities are excluded from this configuration.

### Operator activation requirements

The Asgard provisioning helper defaults to a read-only validation/dry run. To
apply the reviewed development-only account, immutable installation, workspace
ACLs and separate gateway unit, run:

```sh
sudo /usr/bin/python3 -I /home/yeli/agent-work/agentporter-dev/scripts/provision-development-runtime.py --apply
```

This stops only the staging **development** user unit and starts the separate
development system unit on the same loopback port. It preserves the staging
development API key privately and does not restart the production gateway.
Missing provider credentials remain blocked; the helper never borrows another
identity's authentication. Real provider smoke tests and Prof's audit must follow
successful provisioning. The helper's dry run and five focused tests, including
an actual relocated interpreter/dependency/source import, passed without applying
privileged host changes.

1. Provision an unprivileged **host** account named `agentporter-dev`, with its own
   home and state directory. Its UID must differ from production UID `1000`.
   Do not add it to the production user's group or expose the host home wholesale.
2. Install a reviewed, immutable snapshot of this gateway and dependencies outside
   worker-writable workspaces, owned by an operator account. Running the final
   active gateway from editable project source would allow future worker edits to
   change trusted launcher code. The current staging gateway deliberately rejects
   worker launches under `yeli`.
3. Grant that account traversal to explicitly registered development roots and
   appropriate project read/write ACLs. Keep production configuration, service
   credentials and directories inaccessible. Never grant blanket home access.
4. Provision separate, private credential copies per named identity, owned by the
   development account, and update the explicit source paths in
   `development-runtime.yaml`. Do not copy provider settings containing unrelated
   accounts, hooks, MCP servers, SSH/Git credentials, or production service keys.
   Jax/Liz/Prof need their respective Codex profiles; Ming needs his Claude
   credential. Phil uses his installed native Copilot executable and screened
   authentication data. Argie's existing login is stored at
   `~/.gemini/antigravity-cli/antigravity-oauth-token`; copy only this file into
   the same HOME-relative location for the confined worker. Do not import other
   Gemini accounts, settings, MCP configuration or hooks. Wei's authentication
   integration must use his approved interactive Go route.
5. Run only the development gateway as that account, using the separate config,
   state and cache. Repeat the real security integration tests and authenticated
   per-agent smoke tests. Enable availability only for workers whose runtime probe
   passes; report credential/provider failures individually. Do not alter or restart
   `agentporter.service`.
6. Dispatch Prof's read-only Cranary HTTPS audit through the verified backend and
   inspect his durable job result. Do not substitute another worker or host CLI if
   his confinement or authentication fails.

Account creation and ACL provisioning require operator privileges on this host:
`sudo -n true` reports that a password is required. No account, ACL, production
configuration or production service changes have been made by this implementation.

## Initial Asgard verification — 2026-10-20, before operator provisioning

The final full host run passed **1,003 tests and 24 subtests**, with no skips or
failures. One upstream Starlette/AnyIO deprecation warning remains. Test fixtures
isolate config, state and cache from production. This includes real Bubblewrap
launches with synthetic credentials for all seven identity names, read/write and
read-only modes, async results/cancellation/timeout/output bounds, credential and
workspace isolation, Git remount denial, and namespace restrictions.

Additional attack tests found and repaired inherited mount descriptors and a
workspace replacement race during mask discovery. The final launcher closes all
nonstandard descriptors in a fixed, isolated stdlib bootstrap before any worker
or proxy bridge executes. Workspace binding, mask discovery and Git protection
use the same pinned directory object. Independent real worker tests enumerate
namespace process descriptors and verify that source capabilities cannot bypass
read-only Git mounts. An isolated curl test reached public HTTPS with HTTP/2 200
through the per-job proxy. No named model worker ran under the production UID.

Final live checks on the separate development gateway:

| Check | Observed result |
|---|---|
| Authenticated health | HTTP 200, `healthy` |
| Workspace registration | HTTP 200, eight explicit workspaces |
| Public agent inventory | HTTP 200, exactly seven identities |
| Inventory without API key | HTTP 401 |
| All seven workers | `available=false`, `delegatable=false` |
| Prof read-only audit request | HTTP 403, missing `agentporter-dev` host account |
| Production service | PID and both start timestamps unchanged |

The common live blocker for **Jax, Liz, Prof, Phil, Wei, Ming and Argie** is the
missing development host account. Existing Jax/Liz/Prof/Ming authentication files
were observed by metadata only; separate development copies and real provider
authentication have not been verified. Phil's installed Copilot package and Node
have explicit narrow mount configuration; his provider authentication is also
unverified. Wei's expected dedicated credential is missing. No verified Argie
authentication source was found; unrelated Google credentials were not borrowed.

Prof's audit **has not run**. A packet with ten nonempty, SHA-256-recorded source
inputs is prepared at
`/tmp/agentporter-development-asgard/evidence/prof-audit-task.txt`; regenerate its
manifest if those source files change before dispatch. The refusal and live
checks are recorded in the same evidence directory.

Evidence retained locally:

- `/tmp/agentporter-final-host-tests.log`: full final test run.
- `/tmp/agentporter-final-security-review.txt`: independent security review.
- `/tmp/agentporter-public-egress-smoke.log`: real isolated public HTTPS check.
- `/tmp/agentporter-git-fd-closure-smoke.log`: descriptor escape regression.
- `/tmp/agentporter-development-asgard/evidence/`: gateway, audit and production
  service observations.

Implementation and staging are verified; actual seven-worker activation and
Prof's audit remain **blocked/incomplete** until the operator requirements above
are fulfilled. No commit, push, production deployment or production restart was
performed.

## Post-provisioning findings — 2026-10-20

The operator provisioned `agentporter-dev` (UID 994) and the separate system
development gateway. The production gateway remains PID 664960 with its original
start timestamp. The initial missing-account result above is historical.

Argie was incorrectly classified using an unverified placeholder
`~/.antigravitycli/auth.json`. His existing authentication file is
`~/.gemini/antigravity-cli/antigravity-oauth-token`, a private regular file.
An offline, credential-free Bubblewrap trace of `agy models` proves the CLI
looks up this HOME-relative token file. Its credentials were not printed and no
model inference was invoked. The runtime now supports this token-only mapping;
workspace `.gemini` data is masked and adjacent settings, hooks, MCP servers and
other Google credentials are excluded. This does not require a new provider
account, subscription or API key.

The installed development service's live probes found another integration issue:
`bwrap: Can't mount proc on /newroot/proc: Operation not permitted`. The unit's
`ProtectKernelTunables`, `ProtectKernelModules` and `ProtectControlGroups`
settings introduce mount restrictions incompatible with its unprivileged
Bubblewrap proc mount. The development unit must leave namespace creation to
the verified Bubblewrap boundary. It retains its separate UID,
`NoNewPrivileges`, `RestrictSUIDSGID`, private credentials, immutable installation
and worker namespace protections. No host `/proc` fallback or unconfined worker
execution is permitted.

An operator refresh of the reviewed provisioning helper is required to install
the corrected snapshot, authentication mapping and development unit. Sudo still
requires an operator password in this session. Until that refresh passes live
confinement and authenticated worker checks, delegation remains blocked and
Prof's audit has not run.

Wei also has an existing interactive credential at
`~/.config/opencode/go-key`. The provisioner copies it to the private development
vault with mode `0600`, preserving the source file. The runtime selects only
`opencode-go/glm-5.3-flash`, the approved Go endpoint and compatible transport;
it imports no other OpenCode providers or Vertex credentials. OpenCode reads a
private key-file reference, keeping key contents out of process arguments,
environment variables and receipts. The current CLI's standalone mode is used.
There is no provider fallback.

The refreshed operator dry run finds existing credential files for **all seven**
agents. This proves the original missing-credential classifications for Wei and
Argie were integration errors; it does not yet prove token validity or a
successful authenticated model call under confinement. No new provider accounts,
subscriptions or keys are required by these mapping repairs.

After these repairs the full host regression suite passed **1,018 tests and
24 subtests**, with one upstream deprecation warning and no skips or failures.
Log: `/tmp/agentporter-auth-repair-host-tests.log`. The host dry run validates the
installed account and corrected plan. Applying that plan and verifying real
provider authentication remain pending operator refresh.

## Prof pickup verification — 2026-10-20

Prof continued Jax's main session `01a159aa-57b4` after Jax reached his limit.
The checkout already contains the matching bundled Codex helper installation,
pinned read-only helper mount/probe, fixed namespace-local proxy bypass for Wei,
and bounded Argie model selection. These repairs are not yet in the live snapshot.

Executed locally outside the enclosing Codex sandbox:
- Focused confinement, egress, provisioning and delegation checks: 118 passed.
- Full regression: 1,027 tests and 24 subtests passed, one upstream deprecation
  warning. Log: `/tmp/agentporter-prof-pickup-tests.log`.
- Provisioner dry run passed and found credential files for all seven identities.
- Development system gateway is active (PID 1339037); health returned healthy.
- Production user gateway remains PID 664960, with both timestamps unchanged
  from 2026-10-19 21:21:27 EDT.

Saved provider results show Liz, Prof and Ming completed text-only smoke tests.
Prof's subsequent file-reading audit returned `NOT_AUDITED` due to the missing
installed helper. Jax's selected host-loopback provider remains unreachable by
confinement design; Phil reported a monthly quota error. Wei and Argie require
new live smoke tests after the pending fixes are installed. No successful
seven-agent activation or completed audit is claimed.

`sudo -n true` still requires a password. Operator action remains:

```sh
sudo /usr/bin/python3 -I /home/yeli/agent-work/agentporter-dev/scripts/provision-development-runtime.py --apply
```

Then repeat live provider and file-tool checks and Prof's read-only audit.
No commit, push, production restart, or privileged refresh was performed during
this pickup. Earlier sections retain historical observations; this section and
the opening status describe the latest verified state.
