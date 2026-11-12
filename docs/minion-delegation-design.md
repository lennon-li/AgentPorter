# Minion delegation on Asgard, BCC and Nida — design v2

Status: draft v2, 2026-11-11. v1 was audited by an independent reviewer (Fable);
this version incorporates that audit. Nothing here is deployed except the Asgard
ACL mitigation in §3.6. **[verified]** = observed on the live hosts
2026-11-10/11. Everything else is a proposal. Owner decisions are listed in §6.

## 1. Functional requirements (from the owner)

| ID | Requirement |
|----|-------------|
| FR1 | Every repo under `~/repos` on Asgard is auto-registered as a workspace; no manual step. |
| FR2 | ChatGPT and the owner can delegate an agent running on Asgard (Codex, Claude, Jax, …) to work on any registered Asgard repo, including writes anywhere in the tree. |
| FR3 | **Supervised mode:** an Asgard agent can delegate work to Minion; that work applies to the supervising agent's Asgard repo ("local to the main agent"). |
| FR4 | **Direct mode:** ChatGPT and the owner can delegate Minion directly; a direct job works on Nida's own repos ("local to Minion"). |
| FR5 | The execution host is always explicit in requests and results; nothing silently reroutes. |
| FR6 | ChatGPT reaches Nida only through Asgard. |
| FR7 | Minion is not limited to one fixture workspace; it can work on any registered repo of its host. |
| FR8 | Minion2 can write to Asgard repos **and** BCC repos. |
| FR9 | Network reachability (owner, 2026-11-11): BCC ↔ Asgard both ways; BCC must **not** reach Nida directly; Nida may reach both BCC and Asgard. BCC's Minion work therefore routes BCC → Asgard → Nida. This partially reverses the Nov 7 hardening (which denied BCC → Asgard). |

Owner wording for FR8 is "make sure minion 2 can write to Asgard and BCC". The
audit reads this as **Minion itself doing the editing**, not only advising a
supervisor that edits. v2 adopts that reading (§3.2); confirm in D1.

## 2. Current state

### 2.1 Asgard
- **[verified]** Gateway `minion-variants-20261109-v1-gateway` exposes 10 `nida_*` MCP tools (3 in `server.py`, 7 read tools); BCC's live gateway exposes none.
- **[verified]** All `nida_*` tools accept only `workspace_id == "nida-local"` (`nida_virtual_scope.py:37`). ChatGPT's calls with `daoist-widget` and `Qman` were rejected (8/8 in 12 h).
- **[verified]** `nida_dispatch(..., worker='pi'|'opencode', read_only=True)` runs pi/opencode on Nida via the LAN broker; refuses `read_only=False` (`server.py:526`).
- **[verified]** `minion2` = `qwen3.8-flash-next-iq3_xxs`, loaded, default, execution enabled; it is the only loaded model (`/v1/models`). `minion1` disabled.
- **[verified] FR1 not fully met:** `~/repos` has 42 directories; 38 are registered. Not registered: `AgentPorter`, `gambling`, `m3`, `obsidian`. **[verified 2026-11-11]** `AgentPorter`, `m3`, `obsidian` are deliberate tombstones in `discovery-ledger.json` (all operations denied). `gambling` has mode `777`; admission allows only 700/750/755/770/775. Owner decisions: lift tombstones or keep; `chmod 775` to admit `gambling`.
- **[verified]** Broker serializes reads only (`_read_capacity=BoundedSemaphore(1)`, non-blocking → `inspection_busy`, `nida_lan_gateway.py:140,223-228`); `infer`/`dispatch` have no gate.
- **[verified]** Production is sealed: package fingerprints, control scripts, unit files and storage manifests are hash-pinned in a chain. Any code change needs a new sealed release generation.

### 2.2 BCC
- **[verified]** `nida-inference.yaml` and `nida-mac-jobs.yaml` are `enabled:false`; `nida_pi`/`nida_opencode` are in the shipped roster (`NIDA_AGENT_CLIS`) and accepted by `dispatch_agent` ID validation, but hidden when unconfigured and `LOCKED` in `action-policy.yaml`.
- **[verified]** BCC repos carry no named ACL users. Overlay test through the real `Qman` projection as worker UID 997: new file in a subfolder and edit of an existing file both succeed. BCC does not have the Asgard write defect.

### 2.3 Nida
- **[verified]** macOS 27.2. `~/repos` is a symlink to `/Volumes/LLM/repos` (APFS, case-insensitive); 38 repos.
- **[verified]** Names overlap with Asgard (`daoist-widget`, `Qman`, `ALL`) and differ only by case in places (Nida `epiWeave`/`OPCC`, Asgard `epiweave`/`opcc`).
- **[verified]** Working trees can be dirty: `daoist-widget` has 6 dirty entries on Nida, 3 on Asgard; both share `origin github.com/lennon-li/daoist-widget`.

### 2.4 Existing uncommitted code (BCC-built, staging-accepted 2026-11-04, production off)
- **Job-scoped inference** (`nida_inference_*`): per-job socket + fixed client inside a confined worker; host forwards over pinned SSH to Nida `127.0.0.1:8000`. Exact `(agent, workspace, model)` tuples; no lock.
- **Native Mac dispatch** (`nida_mac_*`, agents `nida_pi`/`nida_opencode`): snapshot of the **host** workspace → pi/opencode on the Mac under Seatbelt (no fork, no shell, no Git mutation) → delta imported into the host's workspace transaction (`nida_mac_jobs.py:167-189`). This is Minion editing the host's repo: the basis for FR3/FR8.

## 3. Design

### 3.1 Host-qualified workspace identity (FR5)
- Canonical ID `<host>:<name>`, host ∈ {`asgard`, `bcc`, `nida`}. IDs are byte-exact; on Nida, names that collide case-insensitively are refused.
- `list_workspaces` returns qualified IDs, host and path. Every job result reports host, qualified ID and path.
- Bare names mean the gateway's own host for that host's agents (existing ChatGPT prompts use bare names). Direct Minion jobs require `nida:`.
- Explicit refusals, e.g. direct Minion on `asgard:x` → "Minion direct jobs run on Nida repos; dispatch an Asgard agent with Minion, or dispatch Minion on `asgard:x` in supervised form." Refusal text on BCC must not reveal Nida reachability.

### 3.2 Minion on a host repo — Asgard and BCC (FR3, FR8)
Two forms, both writing only to the host's own workspace transaction:
- **3.2a Minion as worker (primary, meets FR8 as worded).** `dispatch_agent(agent="minion", workspace_id="asgard:<repo>" | "bcc:<repo>", worker="pi"|"opencode")`, or the same launched by a supervising agent. Uses the native Mac dispatch path: host snapshots its workspace, Minion edits the snapshot on the Mac with file tools, host verifies and imports the delta into its own transaction. The repo never changes on Nida.
- **3.2b Minion as helper.** A host agent job with `minion=true` gets the per-job inference socket; the supervisor edits files itself.
- Route admission: admitted agent × any registered workspace of that host × admitted Minion registration (FR7), replacing exact tuples.
- FR6 on BCC: ChatGPT gets neither form on BCC. BCC jobs that use Minion are started by the owner directly or by BCC-local supervisors (D2).
- Transport: Asgard — through the existing LAN broker, extended to admit the worker service for `infer` and Mac-dispatch operations only (single Nida credential holder; needs a new sealed broker release). BCC — its own pinned SSH identity as in the existing BCC design (BCC has no broker).

### 3.3 Direct mode on Nida repos (FR4)
- `dispatch_agent(agent="minion", workspace_id="nida:<repo>", ...)`; `nida_dispatch` kept one release as a deprecated alias.
- Nida registry: direct children of `~/repos` (resolving the single root symlink to `/Volumes/LLM/repos` explicitly); same name rules as Asgard; case-collision refusal; owner `yeli`.
- **Mac-side publisher (new, must be specified before build):** a launchd-owned publisher identity holds a per-repo lock; the job works on a snapshot in its job directory; the publisher validates the delta (paths inside the repo, no `.git`, no symlink escapes, size bounds) and applies it only if the target files are unchanged since the snapshot.
- Dirty trees: refuse the job if the target repo has uncommitted changes, unless the owner explicitly allows it (D4).
- Git: working tree only; no commit, no push (D4).
- Shell tools allowed (D5, owner decision 2026-11-11); see §3.7.

### 3.4 Concurrency (single loaded model)
- One gate in the Asgard broker covers all paths: ChatGPT `nida_infer`/`nida_dispatch`, Asgard Minion jobs, direct jobs. BCC's path must take the same gate. Proposal: BCC Minion requests go through a small Nida-side admission (one lock file under `/Volumes/LLM`) shared by both entry points.
- Busy → explicit `busy` with retry hint; no queue in phase 1; never swap models under a running job (D3).

### 3.5 Model availability
- Minion down → explicit `unavailable`; no cloud fallback; receipts record it.

### 3.6 Asgard write path (prerequisite for everything on Asgard)
- **Applied 2026-11-10 22:53:** named `user:993`/`user:994` ACL entries (access and default) removed below every project root in Asgard `~/repos` (41 projects; for example `AgentPorter` 222,156 entries, `daoist-widget` 370). Project-root ACLs left byte-identical (discovery pins them); `.git` left untouched. Backups: `~/.local/state/acl-fix-20261110/<project>.before.acl` on Asgard; restore with `setfacl --restore=<file>`.
- **[verified]** Overlay test through the real `daoist-widget` projection as UID 993: new file in `scripts/` and `ios/`, edit of existing `README.md` — all succeed (previously `EINVAL`). Discovery stayed `UNCHANGED` throughout; fail-closed handler did not fire.
- Limitations: (a) a new top-level folder inherits the root's default ACL and reintroduces the defect for that folder; (b) `.git` still carries named entries. In-sandbox `.git` is read-only, and `allow_commit` writes go through the host Git service directly on the view (no overlay copy-up), but this is untested (A3).
- Durable fix (later, staging first): add `993→900993`, `994→900994` to the storage idmap. Tested on scratch data. Pins to change: `prepare-production-storage.py:184,185,204,445,625`, `prepare-staging-storage.py:172-191,338,484,655`, `common_publication.py:139,145` (worker and gateway), production manifest and start-gate digests. BCC is not affected and needs no change.

### 3.7 Shell tools for Minion jobs on the Mac (D5)
Applies to every Minion job that runs on Nida: direct jobs (§3.3) and Minion-as-worker jobs on host-repo snapshots (§3.2a). In the snapshot case, commands run on macOS against the snapshot, not on the Linux host.

Why this is a design change: the existing native runner's isolation depends on a **no-fork** Seatbelt profile plus a session-leader launch (`docs/nida-inference-gateway.md` §Native Mac worker dispatch). Shell tools need fork/exec, so that guarantee no longer holds and must be replaced.

Proposed confinement (to be audited before build):
- **Per-job macOS user** (pool of pre-created unprivileged accounts, e.g. `_minion01…`) or, if rejected, a single dedicated `_minion` account. Not `yeli`. File access is enforced by the account plus Seatbelt, not by Seatbelt alone.
- Seatbelt profile with fork/exec allowed; file writes only in the job directory (snapshot or repo copy, job `$HOME`, `$TMPDIR`); reads of system paths, toolchains and `Xcode.app`; no reads of other jobs, `/Users/yeli`, credentials, `/Volumes/LLM` outside the job; network denied except the job-local model bridge.
- Process containment: every job runs as one launchd job with its own label; cleanup kills by **user ID** (per-job account) after the CLI exits, cancels or times out, then proves no process of that UID remains before publication. `setsid`/daemonizing cannot escape a UID-based sweep.
- Resource limits: CPU time, wall time, open files and disk quota on the job directory; output size bounds unchanged.
- Command policy: allow-all inside the sandbox (the sandbox is the boundary), with the existing denied-command list (`git push`, credential helpers, `ssh`, `sudo`, `launchctl`, `security`) as a second layer.
- Git: still no commit/push (D4); `.git` mounted read-only in the job copy.
- `xcodebuild`: needs `Xcode.app`, a job-local `DerivedData` path and, for simulator tests, CoreSimulator XPC services, which Seatbelt cannot confine tightly. Phase A: `xcodebuild build` with `-derivedDataPath` in the job dir and code signing disabled. Phase B (separate review): simulator runs. Device install/signing is out of scope.
- Receipts record every executed command line (hash-only for arguments over a bound) and exit status.

Open technical questions for the audit: per-job accounts vs one account; whether macOS 27 Seatbelt still supports the required `process-exec` path filters; how to prove UID cleanup when the CLI is killed mid-build; disk-quota mechanism on APFS.

**Audit of §3.7 (Fable, 2026-11-11) — blocking items before any build:**
- B1 `/Volumes/LLM` is mounted `noowners`; per-job UIDs give no file isolation there. Owner action: `diskutil enableOwnership /Volumes/LLM`, or a separate quota'd jobs volume with ownership on.
- B2 Cross-UID launch and kill need root; the yeli launchd helper cannot. Fix: root-owned fixed `minion-launch` and `minion-sweep` binaries with two exact NOPASSWD sudoers rules.
- B3 The current kill path (`nida_mac_helper.py` `process.kill()` on a new-session child) reaps only the direct child. Harmless today under the no-fork profile; with fork allowed, build processes would survive cancel while the quiescence seal still says reaped. Fix: seal only after a UID sweep proves zero processes.
- B4 TCC grants for the external volume are per user; `_minionNN` accounts may be denied access to `/Volumes/LLM` outside Seatbelt's control. Must be measured; fallback conflicts with "all job data on /Volumes/LLM" (owner decision).
- Important: Mach services are the real escape channel (each allowed `mach-lookup` runs unsandboxed); kernel-enforced `process-exec` denies for ssh/sudo/security/osascript/open/launchctl/crontab; `sandbox-exec` is deprecated but present on 27.2; APFS has only volume quotas, so `RLIMIT_NPROC/CPU/NOFILE` are required; `xcodebuild` license is system-wide and accepted; build with `CODE_SIGNING_ALLOWED=NO -destination generic/platform=iOS` so CoreSimulator never starts; network restriction to the loopback bridge is kernel-enforced for all descendants.
- Added tests: A18 ownership+TCC on the volume, A19 cancel mid-build leaves zero UID processes before the seal, A20 no Mach-namespace leak into `gui/501`, A21 fork bomb hits NPROC and the sweep completes, A22 allowed Mach services equal the receipt.

### 3.8 Bridge fix for failing Minion jobs — DEPLOYED on Asgard as bridge v3 (2026-11-11)
Status: v1 (refusal placeholders + `ls`), v2 (broker passes unoffered tool names to the bridge) and v3 (no invented tool names; an all-refused reply becomes a final explanation) were deployed in sequence; v3 is live and passed acceptance (inference `47`; outside-path task completes with an explanation; `ls` listing completes). The original analysis below is kept as written.
- Cause of "bounded completion request failed": the job-local bridge on Nida treated any policy-violating model tool call (path outside the job workspace, an unoffered tool) as fatal — generic 400, upstream revoked, job failed, then `supervisor failure: ValueError` from the outcome check. Production jobs `nida_job_a44bf2ec…` and `nida_job_b36877f5…`.
- Fix: `agentporter-deployments` branch `fix/nida-bridge-tool-refusal`, commit `1910c01`, based on `production/asgard-v15-20261105` (byte-identical to deployed files). Refused calls become argument-free `refused_<reason>` calls; pi gets the in-process `ls` tool; refusal counts go to job stderr. 12 new tests; the Nida suite's 47 pre-existing environment failures are unchanged.
- New hashes: bridge `e398e159…`, helper `6324ff34…`, runtime `8f84fac5…` (old `4ea01a02…`, `73b436f1…`, `531b2399…`).
- Deploy chain (root, with owner): new native release (replaces `minion-20261109-v1-native/RELEASE.json`, source fingerprint `34eafb45…`) → broker release whose `read-launcher.py` points to it → gateway `nida-lan-client.json` `broker_source_sha256` → sealed gateway control generation → Mac helper refresh (`stage-nida-supervisor-access.py --worker --refresh-helper`, preserving the signed app).

### 3.9 Delivery plan after bridge v3 (2026-11-11)
- **Phase A — Minion edits Asgard repos (§3.2a).** Native Mac dispatch on a snapshot of an Asgard workspace; delta published through the Asgard worker's transaction service (the broker, UID 970, cannot write repos); gateway scope widened from `nida-local` and the read-only limit lifted for admitted workspaces; dirty-tree refusal; trial + sealed release.
- **Phase B — BCC via Asgard (FR8, FR9).** A scoped gateway-to-gateway channel BCC → Asgard for Minion jobs on BCC workspaces (AgentPorter-level relay, not blanket SSH); snapshot/delta travel BCC ↔ Asgard; Asgard alone talks to Nida. Requires lifting the BCC-source denial on Asgard for that channel only, on both hosts' sealed configs.
- **Phase C — Nida's own repos (§3.3).** Mac-side registry and publisher; Nida may sync with BCC/Asgard repos via Git (FR9).
- Shell/`xcodebuild` (§3.7) stays blocked on the four Mac blockers.

### 3.10 Phase A design — where Minion jobs on Asgard repos run
**[verified]** `nida_mac_jobs._start` already supports writes: route `allow_workspace_write`, writable registration, `WorkspaceTransaction`, transactional publication, resource envelope, no shell/Git/credentials; the snapshot delta is imported only after proven Mac cleanup. On Asgard this code runs inside the LAN broker (UID 970), the sole holder of the Nida SSH identity, against the `nida-local` fixture. The broker cannot write yeli-owned repos and has no worker transaction service; the Asgard worker (UID 993) has both but no Nida route (the broker admits only the gateway cgroup).

Options:
- **A1 (proposed): worker owns the job, broker owns the wire.** The Asgard worker runs Minion jobs for Asgard workspaces with its existing `WorkspaceTransaction`, projection, resource and publication machinery. A new typed broker operation, admitted for the worker service cgroup only, carries the fixed Mac helper protocol (prepare/start/poll/cancel/collect) and the job-scoped inference channel over the broker's pinned LAN SSH. No credential leaves the broker; the worker never gets network or SSH.
- A2: give the broker read/write custody of repos plus its own transaction store. Rejected: duplicates the worker's custody model and widens UID 970.
- A3: copy repos into the `nida-local` fixture and back. Rejected: no publication boundary.

A1 changes: gateway `nida_virtual_scope` (accept admitted Asgard workspaces for `nida_dispatch` with `read_only=false`), worker job manager (Minion agents with Mac policy routes per workspace pattern), broker (worker-cgroup admission for the Mac protocol operations only), policies (`allow_workspace_write`), dirty-tree refusal before snapshot, receipts, trial with writable publication and cancellation, sealed release of gateway + worker + broker.
Acceptance: A5 (Minion edits a subfolder file in `asgard:<repo>`, published, owner `yeli`), cancel mid-job leaves no partial publication, dirty tree refused, worker sandbox still has no network.

**Audit of A1 (Fable, 2026-11-11): A1 is the right split, but the seam above is wrong and the refactor is larger.**
- B1 Seam: `nida_dispatch` runs entirely inside the broker; widening it bypasses the worker. Minion-on-repo jobs must use `dispatch_agent` → relay → worker `_dispatch_nida_mac` (`server.py:335-349`). `nida_dispatch` stays `nida-local` read-only (deprecated per D8).
- B2 Split `nida_mac_jobs._start/_monitor` into a custody half (worker: job row, `WorkspaceTransaction`, import, finalize) and a `MacWire` interface (`SshWire` = today's code in the broker; `BrokerWire` in the worker). The inference service and receipts stay broker-side.
- B3 The production worker has no Nida code at all; port `nida_mac_*` and job hooks; policy v4 with `transport: broker` routes (no SSH fields); worker readiness gates.
- B4 The broker socket (3 MiB frames, 3 s deadline, 4 shared slots) cannot carry 256 MiB snapshots or 900 s sessions; add a separate worker socket with its own slots and chunked streaming.
- Important: per-peer op allowlist (worker: launch/status/cancel/collect/recover only); worker unit needs the broker access group and `IPAddressDeny` for the LAN (the worker service itself has network today); worker runs `BrokerWire` as a child process so pidfd cancel and recovery keep working; restart recovery both ways; typed `busy` (the broker already serializes jobs); dirty-tree refusal does not exist yet (import already refuses owner conflicts); FR5 labels; the earlier "BCC: own SSH identity" line contradicts FR9 and is withdrawn.
- Sequence: doc fix → `MacWire` refactor (keep `nida-local` tests green) → broker worker socket + peers policy → worker port + `BrokerWire` → worker unit hardening → gateway relay + `minion` alias → dirty-tree decision → staging tests → sealed gateway+worker+broker release with writable and cancel trials → Phase B reuses the host-agnostic wire.
- Estimate revised: several days of implementation, three sealed components.

## 4. Delivery phases
1. Asgard write path — mitigation done; finish A1–A4; read the four FR1 exclusions (root).
2. Concurrency gate in the broker (§3.4) — prerequisite for widening Minion access.
3. Minion on host repos (§3.2a) for Asgard, then BCC; helper form (§3.2b) alongside.
4. Direct mode on Nida (§3.3) after the Mac-side publisher is specified and reviewed.
5. Durable storage idmap fix via staging.

## 5. Acceptance tests
- A1 Real Jax job on `asgard:daoist-widget`: new file in `scripts/`, `ios/`; edit existing file; net-zero cleanup. **PASSED 2026-11-11** (`rjob_5efa70bcfd663bdc963902a3cf59fde3`, exit 0, all three writes succeeded, `README.md` restored to `a14ea1a5…`).
- A2 Job 1 creates a new top-level folder; job 2 edits a file inside it (mitigation limit (a)).
- A3 `allow_commit=True` writable job on a mitigated repo commits successfully.
- A4 The four unregistered Asgard repos appear after the FR1 fix.
- A5 Minion job on `asgard:<repo>` edits a subfolder file; delta lands on Asgard only; Nida copy untouched.
- A6 Same on `bcc:<repo>`; ChatGPT on BCC sees no Nida tools and no `minion` agent; refusal text leaks nothing.
- A7 Direct Minion on `nida:<repo>`: edit published to Nida only; Asgard copy untouched.
- A8 Direct Minion on `asgard:x` or a bare name → explicit refusal with guidance.
- A9 `nida:epiWeave` vs `nida:epiweave` → refused or exact; root symlink handled.
- A10 Direct job on a dirty Nida tree → refused (or preserves owner edits if D4 allows).
- A11 Two concurrent Minion requests from different paths → one `busy`; no model swap.
- A12 `launchctl` stop of `org.nida.minion2` → `unavailable`, no fallback.
- A13 Cancel a Minion job → grant/socket revoked; sandbox TCP 22/8000 denied.
- A14 After the storage idmap change: all start gates pass in staging, then production.
- A15 Shell: Minion runs `ls`, a project test command and `xcodebuild build` (signing off) in a job; results returned.
- A16 Shell escape probes: reading another job, `/Users/yeli`, credentials; network to anything but the bridge; `ssh`; `git push`; a `setsid`/`nohup` background process — all denied or killed; no process of the job UID remains after cleanup.
- A17 Cancel during `xcodebuild` → all job processes gone before publication; nothing published.

## 6. Owner decisions — resolved 2026-11-11
D1–D4 and D6–D9 accepted as recommended below. **D5 changed:** Minion may call shell tools (§3.7).

(Original options, with the reviewer's recommendation in brackets:)
- D1 FR8 reading: Minion edits the host repo itself (3.2a) — [yes; matches wording].
- D2 FR6 on BCC: no ChatGPT access to Minion via BCC; owner and BCC-local agents may use it — [yes].
- D3 Concurrency: reject with `busy`, no queue, no swap — [yes; matches existing broker semantics].
- D4 Direct Nida jobs: working tree only, refuse dirty trees, never commit/push — [yes].
- D5 Shell (e.g. `xcodebuild`) on Nida: not in this phase; separate capability later — [yes].
- D6 Asgard transport: broker admits the worker for `infer`/dispatch rather than a second SSH identity — [broker].
- D7 Bare names keep meaning the local host; `nida:` mandatory for direct — [yes].
- D8 Unify under `dispatch_agent(agent="minion")`; deprecate `nida_dispatch` after one release — [yes].
- D9 Same-name repos across hosts are unrelated workspaces; Git remote is the only bridge — [yes].
- D10 Uncommitted changes in host repos (decided by Claude at the owner's delegation, 2026-11-11): Minion jobs on Asgard/BCC repos run on dirty trees, like Jax/Liz jobs; the worker's publication already refuses to overwrite owner edits or deletions (`nida_mac_workspace` import conflict checks). Direct jobs on Nida repos keep D4's dirty-tree refusal until a Mac-side publisher with equivalent conflict checks exists.

## 7. Decision log (all decisions taken in the 2026-11-10/11 session)
Owner = Lennon. "Claude" = decided by Claude where the owner delegated the call. Each entry: decision — reason — where it is implemented or recorded.

**Topology and access**
1. ChatGPT reaches Nida only through Asgard; BCC exposes no Nida tools to ChatGPT (owner) — earlier design — verified: BCC catalog 55 tools, no `nida_*`.
2. FR9 network rule (owner): BCC ↔ Asgard both ways; BCC must not reach Nida; Nida may reach both — BCC Minion work routes BCC → Asgard → Nida — §1 FR9, §3.9 Phase B. Partially reverses the Nov 7 BCC→Asgard denial; not yet implemented.
3. A job runs on the host that owns its workspace; workspace IDs are host-qualified (`asgard:`, `bcc:`, `nida:`); no silent rerouting (owner + Claude) — §3.1, FR5.
4. Supervised mode: an Asgard/BCC agent using Minion works on its own host's repo; direct Minion jobs work on Nida's repos (owner) — FR3/FR4.
5. D1–D9 accepted as recommended; D5 changed by owner: Minion may run shell tools (§6, §3.7). Shell remains blocked on the four Mac blockers from the §3.7 audit (ownership on `/Volumes/LLM`, root launch/sweep helpers, kill path, TCC).
6. D10 dirty trees (Claude, delegated) — see above.

**Fixes applied to production**
7. BCC discovery restart loop: quarantine a folder whose publication fails instead of retrying each tick (owner approved) — `agentporter-deployments` `0999dbc`, installed `/opt/agentporter-bcc/bin/autodiscover-bcc.py`. `/home/yeli/repos/models` (86 GB GGUF download) moved to `/home/yeli/models` (owner approved).
8. Asgard write path: strip named `user:993`/`user:994` ACL entries below every project root, keeping roots (pinned by discovery) and `.git` (Claude, owner approved "fix all") — 41 projects; backups `~/.local/state/acl-fix-20261110/` on Asgard. Durable fix (storage idmap `993→900993`, `994→900994`) deferred to a staged storage generation.
9. Minion bridge releases v1→v3 on Asgard (owner approved each window) — §3.8; tooling on branch `fix/nida-bridge-tool-refusal` (`eb36f67` and earlier).
10. Minion2 IQ3 config with `--conversation-cache-min-free-mib 512` (changed Nov 10 14:50 outside the release process) accepted as the identity baseline (owner) — `prepare-minion-owner-helper-switch.py` `LIVE_MODEL_CONFIGS`.
11. Stay on bridge v2 rather than roll back while v3 was built (owner); v3 then deployed.
12. Split release: bridge fix first, folder inclusion separately (owner chose recommendation B).

**Scope decisions**
13. All folders under `~/repos` should be included (owner). On Asgard, `AgentPorter`, `gambling`, `m3`, `obsidian` are hard-coded `HELD_NAMES` and three are owner-rule tombstones; inclusion needs a sealed discovery generation — pending. `gambling` changed `777 → 775`.
14. Nida `workspace_id` patch (any workspace → `nida-local`) dropped: it fixed the wrong layer (owner agreed after the "why" discussion).
15. Phase order after v3: A Asgard repos, B BCC via Asgard, C Nida repos (owner accepted Claude's recommendation after the BCC boundary finding).
16. Phase A architecture A1 "worker owns the job, broker owns the wire", corrected by the Fable audit (§3.10): entry via `dispatch_agent` → relay → worker; `nida_dispatch` stays `nida-local` read-only.
17. Temporary sudo pattern: 1–2 h `NOPASSWD: ALL` grants removed by a transient systemd timer (owner) — grants on BCC and Asgard all expired or self-revoking.

**Process**
18. Designs are audited by Fable before implementation; production changes go through sealed packets with readiness trials and explicit owner root windows (owner).
19. All decisions are recorded in this section by the end of each session (owner).

## 8. Production changes log (2026-11-10/11)
| When | Host | Change | Reversal |
|---|---|---|---|
| 11-10 ~19:10 | BCC | `models` moved out of `~/repos`; discovery timer paused/resumed | `mv` back |
| 11-10 ~20:11 | BCC | Discovery quarantine installed; 10 failed backups archived to `/var/lib/agentporter-bcc-discovery-archive/` | pre-quarantine script in same archive |
| 11-10 22:53 | Asgard | ACL mitigation on 41 projects | `setfacl --restore` from backups |
| 11-11 ~11:45 | Asgard/Nida | v5 trial (helper switched ~1 min, restored) | n/a |
| 11-11 ~16:40 | Asgard/Nida | Bridge v1 deployed (packet-v3) | `ap-minion-bridge-asgard-20261111-v1.sh --rollback` |
| 11-11 ~18:02 | Asgard | Bridge v2 deployed (packet-b2) | `…-v2.sh --rollback` |
| 11-11 ~19:4x | Asgard/Nida | v7 trial (helper switched, restored); bridge v3 deployed (packet-b3) | `…-v3.sh --rollback` |
