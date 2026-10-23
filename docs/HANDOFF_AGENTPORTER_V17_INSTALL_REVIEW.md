# A7Dev v17 installation review proposal

**Later Cranary coordination:** the [combined v19 approval handoff](HANDOFF_AGENTPORTER_CRANARY_V19_APPROVAL.md) retains this exact v17-r3 security work and adds v18 scoped acquisition. The original v17-r3 artifact and evidence are preserved. Neither release has been installed by this work.

Date: 2026-10-21. Machine: Asgard. Implementer: Liz. **Proposal only: nothing installed, restarted, committed or pushed.** Production A7 and Cranary data were not changed in this task.

The original frozen v17 has a process-tree cancellation gap. Review the revised **v17-install-r3** artifact identified below. The original v17, intermediate install revisions r1/r2, and the separate acquisition-only v18 are preserved. Only r3 is this proposal's final review target. This proposal does not combine v18's Posit/binary-download extension with v17.

**Installation remains blocked pending independent audit, owner approval of the exact changes and maintenance window, and an explicit decision about Argie's strict-policy regression.** Phil remains deferred. The implementing agent's tests and archive verifier are evidence, not independent clearance.

## State and review target

| Stage | Status |
|---|---|
| Process-tree fix implemented | Yes: asynchronous jobs and synchronous Bubblewrap timeouts/output limits |
| Source regression gate | 1,510 tests + 24 subtests + all standalone verifiers passed (executed locally) |
| Revised frozen-artifact gate | 1,451 tests + 24 subtests + all standalone verifiers passed (executed locally) |
| Independent security review | Pending |
| Owner approval / installation | Pending / not performed |
| Actual delegated cgroup enforcement, service-UID acceptance and live rollback | NOT verified; post-install gates |

Live preservation check: A7Dev PID `4102155`, current release `20261021T132836.936455Z` (v12), zero restarts; production **user** `agentporter.service` PID `664960`, zero restarts. A7Dev still has `Delegate=no`, no drop-ins, `MemoryMax=infinity`, `CPUQuotaPerSecUSec=infinity`, and `TasksMax=107647`. The new resource limits are not active.

Known v12 loaded/disk package fingerprint: `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`. Fresh public/local inspection is recorded in the evidence below. Production's previously checked disk fingerprint is `8de423283d3db8938a226719650a6c3b8fb325c534154992636bb6c51bf490a8`; its authenticated loaded fingerprint has not been rechecked here. Neither production configuration nor identities changed.

Final review artifact:

- Version: `20261021T211000.000017Z`.
- Archive: [agentporter-v17-install-r3.tgz](../review-artifacts/agentporter-v17-install-r3.tgz), private original `/tmp/agentporter-v17-install-r3.tgz`.
- Archive SHA256: `a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac`.
- Package fingerprint: `4273eb64b8fee55ff56e388a0645539556411fb7a827050b82876a6ccef4338b`.
- Manifest: 26,353 entries, 73 package source files.
- Base original v17 SHA256: `acbc64e95e238a3d568035834b75949456064445af89110bc68ddf8d18c6c72f`, original package fingerprint `085b63bf291595817d81ae99a14967e10b7a9d56138f39ddbd5ca27b273dbf2d`.
- Exact package/source, harness and evidence pins: [evidence index](evidence/agentporter-v17-install-review-20261021/sha256.json).

Only these five release payload files differ from original v17: `src/agentporter/resources.py`, `src/agentporter/tools/jobs.py`, `src/agentporter/sandbox/bubblewrap.py`, `venv/pyvenv.cfg`, and `venv/lib/python3.13/site-packages/agentporter_development.pth`. The latter two contain only the new version path. Runtime changes are only version-path relocation. All other payload bytes, including the provider broker, ingress scope example and systemd resource proposal, are identical to frozen v17. Runtime preserves Wei's `opencode/glm-5.3-flash-free` route, Jax's Headroom route, all seven canonical accounts, and the strict provider-origin broker. Production relay remains inactive; the retained Liz/Prof receiving admission setting does not activate a relay.

## Cancellation defect and fix

Original v17 cancellation signalled the launcher's owned pidfd. A pidfd identifies one process. Cgroup-wide cleanup occurred only when the monitor reached its `finally` block. A surviving descendant retaining stdout/stderr could keep that monitor waiting until the job's original deadline. Numeric process-group signalling in synchronous execution also failed to cover descendants that call `setsid()` and did not give a stable process identity after leader exit.

The revised implementation:

1. Requests `cgroup.kill` on the already owned job lease immediately when cancellation is accepted, before waiting for output EOF or process exit. It also signals an owned, duplicated pidfd for the launcher. It never discovers targets by scanning `/proc`, stored SQLite PIDs, or numeric PGIDs. Leases are indexed by the owned `Popen` object, rather than a numeric PID, so PID reuse after reaping cannot select another job's envelope.
2. Sets a per-process cancellation event. The monitor checks it while draining pipes and while waiting after pipe EOF, with a 200-ms polling interval. A process that closes its output streams cannot hide from cancellation until its original deadline.
3. Uses the same owned cgroup/pidfd termination mechanism for timeout and output-limit paths, including synchronous Bubblewrap execution. No numeric process-group kill fallback remains in that synchronous path.
4. Serializes lease termination with cleanup and makes successful cleanup idempotent. Only verified `populated=0`, envelope removal, launcher reaping and worker cleanup permit terminal cancellation and admission reuse. Missing envelopes or kernel control-file errors become `ResourceCleanupError`; uncertain cleanup keeps durable capacity held.
5. Preserves restart recovery's separate ownership boundary. A job persisted before restart cannot be cancelled through a stored PID; exclusive startup recovery drains only recognized owner-controlled cgroups.

Native regression tests cover a `setsid()` descendant keeping pipes open, an exited leader, closed output pipes, synchronous timeout/output limits, no numeric PGID signalling, bounded cancellation and stopped workspace heartbeats. Synthetic tests separately prove the envelope termination request precedes monitor completion, idempotence/serialization, kernel I/O failure, absent-envelope rejection, leader signalling despite tree-kill failure, simulated numeric-PID reuse across distinct process handles, delayed cleanup and retained capacity. Native Bubblewrap tests prove PID-namespace cleanup; fake control files prove decisions and errors. **Neither establishes live delegated kernel CPU/memory enforcement.**

The native fixtures have no delegated cgroups: they allow at most one second for the last namespace heartbeat to settle, then require a stable interval longer than the child's write period. Reaping Bubblewrap alone is not immediate descendant-quiescence proof. The main-worker natural-exit case must remain `completed`, rather than falsely claiming cancellation; a separate synthetic case checks tree termination after the launcher itself has exited. Hardened admission instead requires actual cgroup drain before completion, which remains an installed-service acceptance gate.

Affected source: the three modules above. Tests: `tests/security/test_process_tree_cancellation.py` and the `UnverifiedEnvelope` test fixture in `tests/security/test_closeout_resources.py`. New preparation tool: `scripts/prepare-v17-install-review.py`, which starts from the pinned original v17, permits only these three source replacements and two version relocations, and refuses existing outputs. The broader mutable checkout also contains the separately tested v18 work; do not rebuild this proposal by copying the current entire package.

## Exact proposed protected changes

| Path / setting | Proposed change | Ownership / mode |
|---|---|---|
| `/opt/agentporter-development/versions/20261021T211000.000017Z` | New immutable reviewed release | Existing immutable installer; root-owned, frozen payload |
| `/opt/agentporter-development/current` | Point to that release | Existing immutable installer |
| `/var/lib/agentporter-dev/config/development-runtime.yaml` | Candidate runtime; strict provider egress, required ingress isolation and per-job resources; Wei free route retained | `agentporter-dev:agentporter-dev`, `0600` |
| `/var/lib/agentporter-dev/config/public-client-policy.yaml` | New exact two-workspace public scope | `agentporter-dev:agentporter-dev`, `0600` |
| `/var/lib/agentporter-dev/config/internal-client.key` | New random private credential, different from public/relay keys; direct loopback only | `agentporter-dev:agentporter-dev`, `0600` |
| `/etc/systemd/system/agentporter-development.service.d/job-resources.conf` | New A7Dev-only delegation/resource drop-in | `root:root`, `0644`; parent `0755` |
| `/var/backups/agentporter-dev-v17-20261021T211000.000017Z` | New rollback/control-state backup | `root:root`, `0700`; no credential output |

The unchanged proposed ingress file, embedded in the archive under `operator-plan/a7dev-public-client-policy.yaml`, SHA256 `c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210`, grants:

- `cranary` → `/home/yeli/repos/cranary`: `read`, scoped `https`, read-only `dispatch`.
- `agentporter-dev` → `/home/yeli/agent-work/agentporter-dev`: `read`, read-only `dispatch`.

It grants no public generic execution, file writes, Git mutations, Obsidian access, unrelated-project access, or cancellation. Existing public clients relying on those capabilities will receive denial; authorized internal workflows must use the distinct private key over direct loopback. A public key used on loopback remains public. Forwarding headers cannot grant internal access. Do not expose the private key through the tunnel or copy it into ChatGPT.

The unchanged resource proposal, embedded as `operator-plan/a7dev-job-resources.conf`, SHA256 `5d934b1780a461b653cae680a7f525b9affe646c8b1006ecafe4df5ddecdbb5c`, sets `Delegate=cpu memory pids`, `DelegateSubgroup=supervisor`, `MemoryMax=16G`, `MemorySwapMax=0`, `CPUQuota=600%`, `TasksMax=512`, `KillMode=control-group`. Per job: 4 GiB, no swap, 128 processes, two CPU equivalents. Gateway-wide max active jobs: three. No unconfined fallback.

Existing `/var/lib/agentporter-dev/config/public-https.yaml` is preserved byte-for-byte. Expected current SHA256, from the owner's installed policy receipt: `0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7`. The owner must freshly compare it. v17 retains the original Cranary four-host GET/HEAD metadata grant and blocks unrestricted shell networking and redirects. It does not activate Posit or binary downloads; acquisition-only v18 remains separate. If that policy/runtime/release has changed before installation, stop and reconcile rather than overwrite newer work.

## Owner procedure — proposal only, run after independent approval

The following commands are the concrete proposal for review. They were **not executed**. No root execution of mutable repository code is required. The only Python installer executed as root is the pre-existing root-owned immutable `/usr/local/libexec/agentporter/install-development-artifact.py`. Its reviewed source SHA256 is `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`; its protected installed bytes could not be freshly read by yeli and must be verified by the owner before use. Refuse any mismatch. Do not use `--activate`, which would start before the matching controls are installed.

**Preflight while v12 is still available:** confirm independent signoff against the exact archive, explicitly approve the Argie availability change or keep installation blocked, approve scope/resource changes, arrange a quiet maintenance window, and pause callers. Query existing jobs over the authorized API; wait for zero running/cancelling/queued/cleanup-failed jobs and zero unresolved admissions. Do not kill existing work or clear reservations to create a quiet window. Record current Wei free route, fingerprints, public/local endpoint identity and production state without printing credentials. Verify the existing immutable installer and all destination ancestors are root-owned and not group/world writable; config's final directory must retain private service ownership. Check systemd supports `DelegateSubgroup=supervisor` and the actual unit's restrictions allow the proposed cgroup layout. Do not weaken sandbox restrictions if the unit refuses delegation.

Use a root shell only after approval, with tracing disabled. Each failed assertion/command stops the procedure. The fresh backup and all three control destinations must be absent; any different starting state requires a revised reviewed plan.

```bash
set -euo pipefail
set +x
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
umask 077
version=20261021T211000.000017Z
artifact=/tmp/agentporter-v17-install-r3.tgz
backup=/var/backups/agentporter-dev-v17-20261021T211000.000017Z
config=/var/lib/agentporter-dev/config
dropdir=/etc/systemd/system/agentporter-development.service.d
helper=/usr/local/libexec/agentporter/install-development-artifact.py

test "$(id -u)" = 0
test "$(readlink /opt/agentporter-development/current)" = /opt/agentporter-development/versions/20261021T132836.936455Z
test "$(systemctl show agentporter-development.service -p ActiveState --value)" = active
test "$(systemctl show agentporter-development.service -p DropInPaths --value)" = ''
test ! -e "$backup"
test ! -L "$backup"
for target in "$config/public-client-policy.yaml" "$config/internal-client.key" "$dropdir/job-resources.conf"; do
    test ! -e "$target"
    test ! -L "$target"
done
test ! -e "/opt/agentporter-development/versions/$version"
test ! -L "$artifact"
test -f "$artifact"
printf '%s  %s\n' a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac "$artifact" | sha256sum --check --status
printf '%s  %s\n' 84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58 "$helper" | sha256sum --check --status
printf '%s  %s\n' 0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7 "$config/public-https.yaml" | sha256sum --check --status

install -d -o root -g root -m 0700 "$backup"
readlink /opt/agentporter-development/current > "$backup/previous-release"
systemctl show agentporter-development.service > "$backup/previous-service-properties"
systemctl cat agentporter-development.service > "$backup/previous-effective-unit"
for name in development-runtime.yaml public-https.yaml config.yaml workspaces.yaml; do
    test -f "$config/$name"
    test ! -L "$config/$name"
    cp --archive --no-dereference "$config/$name" "$backup/$name"
done
cp --archive --no-dereference /etc/systemd/system/agentporter-development.service "$backup/service-unit"
if test -d "$dropdir"; then
    test ! -L "$dropdir"
    touch "$backup/dropdir-preexisted"
fi
printf '%s\n' public-client-policy.yaml internal-client.key job-resources.conf > "$backup/previously-absent-controls"

systemctl stop agentporter-development.service
test "$(systemctl show agentporter-development.service -p ActiveState --value)" = inactive
test "$(systemctl show agentporter-development.service -p MainPID --value)" = 0
```

At this checkpoint, verify the stopped job database read-only as the service UID and preserve a SQLite backup before proceeding. Do not use a mutable application module as root. The following fixed stdlib-only command runs as the service UID, emits no job content or credentials, and aborts if the stopped state is not quiet:

```bash
runuser -u agentporter-dev -- /usr/bin/python3 -I -c '
import sqlite3
c=sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro", uri=True)
assert c.execute("SELECT count(*) FROM jobs WHERE status IN (?,?,?,?)", ("running","cancelling","queued","cleanup_failed")).fetchone()[0] == 0, "Nonterminal jobs: stop and recover v12"
tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=?", ("table",))}
if "job_admissions" in tables:
    assert c.execute("SELECT count(*) FROM job_admissions").fetchone()[0] == 0, "Unresolved admissions: stop"
c.close()
'
cp --archive --no-dereference /var/lib/agentporter-dev/state/jobs.db "$backup/jobs.db"
# Preserve SQLite sidecars if present; the service is stopped and quiet.
for suffix in -wal -shm; do
    if test -e "/var/lib/agentporter-dev/state/jobs.db$suffix"; then
        cp --archive --no-dereference "/var/lib/agentporter-dev/state/jobs.db$suffix" "$backup/jobs.db$suffix"
    fi
done

/usr/bin/python3 -I "$helper" --artifact "$artifact" --sha256 a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac > "$backup/installer-receipt.json"
# Owner must record the NEW rollback_evidence path in this receipt.
# Do not use an old v12 installation receipt for this rollback.
release=/opt/agentporter-development/versions/$version
install -T -o agentporter-dev -g agentporter-dev -m 0600 "$release/operator-plan/a7dev-public-client-policy.yaml" "$config/public-client-policy.yaml"
openssl rand -hex 32 > "$backup/new-internal-client.key"
install -T -o agentporter-dev -g agentporter-dev -m 0600 "$backup/new-internal-client.key" "$config/internal-client.key"
if test ! -d "$dropdir"; then install -d -o root -g root -m 0755 "$dropdir"; fi
install -T -o root -g root -m 0644 "$release/operator-plan/a7dev-job-resources.conf" "$dropdir/job-resources.conf"
printf '%s  %s\n' c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210 "$config/public-client-policy.yaml" | sha256sum --check --status
printf '%s  %s\n' 5d934b1780a461b653cae680a7f525b9affe646c8b1006ecafe4df5ddecdbb5c "$dropdir/job-resources.conf" | sha256sum --check --status
cmp --silent "$backup/public-https.yaml" "$config/public-https.yaml"
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/agentporter-development.service
systemctl start agentporter-development.service
systemctl is-active --quiet agentporter-development.service
```

If startup or acceptance fails, stop only A7Dev and inspect the recorded state before using the matching rollback procedure; do not leave a failing restart loop running. The gateway must refuse startup if the internal key equals an existing public/relay key, policy scope is malformed, or delegated controllers/supervisor layout are wrong. A random internal key avoids intentional credential reuse; startup validation remains authoritative. Do not publish keys or a raw environment dump as evidence.

## Required acceptance before keeping the installation

Record commands, exit codes, sanitized results and effective configuration hashes under a new owner-controlled evidence directory. The implementer's unprivileged artifact tests do not replace these gates:

1. Verify the entire installed manifest against the approved archive, immutable ownership, new runtime/release pairing and `loaded_fingerprint=disk_fingerprint=4273eb64b8fee55ff56e388a0645539556411fb7a827050b82876a6ccef4338b`, `stale=false`, through **both** actual public and local A7Dev connections. Verify both reach the same new PID. Production A7's release/PID/config must match its preflight receipt.
2. Check effective `Delegate`, `DelegateSubgroup`, `ControlGroup`, aggregate CPU/memory/no-swap/task limits. The gateway must be the sole supervisor process. During a synthetic job, inspect its own `apj_<uuid>` `cgroup.procs`, `memory.max`, `memory.swap.max`, `memory.oom.group`, `pids.max`, `cpu.max`. Confirm real membership before exec. Exercise bounded allocation/process negatives without risking the host. CPU throttling and memory/process enforcement need actual kernel evidence.
3. Through the internal loopback credential, run native offline execution and process-tree cancellation/timeout/output-limit tests under those envelopes. Cover `setsid()` grandchildren, inherited/closed pipes, leader-first exit, three concurrent jobs plus a fourth denial, cancellation during streaming, resource/worker cleanup, no surviving descendants, removed envelopes, and capacity reused only after cleanup proof. A `cancelling` reply is not terminal success. Keep and investigate `cleanup_failed` capacity; never clear it manually to pass.
4. Exercise recognized interrupted-job recovery using a synthetic disposable job and a separately approved restart; reject unknown cgroups, persisted-PID cancellation and uncertain cleanup. No restart solely to recover a slot without first recording evidence and its owner authorization.
5. Public key: only the two approved workspaces visible; Cranary reads/scoped GET+HEAD/read-only dispatch succeed; unrelated/Obsidian/production reads, writes, generic exec, Git mutations, old/foreign jobs and cancellation are denied on REST and MCP. Public key on loopback stays restricted. Private internal key from public/tunnel/forwarded transport must be denied; direct loopback internal authorized workflows must work. Test auth failure and public/internal credential separation without logging headers.
6. Existing four-host Cranary metadata GET/HEAD succeeds, including frozen GitHub and approved CRAN URL. Deny POST, redirects, unapproved/internal/IP hosts, other workspaces and generic shell networking. Posit and binary acquisition remain absent in this candidate. Read approved request results rather than treating every non-error tool envelope as success.
7. Fresh actual provider-backed acceptance by admitted agent: workspace reads, shared skills, required tools and network routing. Preserve Jax's existing model, Wei's free default and every identity. Prior unprivileged native evidence: Jax/Liz/Prof/Ming/Wei passed; strict Argie blocked, Phil deferred. These are not new installed-service acceptances. Do not count either unavailable agent as verified or grant Argie's ACL endpoint to make the test pass.
8. Demonstrate the exact rollback below in the approved window; then re-activation requires the approved candidate/control pair and a new acceptance record. Successful implementation does not grant production security clearance. No production relay activation belongs to this plan.

## Rollback and interrupted-install recovery

The immutable installer creates the exact **current** v12 runtime/release snapshot, including the owner's repaired Wei free profile. Use the **new** `rollback_evidence` from `$backup/installer-receipt.json`; the older `.candidate-32a8c77e2ae39572aa57f417d0b40960` receipt is not the right pair. Never restore the obsolete Go runtime from the historical v12 archive.

Before rollback, pause callers, stop only A7Dev, record whether any new work was admitted, preserve fresh job/audit state, verify candidate current link and all new controls still match this receipt. Use the immutable helper with `--rollback NEW_EVIDENCE_BASENAME` and **without** `--activate`. That guard rejects a mismatched active release. Restore the three previously absent control paths by deleting only the exact newly installed regular files after checking public-policy/drop-in hashes and comparing the internal key to the private backup. If a path is changed, linked, or has unexpected ownership, stop and investigate. No recursive deletion is needed. Remove the drop-in parent with `rmdir` only if this procedure created it and it is empty. Preserve the new immutable release, private backup and installer receipt.

```bash
systemctl stop agentporter-development.service
# Set evidence to the basename returned by THIS install, after inspecting the receipt.
test "$(readlink /opt/agentporter-development/current)" = "/opt/agentporter-development/versions/$version"
test -n "$evidence"
for target in "$config/public-client-policy.yaml" "$config/internal-client.key" "$dropdir/job-resources.conf"; do
    test -f "$target"
    test ! -L "$target"
done
printf '%s  %s\n' c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210 "$config/public-client-policy.yaml" | sha256sum --check --status
printf '%s  %s\n' 5d934b1780a461b653cae680a7f525b9affe646c8b1006ecafe4df5ddecdbb5c "$dropdir/job-resources.conf" | sha256sum --check --status
cmp --silent "$backup/new-internal-client.key" "$config/internal-client.key"
/usr/bin/python3 -I "$helper" --rollback "$evidence"
rm -- "$config/public-client-policy.yaml" "$config/internal-client.key" "$dropdir/job-resources.conf"
if test ! -f "$backup/dropdir-preexisted"; then rmdir -- "$dropdir"; fi
cmp --silent "$backup/development-runtime.yaml" "$config/development-runtime.yaml"
cmp --silent "$backup/public-https.yaml" "$config/public-https.yaml"
cmp --silent "$backup/service-unit" /etc/systemd/system/agentporter-development.service
systemctl daemon-reload
systemctl start agentporter-development.service
systemctl is-active --quiet agentporter-development.service
```

Then verify public/local v12 fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, Wei free-default execution, Cranary metadata grant, previous ingress and resource state, production unchanged. A v12 rollback restores v12's known broader public/worker permissions; do not call that the hardened result.

Do not blindly restore SQLite over work admitted after installation. This proposal preserves the stopped pre-install database and any WAL/SHM sidecars for investigation; an incompatible schema or uncertain admission recovery blocks automated rollback acceptance and requires the owner to reconcile while stopped. Original v17 adds tables/columns rather than removing v12 fields, but compatibility must still be verified against actual jobs. If installation fails before an installer receipt is emitted, inspect root-private staging receipts/current link/runtime before recovery: it may have written a runtime before changing the link. Do not re-run the installer or guess a rollback receipt. The external backup contains the original pair for owner-directed recovery if the immutable helper's exact-pair guard cannot apply. No live interrupted-install or rollback exercise has been performed in this task.

## Verification and evidence

Executed locally, unprivileged (native namespace/loopback tests ran outside the outer Codex sandbox). Source gate:

```bash
bash scripts/verify-development-candidate.sh > /tmp/agentporter-v17-install-source-final5.log 2>&1
```

Result: **1,510 tests, 24 subtests, every standalone verifier passed**, pytest 90.34 seconds. One existing Starlette/AnyIO deprecation warning. Current 74-file source pins are exported separately from the 73-file artifact pins.

Build command (outputs were new; retain them rather than overwriting for a rebuild):

```bash
.venv/bin/python scripts/prepare-v17-install-review.py --base review-artifacts/agentporter-v17.tgz --source-manifest /tmp/agentporter-v17-install-r3-delta-pins.json --version 20261021T211000.000017Z --output /tmp/agentporter-v17-install-r3.tgz --extract-to /tmp/agentporter-v17-install-r3-extracted --report /tmp/agentporter-v17-install-r3-build.json
```

Build round-trip verified every payload entry. The pinned delta manifest is exported as `delta-pins.json`. Separate manifest/runtime comparison permits only the five declared changes and a runtime version relocation. The read-only review archive is an independently copied inode with the same SHA256.

Artifact harness: `/tmp/agentporter-v17-install-r3-harness`, copied from the preserved original-v17 harness; only `test_process_tree_cancellation.py` and `test_closeout_resources.py` were updated. It uses the exact extracted interpreter/dependencies/source. Only `venv/pyvenv.cfg` and the package `.pth` are relocated locally, with before/after hashes in `harness-relocations.json`. Test/script/document pins are in `harness-pins.json`.

```bash
cd /tmp/agentporter-v17-install-r3-harness
PYTEST_ADDOPTS='-o pythonpath=/tmp/agentporter-v17-install-r3-extracted/release/src' bash scripts/verify-development-candidate.sh > /tmp/agentporter-v17-install-r3-artifact-gate.log 2>&1
```

Result: **1,451 tests, 24 subtests, every standalone verifier passed**, pytest 102.34 seconds, the same existing warning. No tests were deselected or skipped. The 12 new process-tree cases passed in the full gates. Isolated import from that interpreter confirms the exact package path and fingerprint. A post-test full-manifest check allows only the two recorded relocations and checks all package pins again.

```bash
/usr/bin/python3 -I scripts/audit-closeout-artifact.py --artifact /tmp/agentporter-v17-install-r3.tgz --sha256 a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac --source-manifest /tmp/agentporter-v17-install-r3-package-pins.json --report /tmp/agentporter-v17-install-r3-streaming-audit.json
```

Result: PASS, 26,353 entries, 3,458,330,164 expanded bytes, 73 source files, expected package fingerprint. This stdlib-only streaming cross-check does not extract or execute payloads and is not independent review.

Fresh live preservation inspection: `.venv/bin/python scripts/verify-a7dev-cranary-acquisition.py` (default inspection mode, without `--after`) confirmed actual public/local v12 identity, unchanged four-host policy and restricted networking. Evidence: `/tmp/a7dev-cranary-acquisition-verification-y7571q07/results.json`. No research acquisition, provider model call or owner policy write was performed by that inspection. Final read-only `systemctl show`/`readlink` receipts confirm both services remain active with their original PIDs and zero restarts.

Sanitized, read-only evidence in [the indexed review directory](evidence/agentporter-v17-install-review-20261021/sha256.json) contains gate logs, exact delta patch, source and harness pins, build/streaming/manifest reports, isolated import and actual service/public-local receipts. `git diff --check` and static Bash syntax checks of the proposed commands passed; proposed privileged commands were not executed.

Earlier intermediate logs remain in `/tmp`, including a source gate run while package files were still being edited (its stale-fingerprint test failed) and any fixture failures corrected before the final frozen checks. They are not final acceptance evidence. Current source and the exact v17-derived artifact have different suite sizes because the current tree also contains the separate v18 acquisition work. The artifact harness starts from original v17's frozen test harness and adds only the new cancellation tests and updated envelope fixture; it does not silently omit incompatible tests from the current tree.

Inherited dirty detached checkout and earlier archives/rollback artifacts remain intact. A final status inventory is pinned in the evidence. Nothing was committed or pushed.

## Independent audit and owner decisions requested

Independently review exact archive/manifest/runtime deltas, the three changed modules, all cancellation failure/race paths, kernel ownership assumptions, public/internal key propagation on REST/MCP, native provider compatibility, and this install/rollback procedure. Re-run the artifact gate and archive audit independently. In particular, check cgroup termination before pipe EOF, cleanup failure retention, launcher exit/reaping races, shared lease locking, and safe handling of partial installation. Implementer-written tests do not establish absence of bypasses.

Owner decisions: approve or revise exact public scope; approve resource budgets and A7Dev-only unit change; approve handling of the known Argie regression (or keep installation blocked); approve the independently reviewed exact artifact and maintenance/rollback window. Internal credential distribution must preserve authorized local workflows without exposing the key publicly. Phil's account stays unchanged. Production rollout needs its own artifacts, review and authorization after development acceptance.

**Source implemented → tests passed on source and exact extracted artifact → independent review pending → not installed → installed controls/live rollback NOT verified.** Return the audit findings and exact owner authorization before any installation action.
