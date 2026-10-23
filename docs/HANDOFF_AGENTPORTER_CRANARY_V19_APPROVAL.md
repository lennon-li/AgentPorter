# Cranary scoped acquisition — combined release and owner approval

Date: 2026-10-21. Machine: Asgard. **Installation blocked: independent security review, explicit owner approval and the Argie compatibility decision are still outstanding. No installation, privileged change, restart, new research download, training, commit or push occurred in this task.**

The requested standalone v18 SHA256 was freshly verified with `sha256sum` and a full streaming base/artifact audit: `fb6b36a63de7738db09baa6aca0e1b2fcb825ddf2778c1357c6ca3dde084976d`. It is a v12 derivative, so installing it alone would omit the prepared v17 controls. The new **v19** below combines acquisition with exact v17-r3, including the latest process-tree cancellation and PID-reuse fixes. Original v17/v18 artifacts and their evidence are preserved. Read-only task discovery found no other active task on this checkout; the v17-r3 archive is the coordination baseline.

## Exact combined review target

- Version: `20261021T212000.000019Z`.
- Archive: [agentporter-cranary-hardened-v19.tgz](../review-artifacts/agentporter-cranary-hardened-v19.tgz); private original `/tmp/agentporter-cranary-hardened-v19.tgz`.
- SHA256: **`701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80`**.
- Package fingerprint: **`2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7`**; 74 package files; 26,357 payload entries.
- Base v17-r3 SHA256: `a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac`.
- Evidence/pins: [review evidence index](evidence/cranary-hardened-v19-20261021/sha256.json).

Exactly twelve release files differ from v17-r3: seven acquisition modules (`action_policy.py`, `client_policy.py`, `https_download.py`, `rest/routers/exec.py`, `rest/schemas.py`, `scoped_https.py`, `server.py`), the inert HTTPS proposal, two inert acceptance scripts, and two venv version-path files. Runtime differs only by release-path relocation. All other payload bytes are retained, including provider broker, Headroom, process handles, cancellation, cgroup limits, admission/recovery and bounded filesystem operations. The delta patch is exported for semantic review; a manifest comparison alone does not prove every security property.

The runtime requires strict provider-origin egress, private internal/public-client isolation, and real cgroup resources. Wei remains `opencode/glm-5.3-flash-free`; Jax's Headroom route and existing worker accounts/credential paths remain unchanged. No production relay is activated. Public clients retain only Cranary read/HTTPS/read-only delegation and AgentPorter-dev read/read-only delegation; internal authorized development workflows use a separate loopback-only credential.

**Compatibility blocker:** strict Argie still rejects `POST /v1internal:writeTrajectoryAcls`; its upstream semantics are not independently established. No ACL-writing endpoint was allowed, success forged, identity/model substituted or paid route enabled. Installing this strict runtime would make Argie unavailable compared with current v12. The request to preserve all gateway functionality therefore prevents automatic activation. The owner must explicitly accept a temporary strict Argie hold after independent review, or require a supported secure compatibility solution first. Phil's quota/account stays untouched.

## Owner policy and filesystem changes

Only the Cranary metadata host set gains `packagemanager.posit.co`, restricted to dated source-snapshot paths. Binary acquisition is a fixed-purpose GET tool for CRAN archive sources and dated Posit sources; HTTPS/443, public DNS/IP pinning, no redirects, no shell networking, no credentials/proxies. Limits remain 16 MiB/60 seconds, one download, shared max-three admission and per-job cgroup envelope. Publication is SHA256-checked, no-overwrite and confined to `data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads`. The original four-host metadata limits remain 256 KiB/15 seconds. No other host, method or workspace grant is added.

Install code and version-2 policy together; never apply v2 to running v12. Policy target: `/var/lib/agentporter-dev/config/public-https.yaml`, owner/group `agentporter-dev`, `0600`. New policy SHA256: `e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf`. Current expected policy SHA256, from the owner's prior receipt: `0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7`; owner must freshly compare.

Other protected changes are the same explicit v17 proposal: new immutable release/current link and matching `development-runtime.yaml`; `public-client-policy.yaml` (`0600`, SHA256 `c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210`); a fresh distinct `internal-client.key` (`0600`); and the A7Dev-only `job-resources.conf` drop-in (`root:root`, `0644`, SHA256 `5d934b1780a461b653cae680a7f525b9affe646c8b1006ecafe4df5ddecdbb5c`). Aggregate limits: 16 GiB/no swap, six CPU equivalents, 512 tasks, delegated cpu/memory/pids supervisor subgroup; per job 4 GiB/no swap/two CPU equivalents/128 processes. No production configuration or existing credential is changed.

## Installation proposal — NOT executed

User handoff step 4 explicitly requires owner approval before privileged changes. The earlier rollout also requires independent review of the exact artifact. These commands are for that review, not permission to execute them. The implementing agent's tests and cross-checks are not an independent signoff.

Before approval: resolve/accept the Argie hold, approve public/internal scope and resource budgets, verify the current v12/free-Wei/four-host grant and production state, pause callers and wait for no active jobs/unresolved admissions. Do not kill work or clear reservations. Verify trusted root-owned non-writable ancestors and the existing immutable installer SHA256 `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`. Its protected installed bytes were not freshly readable by yeli; the owner must verify them. Confirm systemd/controller support and do not weaken unit/sandbox protections to start the gateway.

After independent approval, use a root login shell with tracing disabled. Commands stop on failure. Unexpected existing controls/release/backup or changed policy/release require reconciliation, not overwrite. The only Python installer run as root is the existing immutable helper; acceptance runs as the service UID from the frozen reviewed release.

```bash
set -euo pipefail
set +x
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
umask 077
version=20261021T212000.000019Z
artifact=/tmp/agentporter-cranary-hardened-v19.tgz
backup=/var/backups/agentporter-dev-cranary-v19-20261021T212000.000019Z
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
printf '%s  %s\n' 701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80 "$artifact" | sha256sum --check --status
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

The service is now stopped in the proposed sequence. Check the stopped database without modifying it, preserve its state, install the reviewed artifact and matching controls, then perform live acceptance:

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

/usr/bin/python3 -I "$helper" --artifact "$artifact" --sha256 701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80 > "$backup/installer-receipt.json"
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
install -T -o agentporter-dev -g agentporter-dev -m 0600 "$release/operator-plan/public-https.yaml.proposed" "$config/public-https.yaml"
printf '%s  %s\n' e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf "$config/public-https.yaml" | sha256sum --check --status
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/agentporter-development.service
systemctl start agentporter-development.service
systemctl is-active --quiet agentporter-development.service

# Python runs as the confined service account, never root.
runuser -u agentporter-dev -- "$release/venv/bin/python" -I "$release/operator-plan/verify-a7dev-cranary-acquisition.py" --after --public-key-file "$config/secrets.env" --internal-key-file "$config/internal-client.key" --expected-fingerprint 2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7 > "$backup/acquisition-verification.log"
```

Record the **new** `rollback_evidence` in `$backup/installer-receipt.json`. Never reuse an older v12/v17 receipt. The acquisition verifier prints its service-owned private evidence directory in the root-private log; preserve `summary.json`, `results.json` and `acquisition-receipts.json` from that directory without credential/header dumps. It binds both actual public/local connections to the approved fingerprint and PID, makes public acquisitions, checks denials, then uses the private key only at literal direct loopback for offline byte rehashing and the existing Cranary snapshot consumer. It never sends the private key to the tunnel. Old public generic execution is deliberately denied; the verifier now tests that denial instead of relying on it.

The Posit receipt records source URL, retrieval time, safe publisher headers, byte count and SHA256; the first fetch remains `expected_sha256_verified=false`. TCIU uses its independently pre-recorded SHA256 `f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42`. A wrong checksum must fail without publishing a file. The existing offline population preview must parse at least 1,000 records, select 20 candidates, match the input checksum, and retain all training/evaluation/rights/historical-completeness flags false. Its path, checksum, decompressed checksum, family count and consumer source checksum are recorded. No frozen dataset or model is modified/trained.

A successful date-aliased retrieval is not proof of the exact historical CRAN check population. Publisher date resolution, completeness, rights and independent defect adjudication remain research gates. Do not promote these quarantined bytes.

## Rollback / failed installation

If start or acceptance fails, stop only A7Dev and record its state. The following assumes the complete new control set still matches this receipt, callers are paused and new jobs have drained. Use the new immutable installer's exact runtime/release rollback pair, restore the old HTTPS bytes, and remove only the three previously absent controls after matching their hashes/key backup. Existing secrets and research receipts stay intact. If installation was interrupted before these files/receipt were created, stop and inspect the root-private stage plus external backups instead of guessing a receipt or blindly rerunning the installer; see the v17 handoff's interrupted-install gates.

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
printf '%s  %s\n' e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf "$config/public-https.yaml" | sha256sum --check --status
/usr/bin/python3 -I "$helper" --rollback "$evidence"
install -T -o agentporter-dev -g agentporter-dev -m 0600 "$backup/public-https.yaml" "$config/public-https.yaml"
rm -- "$config/public-client-policy.yaml" "$config/internal-client.key" "$dropdir/job-resources.conf"
if test ! -f "$backup/dropdir-preexisted"; then rmdir -- "$dropdir"; fi
cmp --silent "$backup/development-runtime.yaml" "$config/development-runtime.yaml"
cmp --silent "$backup/public-https.yaml" "$config/public-https.yaml"
cmp --silent "$backup/service-unit" /etc/systemd/system/agentporter-development.service
systemctl daemon-reload
systemctl start agentporter-development.service
systemctl is-active --quiet agentporter-development.service
```

Verify public/local v12 fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, current repaired Wei free default, restored old HTTPS scope and previous resource/ingress state. Verify production PID/release unchanged. Do not restore the obsolete paid-Go runtime from the historical v12 archive. Do not overwrite SQLite after new work was admitted, recursively delete controls, or delete acquired research evidence. Preserve the new immutable release and backups. A v12 rollback restores its known broader permissions; it is recovery to the prior baseline, not the hardened result. No live rollback has yet been exercised.

## Verification and current live result

Executed locally, unprivileged:

- Full source gate: `bash scripts/verify-development-candidate.sh`, log `/tmp/agentporter-cranary-hardened-v19-source-gate.log`: **1,516 passed, 24 subtests, all standalone verifiers passed**, pytest 89.94 seconds.
- Exact extracted artifact: `/tmp/agentporter-cranary-hardened-v19-harness` uses the candidate's own interpreter/dependencies/source; only two venv path relocations are permitted. `PYTEST_ADDOPTS='-o pythonpath=/tmp/agentporter-cranary-hardened-v19-extracted/release/src' bash scripts/verify-development-candidate.sh`, log `/tmp/agentporter-cranary-hardened-v19-artifact-gate.log`: **1,516 passed, 24 subtests, all standalone verifiers passed**, pytest 92.62 seconds. No skips/deselections. Both gates emit the same existing Starlette/AnyIO deprecation warning.
- Fresh standalone v18 archive/base streaming audit: PASS, 26,346 entries, 67 source files, expected SHA256/fingerprint; `/tmp/agentporter-v18-fresh-audit-for-v19.json`. This independently recomputes the hash but does not constitute independent security signoff.
- Combined v19 archive/base streaming audit: PASS, exact twelve-file delta, 26,357 entries, 74 source files, 3,458,369,389 expanded bytes, expected fingerprint; `/tmp/agentporter-cranary-hardened-v19-streaming-audit.json`. Runtime matches strict v17-r3 except version paths.
- Post-test full-manifest/source/operator-script verification: PASS, allowing only the two recorded local relocations; `/tmp/agentporter-cranary-hardened-v19-post-test.json`. Isolated import confirms the exact extracted source/fingerprint. The separate read-only review archive was rehashed and has a different inode from the private original.
- Six new acceptance-procedure regressions passed in the full gates: private key sent only to literal loopback, no credentials in evidence, fingerprint binding before acquisition, public generic exec denial, nonzero offline exit rejection and distinct internal/public credentials.
- Revised inspection-only script succeeds against actual unchanged public/local v12; results `/tmp/a7dev-cranary-acquisition-verification-tad3ev5t/results.json`. It does not try Posit, grant permissions or obtain research data.
- `git diff --check` and static Bash syntax checks of the proposed commands passed. Proposed privileged commands were not executed. All sanitized receipts, exact source/operator input pins, source delta and harness pins are exported in the indexed evidence directory.

Reproduction (fresh output paths required; old outputs are preserved):

```bash
.venv/bin/python scripts/prepare-cranary-hardened-candidate.py --base review-artifacts/agentporter-v17-install-r3.tgz --input-pins /tmp/agentporter-cranary-hardened-v19-input-pins.json --version 20261021T212000.000019Z --output /tmp/agentporter-cranary-hardened-v19.tgz --extract-to /tmp/agentporter-cranary-hardened-v19-extracted --report /tmp/agentporter-cranary-hardened-v19-build.json
/usr/bin/python3 -I scripts/audit-cranary-hardened-candidate.py --artifact /tmp/agentporter-cranary-hardened-v19.tgz --base-artifact review-artifacts/agentporter-v17-install-r3.tgz --input-pins /tmp/agentporter-cranary-hardened-v19-input-pins.json --sha256 701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80 --report /tmp/agentporter-cranary-hardened-v19-streaming-audit.json
```

All work is uncommitted on the inherited dirty detached checkout. Session changes: revised acquisition acceptance script, its six routing tests, combined preparation/streaming-audit scripts, this handoff, additive notices in the previous two handoffs, and frozen review/evidence artifacts. No v17 source module was overwritten. The implementing agent authored the tests/auditors; independent security clearance remains pending.

**Installed fingerprint:** current v12 `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, PID `4102155`, zero restarts. Public/local agree, `stale=false`, original four-host grant, no binary capability. Production user service PID `664960`, zero restarts, unchanged. A fresh authenticated production loaded fingerprint was not queried.

**New download receipts:** none — Posit/binary access remains unactivated. No `--after` live acceptance or rollback success is claimed. Existing canonical GitHub `ropensci-archive/rrlite` acquisition remains valid and needed no grant expansion.

**Remaining approval:** ChatGPT/independent reviewer must audit the exact combined archive, seven-module delta, v17 controls, acceptance credential routing, policy, owner procedure and rollback. Owner must approve that exact artifact/window and decide whether the temporary Argie hold is acceptable. If preserving Argie availability is mandatory, installation remains blocked until secure compatibility is resolved. Source/tests/review/install/live acceptance are separate states; production clearance is not implied.
