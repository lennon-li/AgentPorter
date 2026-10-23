# A7Dev automatic discovery (live 2026-10-22)

## Writable delegation update — prepared, not installed

The reviewed update makes newly discovered ordinary projects writable for
delegated agents: public scope includes `dispatch_write`, and the exact runtime
root uses `writable: true`. It also accepts existing explicit `dispatch_write`
grants rather than rejecting the entire policy. No protected root, overlapping
root, HTTPS capability, Git publication permission or credential is added.

Generated managed records now carry `profile_version: 2`. The helper recognizes
the exact older unversioned read-only profile as version 1 and upgrades it only
when registry, public scope, runtime row and directory identity all still match.
Any operator edit, including an explicit write grant or removal of permissions,
relinquishes automatic authority. A persistent `overridden: true` tombstone
prevents later scans from re-enrolling a deleted row and skips all ACL refresh
for that project. Unknown versions, mixed profiles and malformed tombstones fail
closed. Existing descriptor, owner/device/mount, secret-name, overlap, admission
guard, backup and exact-byte rollback checks remain enforced.

Ordinary human-owned directories also receive an explicitly named human default
ACL, so future service-created ordinary files retain human edit access. The
service default remains denied, and unrelated masked rights remain masked.
Private and Git directories receive no new human grant. This automatic scan does
not repair existing service-owned directories or explicit project trees. Native
programs creating mode `0600` files can mask inherited named ACLs under POSIX
rules; file tools separately apply their explicit collaborator ACL before atomic
publication. Effective native write accessibility still requires live acceptance.

Install the reviewed update as yeli using the command below after independently
checking the pinned helper/unit/installer bytes. The installer admits only its
listed release versions (including `20261022T165047.488565Z`); an unlisted newer
release requires reviewed pin maintenance. It stops the discovery timer before
replacing immutable helper bytes and preserves existing private recovery state.
Unverified source bytes are copied through yeli-opened input into root-private
staging and hashed there before publication, preventing swapped source contents
from becoming a public helper or unit even if verification fails.
The first reconciliation upgrades untouched legacy projects; it defers while
jobs or unresolved admissions exist and restarts A7Dev only if configuration
changes. Inspect the resulting helper plan and journal, public writable workspace
inventory, one newly enrolled ordinary project, and a known private/protected
denial. Source tests do not prove the operator installation happened.

The remaining sections describe the original live read-only-delegation
enrollment. Their default policy is superseded only after this update is
installed; prior runtime and secret protections still apply.

This change installs a separate root reconciler and 30-second timer. It does not
modify gateway packages, production, existing explicit workspace permissions,
models, credentials or network configuration. The operator installed the reviewed
files; parent verification confirmed successful reconciliation, repeated timer
scans, public registration of `references`, and offline execution as UID 994.

For a reviewed reinstall, run as **yeli**:

```bash
bash /home/yeli/agent-work/agentporter-dev/scripts/install-a7dev-autodiscovery.sh
```

The installer requires local `sudo -v`. It copies reviewed bytes to root-owned
files, verifies their pinned hashes before executing the installed helper or
reloading systemd, then enables `agentporter-dev-autodiscovery.timer`. Root reads
source bytes through an input stream opened by yeli, not mutable repository
pathnames. The helper is installed at
`/opt/agentporter-autodiscovery/autodiscover-a7dev.py` and runs using isolated
system Python (`/usr/bin/python3 -I`). PyYAML and the OS ACL tools are required.
The root unit permits fixed localhost health access only; the helper has no
remote HTTP path and does not read API keys or other credentials.

The acquisition/Git repair must precede discovery because its reviewed runner
pins the old static registry. The installer recognizes the old release
`20261021T232414.837654Z`, checks the existing runner's checksum and runs that
runner as yeli first. If release `20261022T015212.581522Z` is already active, it
does not repeat the repair or its external acceptance actions. Unknown releases
fail closed. The implementation worker did not run either installer.

## Enrollment and exclusions

Every approximately 30 seconds after the preceding scan finishes, the helper
examines direct children of `/home/yeli/repos`. A candidate must be a visible,
canonically named real directory owned by yeli, on the same device and mount as
its pinned parent. Directory names may use ASCII letters, digits, `_`, `-`, and
`.` after the first alphanumeric character (maximum 128 characters).

It excludes `obsidian`, `AgentPorter`, `agentporter`, `repos`,
`asgard-hermes-review`, private names, symlinks, special entries, other owners,
mount crossings, existing IDs/paths and ancestor/descendant overlaps with explicit
workspace/runtime roots. The existing `repos` umbrella is an intentional overlap
exception: its own ACL is never changed and it is never added to the worker
allowlist by this helper. Explicit registrations always win. If a new explicit child, ancestor or same-path
alias overlaps an unchanged auto-managed root, the helper revokes its automatic
registry/public entries and ceases ACL refresh. An exact shared runtime row is
retained for an explicit same-path alias; other unshared auto runtime rows are
removed. The scan reports affected IDs under `revoked`. Operator-edited auto rows
are instead relinquished without changes. Non-Git directories
are eligible and are never initialized as repositories.

The original installed helper gives new projects read/write, offline execution,
Git inspection, artifacts and read-only delegation, with runtime
`writable: false`. The prepared version 2 update above replaces that delegation
default with scoped writable delegation.
No new HTTPS, Git publication, SSH, SciNet, local HTTP ports, or remote access is
granted. Worker roots retain the existing capacity of **64**; overflow names
appear in the scan's `pending` list. Overlap exclusions appear under `overlaps`.
An enrollment updates the registry, public policy and worker allowlist together.

ACL traversal opens descriptors without following links and uses inherited file
descriptors for nonrecursive `getfacl`/`setfacl` operations. It skips symlinks,
hardlinked files, special entries, other owners/devices/mounts, and denies the
case-insensitive private-name classes, including bare SSH keys, `.gnupg`,
credential/config/cache directories, auth/credentials JSON, environment files and
PEM/key suffixes. Git metadata is read-only. Existing owner/other
ACL entries and unrelated effective ACL rights are preserved; previously masked
rights are clamped before expanding the mask for the service account.

A directory's default service ACL is **deny**, so newly created private files do
not inherit read access. New ordinary files become accessible when a subsequent
scan classifies them. ACL refresh scans do not restart the gateway. The complete
scan has a 100,000-entry/120-second ACL budget; errors or oversized trees report
`deferred_acl` and do not install configuration or restart A7Dev. An incomplete
ACL pass may have granted access to some ordinary entries, but its new workspace
is not registered or mounted for workers until a successful scan. No project
files are removed during pruning or rollback.

## Admission safety, transaction and recovery

A root-private directory `/var/lib/agentporter-dev-autodiscovery` (0700) stores
managed rows, the exact-byte transaction journal, guard ownership token and
historical backup receipts. Control files are opened through pinned descriptors,
with private ownership/mode, regular-file, single-link and size checks. YAML is
bounded, duplicate-key rejecting, and forbids aliases/anchors and unsafe tags.

The root parent launches only its installed immutable helper as `agentporter-dev`
for database operations. Python launches that child directly with the explicit
service UID/GID, no supplementary groups, `/` as working directory, and a fixed
minimal HOME/PATH/LANG environment. This avoids PAM/runuser dependencies and
credential or group inheritance. The dedicated `/opt/agentporter-autodiscovery`
directory is root-owned 0755 and its helper is root-owned 0644 so the service
account can traverse/read it. The existing private `/usr/local/libexec` tree and
old helper copies are untouched. The existing root-private guard ownership token
and transaction state are reused; they must not be deleted during this upgrade.
Child setup failures include bounded, control-character-sanitized stderr; hung
children are terminated before nonblocking diagnostic reads. The child uses `BEGIN IMMEDIATE` to check that all jobs
are terminal and no unresolved admissions remain. Known terminal history includes
`completed`, `failed`, `cancelled`, `timed_out`, `output_limit_exceeded`, and
`interrupted`; queued/running/cancelling/cleanup-failed and unknown statuses defer. Busy jobs/admissions cause a
deferred scan without cancellation or restart. Root never opens SQLite as a
writer, avoiding root-owned WAL files.

While holding that initial writer transaction, the child installs exact,
uniquely owned INSERT/UPDATE admission guard triggers and commits atomically.
The root ownership journal is durable before the guards can commit. The guards
block real admissions continuously while permitting empty startup INSERT SELECT
and recovery statements in the existing gateway. Holding a writer transaction
through startup would deadlock that existing initialization, which is why the
durable guard handoff is required.

Only A7Dev is stopped; the configuration and managed rows are journaled before
writes. All three documents are replaced atomically per file, A7Dev starts, and
`http://127.0.0.1:8876/health` must succeed before committing managed state. The
child verifies exact guard SQL, zero admissions and terminal jobs before guard
removal in another writer transaction. Guard triggers remain throughout health
verification. An unchanged configuration scan does not stop/start any service;
an inactive A7Dev is left inactive and config enrollment is deferred.

A helper crash leaves durable admission guards in place. The next scan resumes
only guards matching the root-private ownership token. Known partial transactions
restore exact previous config bytes and previous managed-state bytes (or its
prior absence), restart the previously active gateway and verify health. Unknown
or newer bytes and unknown guard SQL are refused rather than overwritten. A
failed rollback/startup leaves the journal and admission block for investigation.
Backups are preserved rather than automatically aged/deleted.

Inspect operation with:

```bash
sudo /usr/bin/python3 -I /opt/agentporter-autodiscovery/autodiscover-a7dev.py
systemctl status agentporter-dev-autodiscovery.timer
journalctl -u agentporter-dev-autodiscovery.service
```

The first command defaults to a read-only plan; `--apply` is root-only and requires
the immutable installed location. A pending transaction needs `--apply` recovery.
Do not delete root state or manually drop guard triggers to bypass unresolved
recovery. Stopping the timer alone does not remove a pending database guard.

## Verification evidence

The focused suite exercises filtering/owner/root replacement, same-device mount
exclusion, strict YAML, symlink/hardlink/special-file handling, ordinary permission
parity, explicit-row preservation/overrides, pruning/capacity/overlap/no-op/busy
behavior, SQLite writer and durable guard admission races, crash guard resumption,
unknown guard refusal, exact rollback after injected write/start/health failures,
and known-partial/unknown-byte recovery. Native ACL fixtures use only owned
short-lived `/tmp` trees and a distinct numeric named-user ACL; no sudo is used.

### Follow-up: effective CAP_SETUID retention

The operator's transient-unit probe showed `CapPrm/CapEff=0x6f` and
`CapBnd=0xef`: `setgroups` and `setregid` succeeded, but `setreuid` failed
with EPERM. systemd v255's `keep_seccomp_privileges` path explicitly drops
CAP_SETUID unless it is requested in the ambient set (see
`src/core/exec-invoke.c`, `drop_capability(CAP_SETUID)`). The unit now sets
`AmbientCapabilities=CAP_SETUID` within the existing bounding set. Changing
the child UID clears its ambient capabilities; NoNewPrivileges remains enabled.
The installer service checksum was refreshed. Native focused verification:
59 tests passed; shell syntax and systemd static checks passed.

Live activation was subsequently verified on 2026-10-22 at 09:09 EDT:
the installed unit completed with Result=success/ExecMainStatus=0, added
`references`, and the timer is enabled and active. Public A7Dev workspace listing
shows `references` with the ordinary project permissions. An offline command in
that workspace exited 0 as UID 994, with a writable workspace, zero effective
and ambient capabilities, and NoNewPrivs=1. The development gateway remained
active. This validates installed root-to-service launch and admission release;
live crash-recovery scenarios have not been exercised.

`scripts/diagnose-a7dev-autodiscovery.sh` provides a credential-only transient
unit probe, now including the corrected ambient setting. It does not edit
gateway configuration or workspace ACLs.

Run the suite under a native UID mapping if the restricted sandbox maps only one
UID (foreign numeric ACLs fail with `EINVAL` in that mapping):

```bash
.venv/bin/python -m pytest -q tests/security/test_a7dev_autodiscovery.py
bash -n scripts/install-a7dev-autodiscovery.sh
systemd-analyze verify scripts/agentporter-dev-autodiscovery.service scripts/agentporter-dev-autodiscovery.timer
```

Installed root-to-service child launch, service-UID execution in `references`,
and repeated live timer scans passed parent verification. Production-scale scan
duration and crash recovery against the live gateway remain **NOT verified**.
The unit
validation tool may print unrelated pre-existing host unit warnings; those units
are outside this change.

The 2026-10-22 launch correction addresses the observed inaccessible private
libexec ancestor and PAM-dependent child setup. Regression fixtures verify the
new install path/modes, exact dropped identity/groups/environment, child stderr
and timeout diagnostics, and service-mode SQLite access through a pinned proc FD
including WAL and the READY/VERIFY/RELEASE protocol. Native fixture execution
does not impersonate root or the actual service account; subsequent installed
root-unit activation and service-account execution passed parent verification.
