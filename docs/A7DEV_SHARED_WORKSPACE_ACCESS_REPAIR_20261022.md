# A7Dev shared workspace access and promotion gates

Production promotion is on hold. A7 production has not been modified. No source
changes have been committed or published by this repair session.

## Live evidence

A7Dev currently runs immutable release `20261022T165047.488565Z`.
The original shared-file and explicit writable-dispatch fixes are installed;
`agentporter-dev` is the only workspace whose writable public grant was
activated. Its subfolders are included recursively, with secret/control masks
and exact-root confinement retained. Other projects need the prepared grants.

Native `write_file` and `apply_patch` passed actual creation, inode replacement,
patch creation/replacement, executable access and yeli read/write checks.
Sensitive-path, traversal, stale-hash and public commit/push denials passed.
Evidence is private at `/tmp/a7dev-shared-access-live-563fe5e0afc7.json`.

The real worker test exposed an additional inheritance defect: access ACLs on
service-created directories named yeli, but their default ACLs did not.
The prepared core adds an explicit named human UID to new directory defaults,
while clipping existing masked rights before recomputing the mask. Native file
tools also repair validated ordinary service-owned ancestors and refuse to
publish beneath inaccessible owner-controlled ancestors. Existing ordinary
directory defaults outside a native file operation need the separately guarded
repair. A default
ACL cannot override an application's explicit mode-0600 creation; native
`write_file`/`apply_patch` explicitly grant the collaborator on ordinary files.

Only the synthetic acceptance directory's ownership/default ACL was repaired
for the subsequent seven-agent smoke test. Four configured identities completed
and produced exact files editable by yeli: **Liz, Prof, Wei and Ming**.
Jax produced the correct editable file but exited with signal 9 in the concurrent
run, then passed a serial retest. The earlier concurrency failure remains
unexplained; no production readiness claim relies on ignoring it. Phil failed
before creating its marker because its CLI parsed a bare MCP config filename
as JSON; the prepared fix uses its documented `@file` syntax. Argie failed
with HTTP 403 / PERMISSION_DENIED. Argie is not counted as ready; Phil awaits a live retest after installation.
Private job/results: `/tmp/a7dev-all-worker-write-smoke.json` and
`/tmp/a7dev-worker-smoke-<agent>.json`. No credentials are included in this report.

Four previously inaccessible handoffs were repaired without content changes:
yeli owns them, service UID access is retained, group/other access remains
denied. Local and authenticated native API reads matched file content hashes.
Private metadata backup: `/tmp/a7dev-handoff-acl-backup-5qvxgn4r.json`.
Read evidence: `/tmp/a7dev-handoff-live-read-acceptance.json`.

## Prepared development changes

The explicit grant helper selects every existing eligible owner-authorized
project leaf, including Qman, through matching public policy, registry and
runtime roots. It reports exclusions and blocked roots rather than granting a
writable umbrella. The `shiny` parent overlaps separately admitted children and
must remain excluded as a writable parent. Production, Obsidian, host/control
roots and secret containers remain protected. Each ordinary selected root
includes its subfolders; no per-subfolder public grant is needed.

Each selected root receives the actual immutable worker's metadata/hardlink
preflight. Hardlink denial has not been weakened. For this development checkout
only, 2,191 dependency files were detached into byte-identical private inodes;
mode, ownership and xattrs were verified and shared cache aliases were untouched.
Evidence: `/tmp/a7dev-venv-private-inodes.json`. Other projects are not silently
rewritten when a preflight fails.

Autodiscovery version 2 admits writable dispatch for future ordinary projects
and migrates only exact untouched legacy profiles. Explicit restrictions,
grants and deletions persist as owner overrides. The currently installed old
reconciler rejects the new dispatch scope and is failing closed; its prepared
replacement must be installed before claiming automatic enrollment works.

Operator scripts pin immutable inputs, verify root-private staged helpers before
publishing them, pause and drain automatic discovery, refuse active jobs,
require reviewed stopped-state plan hashes and preserve distinct recovery
records. They touch development services only. No alternative privilege route
or weaker sandbox has been introduced.

The new immutable core candidate preserves the SHA-pinned actual active runtime
apart from release-path relocation. Runtime admission must pass both before
stopping and immediately before installation. A failed installation gate must
never be bypassed. Activation cannot be completed by this agent because the
reviewed root Python installer requires interactive sudo authentication.

## Validation and remaining promotion gates

The final complete host gate passed **1,918 tests, 24 subtests and all six
offline security verifiers**. Log:
`/tmp/a7dev-workspace-complete-validation-final.log`. The verified extracted
candidate passed **178 packaged ACL/delegation tests**. The final inherited
error-handler regression and activation suite passed 13 checks. ShellCheck,
shell syntax and `git diff --check` passed. One existing Starlette/AnyIO
deprecation warning remains.

The final immutable development candidate is
`/tmp/a7dev-workspace-writes-activation.tgz`, version
`20261022T181133.685266Z`, SHA-256
`ce546675f17f6e6e70a39d196ac763b3bbe155de67ad39f24af057e95e22d5b9`.
Its report is `/tmp/a7dev-workspace-writes-activation-report.json`. Independent
review rehashed the archive and verified all source/launcher pins, runtime
relocation, full manifest delta and package fingerprint for development-only
activation. Review: `/tmp/a7dev-workspace-writes-independent-review.json`. Its strict
manifest contains 26,369 entries; the only changed runtime modules are
`workspaces/shared_access.py` and `agents/development.py`, plus declared inert
operator/tests and two Python release-path relocations. Every current source
input pin matches. Active runtime semantics are preserved exactly except
release-path relocation. The required current canonical runtime digest is
`b8e1d9b98398e5b3a3776670ccb98e718c02468c023d6b859254783c79365d9c`.

Run as yeli to install this development-only repair and its separately pinned
grants/directory-default/discovery helpers:

```bash
bash /home/yeli/agent-work/agentporter-dev/scripts/activate-a7dev-workspace-writes.sh
```

The command requires interactive sudo. It cannot claim every root succeeds:
blocked/excluded roots are reported; inaccessible existing human directory ACLs
and bounded traversal failures stop directory repair before service shutdown.
Default-only repair deliberately preserves existing directory access ACLs.
Original metadata and partial-apply journals remain root-private. Concurrent
noncooperating human renames after final checks remain a filesystem limitation.
Do not bypass gates or substitute an earlier superseded artifact.

Final read-only checks: development PID `2174796` and production PID `664960`
remain active with zero automatic restarts. No final candidate was installed
by this agent.

Remaining gates are development activation and effective-root acceptance;
existing directory default-ACL repair and real worker editability acceptance;
the earlier concurrent Jax signal-9 diagnosis; Phil live retest after installation; Argie HTTP-403
resolution; and installed lifecycle/resource/rollback acceptance.

The production relay currently rejects writable jobs by design. Development
`dispatch_write` cannot enable writable production relay jobs. A reviewed
writable relay boundary and live credential/scope/replay/path/cleanup tests are
required before a production rollout promising writable delegation.

A clean explicit source manifest, reviewed immutable production candidate,
publication authorization and tested rollback are also outstanding. The current
development checkout contains unrelated changes and private operational evidence;
its origin points at the production checkout. Do not bulk commit/push or use
that origin as a publication destination. Production remains untouched.
