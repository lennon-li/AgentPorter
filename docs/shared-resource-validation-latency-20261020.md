# Shared resource validation latency and workspace scope — 2026-10-20

## Measured cause

The repaired v8 service was healthy, but inventory requests spent minutes in
CPU work without subprocess children. An ordinary-user profile of exactly one
`_shared_toolkit_source()` call against the public installed toolkit took
**10.782 seconds** and 5.23 million Python calls. It hashed 19,608 package
regular files, checked 19,626 admitted package entries across eight packages,
and checked 19 ELF tools plus nine scripts. The manifest is 3,018,175 bytes.
Hashing accounted for about 5.8 seconds, with `Path.relative_to()` adding
2.23 seconds. The package loops are linear in tree size, not quadratic in the
number of admitted files; directories receive a repeated metadata check.

Each first inventory can invoke the full validation about **38 times**:
24 confinement/version/helper `_build()` calls, plus two status calls per
identity. The 30-second confinement cache does not cache the shared-resource
validation in `_build()` or `status()`. The broker separately obtained status
for detection and then obtained it again for each inventory row.

## Changes and security contract

- `src/agentporter/agents/development.py`: adds a per-runtime, locked,
  in-memory success cache. First use retains all tool/package digest, signature,
  ownership, mode, symlink containment and exact membership checks. Unlisted
  top-level resources and undeclared package contents are rejected.
- Only canonical unique release versions with **every non-link resource
  root-owned and owner-read-only** qualify. Symlinks remain root-owned with
  immutable parent directories and are checked against their admitted targets.
  Owner-writable trees continue to undergo full validation on every call;
  untrusted ownership, writable shared ancestors or symlinked trust roots fail.
- Every hit rechecks trusted ancestor/release/top-directory identities and
  permissions, opens the bounded manifest with `O_NOFOLLOW`, compares stable
  descriptor metadata and a fresh full manifest SHA256, and checks runtime
  config identity plus its parsed content digest. Config changes, including
  operator workspace authority revisions, invalidate cached success. A second
  snapshot after initial validation prevents publishing success across a
  manifest/root/config transition. Concurrent first use is serialized.
- The cache is process memory only. No worker-writable validation evidence or
  on-disk cache is accepted. The installer publishes new unique versions and
  refuses an existing version. **Trusted root editing a deep immutable leaf
  in place without a manifest/release revision violates this publication
  protocol and is outside the cache threat model.** This does not claim to
  detect arbitrary hostile-root tampering on every hit.
- `src/agentporter/agents/broker.py`: inventory supplies its one runtime status
  result to detection, retaining metadata and fail-closed confinement behavior
  without executing host CLI detection.

## Operator workspace boundary

Independent review confirmed that the live catalog contains auto-discovered
production/unrelated leaves under broad discovery roots. Registry discovery
inherits `allow_agent_dispatch`, execution and writable flags; the old runtime
had no separate eight-root operator boundary. A discovered production leaf
could therefore pass the registry-only worker admission checks. No forbidden
job was launched during this investigation.

The runtime now requires explicit `allowed_workspace_roots` records containing
canonical `path` and boolean `writable`, with no legacy registry fallback.
Missing, malformed, duplicate or symlinked roots fail closed. Worker launches
must match an exact approved path and retain registry dispatch/execute grants;
write access is the intersection of operator and registry permissions.
Broad-parent checks use approved roots, so an unapproved discovered shiny child
neither gains authority nor revokes the explicitly approved shiny root.
Existing broad-host-root and protected config/state/credential checks remain.

The builder passes reviewed staging workspaces to the provisioner's snapshot.
`workspace_admissions()` requires exactly the existing reviewed `WORKSPACES`
entries, verifies their canonical paths and capabilities, and emits explicit
path/writable records into runtime metadata. It never derives authority from
the discovered live catalog. This guarantee applies to **DevelopmentRuntime
worker launches**; generic catalog/registry-based APIs are unchanged by this
bounded task. No registry row or production configuration was rewritten.

## Verification

- **Executed locally:** current source against the actual public immutable v8
  toolkit, using only a temporary synthetic config: cold **7.747 seconds**;
  seven warm calls **12.69–12.97 milliseconds** each (about 600-fold lower
  repeated validation cost). The original profiled and new unprofiled cold
  numbers have different profiling overhead; the cold/warm comparison above
  uses the same unprofiled implementation. No credentials, providers, gateway
  requests or installed writes were involved.
- **Unit test:** 155 passed across toolkit cache, runtime security, inventory,
  provisioning and artifact roundtrip tests. These cover actual initial
  hashing, concurrent first use, uncached mutable fixtures, config/manifest/
  version invalidation, unchanged-metadata digest protection in independent
  audit, one status per worker, negative production leaf scope, approved shiny
  parent behavior, read-only intersections, malformed authority rejection,
  and runtime metadata propagation.
- **Executed locally:** existing standalone
  `tests/verify_shared_agent_resources_offline.py` passed after adapting its
  explicit class call to the instance-owned validator.
- Independent review owns additional adversarial cases in
  `tests/security/test_shared_resource_cache_audit.py`, including manifest
  swap after a scan, special files, symlink escape and instance isolation.

No runtime deployment, service restart, credential refresh, provider call or
git write was performed for these source changes. Actual inventory endpoint
latency with the new release remains **NOT verified** until a reviewed new
candidate is installed; the benchmark measures only resource validation.

## Frozen v9 derivative and activation preparation

`scripts/prepare-development-overlay.py` produced a new candidate from only
the digest-pinned frozen v8 archive. It never ran payloads. It verified the
entire original release, overlaid exactly the two reviewed runtime/broker
sources, generated a new unique UTC release version, relocated runtime release
paths and the two venv relocation documents, and added the reviewed eight-root
operator authority. Strict manifest comparison requires exactly four changed
release entries and no new or missing entry. All other release file digests,
execute flags and link targets remain identical, including every tool, skill,
native CLI, provider route and credential path. Original resource-admissions
digest remains `74795554efdc1328f1d7398597679f81cd60316bb14beb935e446e4a4b9f08ad`.

| Item | Value |
| --- | --- |
| Previous release | `20261020T223443.649130Z` |
| New release | `20261021T011116.967219Z` |
| Frozen candidate | `/tmp/agentporter-development-candidate-v9.tgz` |
| Candidate SHA256 | `537a7645c38626b65a10b820570d7b984ba98ec6cef28045fd724d0e2abdef2f` |
| Full delta evidence | `/tmp/agentporter-development-candidate-v9-review.json` |
| Preparation script SHA256 | `bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc` |
| Activation launcher SHA256 | `64facc30cfa3cdbecd495216cc59a9c2884bded2cdd0b11ac3b461ea97464b0e` |
| Activation test SHA256 | `a2752b22503df2490e2c78752743458ae2f40313b782d6fbb682f3a99ba69e22` |

The new launcher `scripts/install-approved-a7dev-v9.py` is an ordinary-user
entry point whose caller must pin that SHA256. Its fixed isolated root
bootstrap imports only standard-library code and executes only the unchanged
immutable installed helper (SHA256
`84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`).
The mutable preparation script is never executed under sudo.

Before mutation the launcher verifies the exact v8 current release, immutable
interpreter/code ancestry, exclusive service identity UID 994/GID 981,
root:service data directory mode `0750` without an access ACL, existing private
key metadata, archive digest and helper digest. It holds a nonblocking exclusive
`flock` on the existing pinned installation directory descriptor throughout
activation and recovery; there is no lockfile write. It emits only requested
Jax job metadata before and after stopping development, using a service-UID
read-only/query-only SQLite query of the fixed jobs DB and five explicit
columns. It does not inspect argv, tokens or log contents, dispatch any job,
or retry the previously delayed acceptance request.

It stops only development and invokes the unchanged helper **without
`--activate`**. Before restarting, full `create_asgi_app(Config(...))` and
`list_agents()` run as the real service UID with matching HOME/cwd/private
umask and the immutable new interpreter. All seven exact named rows must pass
real OS confinement and CLI/version probes. This does not dispatch a provider
task or establish provider quota/authentication readiness. Root never reads or
copies credential contents; normal service-UID initialization/probes use the
already provisioned private files internally, with output suppressed except
safe inventory summary fields. Acceptance has a 300-second bound. Restart is
followed by the same redirect/proxy-free loopback health checks with stable
MainPID and NRestarts used by the reviewed directory repair.

Recovery identifies only newly created root-private evidence whose candidate,
previous release and previous runtime digest match the exact captured pair.
It does not depend solely on the installer printing success: a failure after
switching `current` can recover the matching stage and invoke unchanged helper
`--rollback ... --activate`. Successful restoration requires exact previous
runtime/current and healthy service. If no pair changed, only the previous
service is restarted. If installation fails in the narrow interval after
writing runtime but before switching `current`, the unchanged rollback helper
cannot accept that mismatched pair. The launcher deliberately leaves
development stopped and reports that automatic recovery is unverified; it
never weakens the helper's stale-pair check or starts mismatched code/config.
Any failed restoration also requests a development-only stop and fails.

**Executed locally:** both actual frozen v8 and v9 archives underwent full
extraction and unchanged installer manifest verification. Parent validation
then installed the actual v9 archive and restored the exact previous pair in
private temporary storage, simulating only root ownership/DAC and service
effects and rebasing previously checked canonical runtime paths. Evidence:
`/tmp/agentporter-v9-full-install-preflight.json` and `.log`.

**Unit test:** 21 activation/preparation tests pass, including actual temporary
filesystem evidence digests/modes/symlink rejection/ambiguity, actual directory
lock exclusion, success and all recovery branches, metadata-only read-only
SQLite filtering, fixed sudo/helper argument capture, and read-only overlay
replacement. **Unit test / parent full gate:** 1,216 tests and 24 subtests
passed, and all standalone candidate security checks passed in
`/tmp/agentporter-liz-v9-frozen-verification.log`. The sole warning is the
existing Starlette test client's deprecated AnyIO BlockingPortal alias.
Independent archive/bootstrap admission is coordinated by the parent.
**NOT executed here:** live v9
installation, service-UID acceptance, restart or rollback. The live service and
production were not changed while preparing this candidate.
