# Independent shared resource cache review — 2026-10-20 session

**Source verdict: no identified code blocker for the reviewed toolkit cache and DevelopmentRuntime workspace admission changes under the immutable-version publication contract below. Exact v9 archive/launcher admission is recorded in the addendum below; live execution is not verified.** Generic registry-based APIs/catalog remain outside the new workspace fence; this is not a claim that every gateway API is limited to eight roots. The current installed v8 does not contain these source fixes.

## Exact reviewed source

| File | SHA256 |
| --- | --- |
| `src/agentporter/agents/development.py` | `6b09a3a870f6b7c7ab5859397353a59389864ea266d35f7555dafc4a76958be3` |
| `src/agentporter/agents/broker.py` | `7e7619504a38b895974f88a3a15e2f134ede85872162b94ddc9744bc976be32f` |
| `scripts/build-development-candidate.py` | `c748d2fdc189f85515f2c0e67f75c171cd95be2edf2ec31892afa181a3622554` |
| `scripts/provision-development-runtime.py` | `57db044e3ca48df56f090013f2fc39e16d0abd2f8e89b00f7f02c2ddbb2a0bf9` |
| `tests/security/test_shared_toolkit_validation_cache.py` | `814b354a90e682963abc2d294647b65b7ed574e188bf581fa3c4feccede7ccbe` |
| Reviewer `tests/security/test_shared_resource_cache_audit.py` | `05e70aeefa49e6627219db9f322f7a5f2a9890f8522bc208322d184881a7c134` |

Compared broker and runtime changes directly with the public installed v8 source. Broker changes reuse one runtime status result within each inventory row; they retain the confined detection path and routing decision. Runtime changes introduce the toolkit cache and explicit workspace rows. The four-file source delta above requires inclusion in a separately reviewed candidate; builder/provisioner are ordinary-user packaging inputs, not newly trusted root helpers.

## Cache safety argument and precise limit

The cache is per DevelopmentRuntime instance, in memory, with one lock serializing admission and cache hits. There is no worker-writable disk marker or cross-instance success entry. A first successful validation retains the existing tool signature/size/SHA256 checks, exact binary/wrapper set, package file-set checks, regular-file hashes/executable bits, trusted ownership/modes and internal manifest-matching symlink checks. Review caught that extra top-level nodes and undeclared packages in an otherwise empty package admission could evade an ALL-nodes eligibility claim; final code rejects those cases. The actual installed toolkit contains exactly `manifest.json`, `bin`, and `packages`.

Caching requires the fixed `/opt/agentporter-development/versions/<version>/shared/toolkit` shape, a unique version-format directory, trusted nonsymlink directory ancestors, and absence of write bits in the resource directories, manifest, binaries/wrappers and all regular package nodes. Root ownership is required throughout. Root-owned package symlinks are checked for exact manifest targets and resolution within their declared package; symlink mode 0777 is not a writable-content capability when its root-owned parents cannot be changed by workers. Owner-writable resources remain fully validated on every call and are not cached.

Every prospective hit rechecks directory identities/modes/owners along the ancestry and top-level `bin`/`packages`, then reads the bounded manifest through `O_NOFOLLOW|O_NONBLOCK`, checks its opened descriptor before/after reading, and hashes its actual bytes. The token also contains runtime-config file identity and a canonical digest of the parsed config, including the new workspace authority. A changed version, manifest identity/content, top-level trust boundary or config revision cannot reuse the old entry. Cold validation compares the complete token again after the full scan, and an unsuccessful full scan publishes no success. Independent tests verified manifest digest invalidation even when its metadata identity was deliberately frozen, and refusal to publish a cache entry when the manifest changes immediately after a successful scan.

**This is not protection against a privileged in-place deep edit.** An independent synthetic probe warmed the cache, simulated root modifying a deep package payload and restoring mode 0444 without changing the manifest/top-level identities, and observed the cached success. Clearing the token forced full validation and correctly rejected that payload. Root can also replace read-only files by changing root-owned metadata. The optimization therefore depends on the established installer protocol: trusted root publishes a new unique immutable version, refuses replacing an existing version, and changes the manifest/runtime reference for updates. Manual deep modifications must trigger a new admitted release or full revalidation; a warm cache is not a detector for violations of that protocol. This assumption is appropriate for these installer-managed resource trees and must remain an explicit operational constraint.

Workers cannot carry out those changes: they neither own the admitted resource nodes nor have writable ancestor directories, and resource mounts enter worker namespaces read-only. The cache does not bypass fresh config, credential/spec, namespace or per-agent executable admission. Inventory status deduplication is local to one row and is not a persistent authorization cache. Provider authentication is not inferred from resource verification.

## Workspace finding and reviewed correction

The reviewer independently reproduced the original gap using only temporary directories: an umbrella registry with `auto_discover`, execute and writable dispatch enabled discovered an unapproved leaf; the original `_workspace` admitted that leaf even though the umbrella itself failed the broad-parent check. Registry-derived discovery therefore was an authorization expansion relative to the documented eight development roots.

The reviewed code now requires explicit `allowed_workspace_roots` rows with exactly canonical absolute `path` and boolean `writable`. Missing, empty, malformed, duplicate, noncanonical or symlink-root rows fail closed. Selected-path membership is exact, so discovery cannot grant a child or sibling. Registry dispatch/execute permission and writability still intersect that operator authority; a true value in either source alone cannot grant edits. Broad-root/protected-state/credential checks remain. Broad-parent comparison now uses approved roots, so an unapproved catalog child cannot revoke its explicitly approved parent; adding that child to approved roots makes the parent broad and denied.

Packaging derives the rows from the explicit reviewed provisioning workspace plan, not the live discovered registry. The plan must match the fixed eight names and canonical expected paths, reject extra/missing/redirected roots, require execute/dispatch permission and boolean write capability. The builder passes this plan into snapshot creation; snapshot writes the separate authority into runtime metadata. Actual candidate admission must verify the resulting eight paths and caps. Current v8 lacks this field and must not be described as having the new enforcement.

**Scope limit:** the fix constrains DevelopmentRuntime agent launches. Workspace listing and generic file/execute tools still use WorkspaceRegistry; their effective scope is not narrowed by this method. No forbidden live provider job or generic operation was attempted. An all-API eight-root claim requires separate effective registry filtering or authorization at those other boundaries. This limitation was reported to the parent before candidate preparation.

## Independently executed verification and performance

The frozen-source host selection passed **122 tests**:

`.venv/bin/python -m pytest -q tests/security/test_shared_resource_cache_audit.py tests/security/test_shared_toolkit_validation_cache.py tests/security/test_development_runtime.py tests/unit/test_development_delegation.py tests/unit/test_development_provisioning.py`

It includes 12 reviewer-authored adversarial cases: nonroot package owner, a matching-manifest escaping symlink, FIFO rejection without opening it, post-scan manifest race, manifest digest with frozen identity, per-instance isolation, unadmitted mutable node, discovered-leaf denial, both directions of write-capability intersection, registry execute denial and workspace-authority revision invalidation. Author cases additionally cover concurrent first use, mutable-tree fallback, config/manifest/version invalidation, malformed roots, wrapper/binary/file provenance and inventory deduplication. Tests use synthetic credentials and simulated root metadata; actual file I/O, descriptor manifest reads, hashes, chmod changes, threads and synthetic namespace launches run. The restricted runner initially denied ten namespace/netlink cases; all passed in the exact ordinary-host rerun without sudo. A final audit/cache-only run against the exact test-file hashes above passed **30 tests**. The author separately reports 155 focused tests and offline security checks passing; that larger selection was not independently rerun here.

Only public installed resources were used for the independent host benchmark. The toolkit manifest is 3,018,175 bytes, with 28 tools and eight packages containing 19,608 regular entries and 18 links. The existing installed full validator took **7.9778 seconds**. Proposed code on the same installed resources, with a temporary synthetic config, measured:

| Measurement | Seconds |
| --- | --- |
| Initial complete validation | 7.845080 |
| Mean of ten warm calls | 0.012907 |
| Warm minimum / maximum | 0.012784 / 0.013039 |

Exactly one full content validation occurred across those eleven calls. This demonstrates the resource-validation reduction, roughly 608 times between the measured cold call and warm mean. It does not establish end-to-end inventory/delegation latency, CLI/provider availability or live correctness; real confinement probes and other work still run. No private DATA/config/credentials, providers, AgentPorter requests or live service operations were used for the benchmark.

## Remaining admission gates

At the source-review stage these were separate gates; the following addendum records the completed v9 artifact/launcher checks. Actual privileged installation/rollback and live positive/negative workspace/provider acceptance remain separate. Only this report and the disjoint reviewer test file were added; implementation, installed artifacts, service state and git metadata were not changed by this reviewer.

## V9 artifact and activation launcher admission

**Verdict: no remaining identified admission or bootstrap code blocker for the exact v9 inputs below.** This clears the bounded reviewed operation, not live installation, provider success, general publication restrictions or all-API workspace scope. The only privileged filesystem installation is performed by the unchanged trusted artifact helper. No privileged operation was performed by this reviewer.

| Input | Independently verified SHA256 |
| --- | --- |
| `/tmp/agentporter-development-candidate-v9.tgz` | `537a7645c38626b65a10b820570d7b984ba98ec6cef28045fd724d0e2abdef2f` |
| `scripts/install-approved-a7dev-v9.py` | `64facc30cfa3cdbecd495216cc59a9c2884bded2cdd0b11ac3b461ea97464b0e` |
| Ordinary-user `scripts/prepare-development-overlay.py` | `bc49c16bae77964779aa8e2a7e39d7d69ad2df9551ed77cd9de2172e60f126fc` |
| `tests/security/test_development_v9_activation.py` | `a2752b22503df2490e2c78752743458ae2f40313b782d6fbb682f3a99ba69e22` |
| Unchanged reviewed artifact helper source | `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58` |

The reviewer freshly reverified the complete v8 base archive SHA256 `e9b9919f27b9a01e11b8f1274811e035a7d85ecbb809474e83eb6a0a7a89d929` and recovered its exact runtime, release metadata and manifest documents into a private temporary baseline. The complete finished v9 archive hash was then independently verified, the **entire archive** extracted with the unchanged strict installer, and all **26,344** manifest entries verified. Extraction completed at 32.57 seconds; full verification, exact delta checks and symlink closure completed at 52.03 seconds. All **1,066** links resolved strictly inside the release and zero cache paths were present. No archive payload was executed.

The manifest file set is identical to v8. Exactly four release entries changed, retaining their nonexecutable flags:

| Release file | New SHA256 / independently checked change |
| --- | --- |
| `src/agentporter/agents/development.py` | `6b09a3a870f6b7c7ab5859397353a59389864ea266d35f7555dafc4a76958be3`, exact reviewed source |
| `src/agentporter/agents/broker.py` | `7e7619504a38b895974f88a3a15e2f134ede85872162b94ddc9744bc976be32f`, exact reviewed source |
| `venv/pyvenv.cfg` | `4221a220fb6fef6ef008e846cab0f4fdee5f144de44ea2a02a571fd2a44da9b1`, exact old bytes with release prefix relocated |
| `venv/lib/python3.13/site-packages/agentporter_development.pth` | `eb2e0e3263203ee6e992d17902cd6b0b7f09f1868957a0d4b486491b6ce9209e`, exact old bytes with release prefix relocated |

All other release hashes, executable flags and link targets are unchanged. This includes toolkit/shared resource admissions, provider/egress code, worker binaries and dependencies; no credentials are introduced or changed by the derivative. Runtime is exactly the previous object with release-prefix relocation plus eight canonical `allowed_workspace_roots` rows, each `writable: true`, for PAGe, agentporter-dev, cranary, insider, m3, m3-poc, obsidian and shiny. Registry permissions still attenuate those write caps. Release metadata changes only version from `20261020T223443.649130Z` to `20261021T011116.967219Z`; the resource-admission digest is unchanged.

| Extracted document | Independently verified SHA256 |
| --- | --- |
| `runtime.json` | `8ed4c5b2616577fc67c4e6af97dc47f352badbe4294b8af11dd061ecd0ddea6e` |
| `release-metadata.json` | `da5153452a9c68856993f0fba7ac024d140ac007d0819d8419bd2216f12c9612` |
| `release-files.json` | `57b2aea1ad3494033a18faab65250b9ca25122e8d0d8d349f0822884d1a542e3` |

The ordinary-user preparer pins its two source inputs and three packaging helpers before loading their verified bytes, freezes and verifies the v8 base privately, enforces the exact four-entry delta, round-trips the candidate through the strict installer and publishes a new mode-0400 archive without replacement. It is never passed to root. All embedded source/helper pins were independently compared with current bytes.

### Fixed root bootstrap and failure behavior

The root launcher uses only `/usr/bin/sudo /usr/bin/python3 -I -B -c <fixed bootstrap>`. The root bootstrap imports stdlib, requires exact service UID/GID 994/981 and its exclusive group, rejects unexpected DATA owner/group/mode/ACLs, requires existing private config/key metadata without reading key contents as root, and requires the current release to be the exact admitted v8. It pins trusted ancestors and checks bounded regular metadata through opened descriptors. Its direct filesystem opens are read-only or `O_PATH`; deployment/rollback writes are delegated to the unchanged installed helper with its exact SHA256 checked before the first stop and again before every helper execution.

The live installed helper path is protected from this ordinary reviewer, including ordinary host execution. Its actual installed bytes therefore were **not independently readable/hashed here**. The expected digest matches the previously reviewed source; the fixed bootstrap enforces the actual installed descriptor digest before service mutation. Independent synthetic negative checks confirmed that wrong helper bytes are rejected and that this failure occurs before any archive/service/install operation. No sudo was attempted to bypass this read restriction.

Review identified that concurrent invocations could otherwise mistake each other's newly created evidence and roll back an accepted activation. The final bootstrap acquires an exclusive nonblocking `flock` on the pinned existing INSTALL directory descriptor before snapshots or service mutation and holds it through acceptance/recovery. The lock adds no persistent lockfile. A real unprivileged two-descriptor test confirms exclusion.

The bootstrap captures only selected recent Jax job metadata as service UID using a read-only/query-only SQLite connection before and after stopping the development unit; it does not read argv, task prompts or logs, dispatch another job, or treat that snapshot as a job-drain guarantee. It pins the old runtime digest, installs the exact artifact **without `--activate`**, and admits only newly created root-private evidence with the exact v8/v9 record and matching previous-runtime bytes. Stale, other-candidate, modified, symlinked or ambiguous evidence is rejected.

Before restarting, the new immutable interpreter constructs the full app and verifies the seven confined inventory rows as UID 994, with isolated Python, clean HOME/PATH, private cwd/umask and captured output. It launches only the existing confined version/confinement probes, not a provider task. Normal app construction reads the existing gateway key internally and may update service-owned startup state; only safe inventory booleans/status fields are printed. This is confinement/executable acceptance, not provider authentication, quota or task success. Stable loopback health uses no proxies/redirects and requires repeated unchanged PID/restart counters. Production unit control is absent.

On failure after a complete switch, only the newly admitted exact rollback pair is passed to the unchanged helper; old runtime digest, old current target and bounded health must all be restored. Failure before any pair change restarts only the verified previous pair. **An old-current/new-runtime partial failure is intentionally stopped rather than forced through the helper's current-candidate rollback predicate.** Failed or unverifiable recovery requests a development stop and reports failure. There is no bypass of helper checks or destructive version cleanup. Retained versions/evidence may require a separately admitted new version for a later retry. Crashes or unrelated privileged concurrent operations are not claimed to be transactionally recovered by this script.

### Final executed checks and outstanding live gates

The reviewer independently ran **51 passing tests**: 21 activation/evidence/metadata tests plus the 30 cache/audit tests. They cover real descriptor lock exclusion, actual temporary-file evidence reads and symlink/mode/digest rejection; synthetic successful install and startup/health failure rollback; helper failure before mutation and after switch; fail-stop for partial runtime-only mutation or failed rollback; read-only selected-column Jax metadata with a private argv canary excluded; exact service preflight context; and source pin refusal before payload execution. Privileged service/install effects are mocked.

The exact final root bootstrap and both inline service probes compile. Stubbed launcher execution captured its sole isolated sudo argument vector. Independent AST inspection verified fixed development-only controls and absence of direct root filesystem writes; independent negative helper-pin checks failed before service stop. No live bootstrap, helper, service probe, private config or credential was executed/read by this reviewer.

The parent additionally reports the final frozen full gate at `/tmp/agentporter-liz-v9-frozen-verification.log`: **1,216 passed, 24 subtests**, all standalone verifiers passing, with one upstream warning. The parent separately executed the complete actual v9 archive through a temporary install/exact-rollback harness; this reviewer inspected `/tmp/agentporter-v9-full-install-preflight.json` and its log. Root ownership/DAC, runtime-path rebasing and systemctl are simulated there; its previous pair is synthetic, and it explicitly records no sudo, payload execution or service changes. Neither evidence establishes actual installed rollback or provider acceptance.

The caller must pin the exact launcher bytes above and execute those same bytes as the ordinary user. Actual privileged execution, live installed helper/source/runtime fingerprints, stable listener/inventory latency, exact negative workspace enforcement, provider-backed task success and production readiness remain **NOT verified** here. Existing provider quota and generic registry/API scope conditions are not resolved by this admission. Private reviewer extraction/baseline state was cleaned; only the durable report/test artifacts remain.

## Actual v9 attempt: acceptance failed, diagnosis pending

The parent reports that the user executed the pinned v9 launcher: its service-UID startup/inventory child exited 1, the exact previous release/runtime pair was restored, and prior v8 health was verified (reported PID 3146925, restart count 0). V9 remains installed but inactive; the newly created evidence directory is `.candidate-7087e8805d9ee71bee0a40cbb059269f`. No successful v9 activation or provider readiness is established. The child's safe inventory summary was captured behind `check=True`, and stderr was discarded, so the user-facing exception omitted the actual stage/per-agent failure. That diagnostic deficiency was not exposed by the synthetic rollback tests above.

The reviewer independently inspected actual public directory ACLs and installed-code metadata: service UID 994 can traverse the parents and has rwx ACLs on all eight approved roots; v9 release/toolkit directories are 0555 and its toolkit manifest 0444. This makes a simple approved-root DAC explanation less likely, but does not prove the first failure. A single real inventory availability/confinement/model blocker remains a hypothesis, not a finding. No retry, new artifact, source relaxation, provider request or live service operation is recommended before a narrowly scoped service-UID diagnostic preserves safe evidence of the actual cause and a regression covers it.
