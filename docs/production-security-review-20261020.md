# Independent security review — 2026-10-20

Current status: **No remaining code blocker found to constrained A7Dev installation through the reviewed data-only installer**, subject to independently admitted exact artifact/installer hashes and privileged authorization. Live acceptance and production activation are **not cleared** by this review. The initial findings below describe the earlier tree; subsequent sections record their disposition. This local independent review uses synthetic fixtures only. No provider invocations, real credential reads, sudo commands, service mutations, or AgentPorter delegation were performed.

## Blocking findings

1. **High — private directory contents enter public skill snapshots.** `stage_shared_obsidian()` admits a leaf whenever its other-read bit is set, without checking the privacy of descendant directory ancestors. A synthetic `skills/private/` directory mode `0700` containing `sensitive.md` mode `0644` was copied successfully. The recursive extension allowlist is not a reviewed publication manifest. Require explicitly approved per-file hashes and reject private descendant directories; freeze the canonical index and permitted resources without copying unrelated notes.

2. **High — privileged provisioning still consumes mutable source and follows checked paths.** `snapshot()` checks executable/helper ELF headers and then reopens their names through `shutil.copy2()`. `copy_tree()` recursively consumes the mutable interpreter, venv and repository source without approved digests. `immutable_tree()` checks symlinks and later follows pathnames with `chown`/`chmod`. `atomic_text()`, `private_dir()` and initial credential copying likewise retain check/open boundaries under service-owned paths. The provisioner's `validate_inputs()` requires its own location under the writable development checkout, contradicting the trusted installed-helper requirement. Do not execute this repository script as root. Build unprivileged; admit a frozen, independently reviewed artifact using trusted installed data-only code, pinned source/destination descriptors, approved digests, and bounded regular-file reads. Reject unsupported special files and escaping symlinks before publication.

3. **High — root ACL changes use replaceable workspace pathnames.** `grant_workspaces()` skips symlinks during scanning but later invokes privileged `setfacl` on those names; file batches do not use physical traversal. A workspace can swap a checked pathname for a symlink before the command. Scope ACL changes through validated pinned objects, or exclude mutable workspace ACL provisioning from deployment and use an independently vetted operator procedure.

4. **Medium — tool hashes establish consistency, not approved provenance.** `stage_standalone_tools()` accepts arbitrary user-owned ELF files under selected home directories and records their hashes only after copying. Require a reviewed manifest of names, exact permitted sources, expected hashes, and dependencies. Validate bytes read through pinned descriptors against expected hashes before staging. An ELF signature does not prove dependency availability or approved origin.

5. **Medium — FIFO opens can block privileged work.** Tool source opens and `_validated_secret()` use blocking `O_RDONLY` before checking file type. A synthetic credential FIFO blocked for the one-second subprocess deadline when the parent-directory trust check was isolated using a synthetic trusted-parent fixture. Use `O_NONBLOCK|O_NOFOLLOW`, `fstat` regular-file checks, bounded reads, and before/after descriptor consistency checks. Initial `copy_worker_credentials()` also reads unbounded by pathname.

## Boundaries observed

- Worker launch constructs `--unshare-all`, drops capabilities, disables nested user namespaces, clears the environment, mounts only the selected workspace at `/workspace`, masks control/secret paths, and closes inherited nonstdio descriptors before the worker runs.
- Broker task packets use `/workspace` for confined project roots. The runtime uses `--chdir /workspace` and rewrites Codex `-C`, `--cd`, and `--cd=` arguments. Real delegated path behavior remains an integration acceptance requirement.
- Shared-resource runtime validators require root-owned immutable release paths and read-only mounts. Toolkit validation rejects unlisted binaries and mismatched recorded hashes. These controls do not fix unsafe acquisition or establish tool provenance.
- Credential refresh separates hardcoded source identities and authentication material from route inspection, stages private output via pinned descriptors, and does not intentionally print secret values. OAuth persistence/rotation and real synchronization remain unverified.
- Public egress resolves addresses on the host, rejects private/special addresses and mixed public/private DNS answers, and connects to the checked numeric address. Its API accepts CONNECT to public port 443 only. This code did not yet supply the required tightly scoped Headroom path at review time.

## Verification and limits

- Focused pytest invocation: `tests/security/test_development_runtime.py`, `tests/security/test_development_egress.py`, and `tests/unit/test_development_provisioning.py`: **83 passed, 24 failed**. Most failures are this reviewer execution sandbox denying sockets/netlink; three provisioning failures are genuine fixture/error-contract regressions already reported to the parent. Parent host verification must distinguish those categories and supply real namespace execution evidence.
- `verify_shared_agent_resources_offline.py`: fails because a rejected symlink raises `OSError(ELOOP)` while the fixture catches only `ValueError`. Its positive assertions inspect mount arguments; they do not execute a sandbox or demonstrate tool runtime dependencies.
- `verify_worker_credential_refresh_offline.py`: blocked in this execution sandbox because nominal root-owned filesystem ancestors appear as UID 65534; the helper correctly rejects that ownership. Repeat on the actual host without weakening production ownership checks.
- Synthetic private-directory disclosure: reproduced, `PRIVATE_DIRECTORY_COPIED True`.
- Synthetic FIFO source blocking: reproduced with trusted-parent fixture isolation and subprocess timeout.
- No claim is made about live A7/A7Dev fingerprints, provider connectivity, Headroom optimization, all 38 tools, publication enforcement, actual immutable installation, or production activation. Those require evidence from the frozen installed candidate.

## Final clearance gates

Close the findings above; rerun the full suite and hostile source-swap/private-directory/FIFO/provenance tests; inspect the exact trusted installer and immutable candidate manifest; execute real namespace probes for all seven identities and two workspaces; prove skills read-only and tool dependencies within the sandbox; verify credentials remain private and routes unchanged; test Headroom's scoped bridge and measured optimization; independently test production relay restrictions and rollback. A health response or `delegatable=true` does not satisfy these gates.

## Follow-up: data-only artifact installation

The follow-up implementation moves candidate construction into the unprivileged `build-development-candidate.py` and rejects root execution of the legacy provisioner. The new `install-development-artifact.py` consumes an explicitly supplied archive SHA256, copies the input into private installer-owned staging before verifying it, manually extracts bounded regular members, rejects hardlinks and special files, restricts symlinks to release-relative targets, and verifies the exact release file set, bytes and executable bits. It does not run archive Python or alter accounts/workspace ACLs. This removes the legacy root copy/chown/ACL operations from the proposed installation path; those legacy operations must remain unreachable under root.

Latest inspected resource staging adds exact admitted resource/tool digests, descriptor-based nonblocking tool reads, source consistency checks, and private descendant directory rejection. Credential reads now use `O_NONBLOCK` and before/after descriptor metadata checks. Headroom is exposed through a distinct fixed-service capability only for the exact canonical route `http://127.0.0.1:9787/v1`; this is separate from public CONNECT egress. Real routing and optimization evidence remains outstanding.

Added independent adversarial tests in `tests/security/test_development_artifact.py`: **25 passed**. They exercise canonical member paths; hardlink/FIFO/device rejection; escaping symlinks and attempts to traverse extracted symlinks; duplicate members; file-size limits; mandatory metadata; privileged-mode stripping; exact hashes/file sets/executable flags; symlinked directory pinning; and rejection of non-root intermediate directory owners. Additional source-admission tests prove a mismatched archive digest never reaches extraction and a source FIFO is opened with `O_NONBLOCK|O_NOFOLLOW` before being rejected. Synthetic ownership fixtures isolate actual `O_NOFOLLOW` execution from this review runner's mapped filesystem ownership. Runtime directory pinning now validates root-owned intermediate components and the requested final owner; an initial compressed-output inference about that logic was withdrawn and replaced by executable tests.

**Clearance remains pending**, rather than rejected solely because of superseded legacy code. The parent is still completing worker executable admission, package validation and rollback. Final approval requires reviewing those completed changes and the exact immutable artifact/installer hashes, then verifying the installed candidate and live delegation. None of the follow-up tests executes installer payloads as root or establishes live deployment acceptance.

## Final code review: A7Dev installation boundary

The completed installer rollback implementation and credential-sync units were reviewed. Three additional rollback fixtures demonstrate exact runtime/release restoration, restart of the development service only, and rejection of stale or external rollback pairs before changes. The timer invokes only the trusted installed credential helper with the isolated distro interpreter. The service uses root for the bounded credential-copy operation, denies network access, mounts the system read-only, and limits writable persistent state to A7Dev's existing data directory. No new code blocker was found in these units.

Independent Headroom review found and reproduced an additional control-plane escape boundary: a client-declared WebSocket request previously entered duplex forwarding without first establishing that Headroom had accepted the upgrade; bytes pipelined before the handshake were also admitted. The corrected implementation rejects pre-handshake remainder data, validates the WebSocket request key, and verifies the upstream `101`, upgrade headers and RFC-derived `Sec-WebSocket-Accept` before granting duplex transport. Denied/non-upgrading responses remain response-only. Independent fixtures now reject admin/metrics and ambiguous targets, HTTP framing ambiguity, HTTP and WebSocket pre-handshake pipelines, denied/non-upgrading responses, and invalid accepts; a valid upstream WebSocket handshake successfully reaches duplex forwarding.

The final independent targeted run passed **50 tests**: 28 artifact/rollback tests and 22 Headroom boundary tests. These are code-level synthetic checks, not live delegation or full-suite evidence. No remaining code blocker was identified for installing an independently reviewed exact candidate on **A7Dev only** through the trusted installer. This does not authorize privileged execution, establish provenance of an artifact not yet admitted, or clear production activation. The initial legacy privileged implementation must remain disabled. Live acceptance must still demonstrate all requested confinement, tools/skills, credentials, provider connectivity, actual Headroom optimization and version fingerprints; production reconciliation and relay activation require their separate review.

Reviewed file SHA256 values:

| File | SHA256 |
| --- | --- |
| `scripts/install-development-artifact.py` | `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58` |
| `scripts/build-development-candidate.py` | `e08b2c6a56b672bd9abbeec4ff6aa0b61cfb0c8d1161e5d29780495e642e7a46` |
| `scripts/provision-development-runtime.py` | `c5d80d9ab88f3687e3fb65161877e35eaee66a91875a61d53e9a8ae68865c3e3` |
| `scripts/refresh-development-worker-credentials.py` | `84d63f18efa1dbf84c3804afd621eace4b2091565e29d6e3f77d372a283db5f5` |
| `src/agentporter/agents/development.py` | `f2c7be192b84a7208f6932049bc91d79a7fb4581582adc4a2ad611a5c36c6f8f` |
| `src/agentporter/agents/development_egress.py` | `0d0f5899f668d743b4f10db516df8a6b4889f689639df6ec6074d7bf4a98ca8e` |
| `scripts/agentporter-dev-credential-sync.service` | `30bd3a3a9e26f5733d3efd4520c1645a735eddcebb4c0ae55e470b4519922bca` |
| `scripts/agentporter-dev-credential-sync.timer` | `43b7a2200c0a0521e400adb01da93abf759f7ebdb685e4529234b9aa4f3738c2` |

## Frozen v7 candidate admission

Independently verified the complete archive SHA256 of `/tmp/agentporter-development-candidate-v7.tgz`: **`58db31a16a80a3147808d41bf0d7febcfcf27d378de203d4c6db634f385451b8`**, release **`20261020T223443.649130Z`**. A streaming archive inspection checked all 30,427 member paths/types and symlink destinations without extracting or executing payloads. The archive's 66 matching AgentPorter source files equal the current checkout byte-for-byte. Its admitted-resource JSON exactly matches `/tmp/agentporter-resource-admissions-v7.json`; the shared snapshot contains exactly the 142 admitted files; seven named worker entries and the explicit Parallel Search opt-in are present.

The narrow Parallel Search change preserves only the operator-enabled fixed `https://search.parallel.ai/mcp` endpoint and `web_search`/`web_fetch` tools for supported adapters. Arbitrary canonical MCP entries remain stripped. The independent opt-in/off regression passes. Current reviewed source hashes superseding the preceding table are:

| File | SHA256 |
| --- | --- |
| `scripts/build-development-candidate.py` | `7f917976416aef0c2689a0ddca778dbc07b146043b0247f3b8a9150ae5698ee4` |
| `src/agentporter/agents/development.py` | `a6798b511cc301fde4e31b6d1d13aaced9cead0543dd3490ec227d21f373d854` |
| `src/agentporter/agents/parallel_search.py` | `6f6a60264f008fd829d60dba0f38b6a85902d85ec3118f97a413caf28f1e3f5c` |

The independently rerun bounded review selection passed **92 tests**, excluding 10 actual namespace/live executable cases unsupported in this review runner. The host verifier log `/tmp/agentporter-candidate-host-v5.log` records **1,111 passed, 24 subtests passed, one warning**, followed by complete candidate verification PASS. The reported v6 offline Bubblewrap tool proof contains all 38 required tools with actual functional command output and `runnable` states. Delta's exit 1 is the expected successful detection of fixture differences; all other tool commands return zero. The v6/v7 admitted tools, dependency packages, shared files and worker executables are identical. This review inspected the proof and matching admissions; it did not independently rerun those 38 commands inside a namespace.

**The exact v7 artifact above and unchanged trusted installer hash `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58` have no remaining identified code/admission blocker for constrained A7Dev installation.** Privileged authorization and trusted-helper bootstrap are still separate requirements. This admission does not establish live provider connectivity, credential synchronization behavior, Headroom optimization, active fingerprints, or production readiness. Those remain acceptance gates after installation.

## Authorized v7 local-command bootstrap review

Reviewed `scripts/install-approved-a7dev-v7.py`, exact SHA256 **`9ea0c8b7bb5eaa1be7b3c3b6e6c04d64f5ba8c915cf7a2d79e68d6099bfeb421`**, for the user's authorized A7Dev-v7 installation. Independently verified the launcher digest and all four embedded helper/unit digests; compiled the embedded bootstrap without executing it; and verified the actual sudo argument vector selects `/usr/bin/python3 -I -c` with fixed bootstrap code. The root bootstrap treats repository files as bounded nonblocking data, validates regular-file ownership, descriptor consistency and exact approved hashes, and publishes root-owned helper/unit files atomically through pinned trusted parent directories. It subsequently executes only the installed immutable helpers and the exact previously admitted v7 archive, targeting A7Dev and its credential timer. No new blocker was found for this operation.

The caller must read the launcher bytes as the ordinary user, validate their pinned digest, and compile/execute those same bytes unprivileged. It must not invoke mutable repository Python by pathname under sudo. This review performed no sudo execution, launcher execution or service mutation. It does not alter the separate production-relay blocker or imply that the approved v7 archive contains later production-only SNI hardening.
