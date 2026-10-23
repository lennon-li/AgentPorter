# Cranary acquisition access — 2026-10-21

**Later installation coordination:** standalone v18 must not be installed over the prepared v17 security work. The [combined v19 approval handoff](HANDOFF_AGENTPORTER_CRANARY_V19_APPROVAL.md) preserves v17-r3 and adds this acquisition interface. Its exact artifact, owner controls and live acceptance supersede the historical standalone installation commands below; installation remains pending approval.

**Checkpoint: GitHub source acquisition works through actual A7Dev. Posit and large binary acquisition are implemented and tested, but not installed or live verified.** The owner authorized access needed for Cranary; this is not an unrestricted-network grant. The original requirement for an independently reviewed artifact and owner-performed privileged installation still applies.

## Live diagnosis and acquisition

The authenticated public and local A7Dev connections reach the same unchanged v12 process and loaded fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, with `stale=false`. Its active grant remains Cranary-only, GET/HEAD, four exact hosts, 256-KiB text/metadata responses and 15-second timeout. Generic shell networking remains disabled.

1. **GitHub:** the installed policy already allows GET on `api.github.com`; there is no repository-path allowlist in its implementation. Old `ropensci/rrlite` and `richfitz/rrlite` requests fail later with worker exit 77/`PermissionError`. Approved GitHub repository search identified the current repository, **`ropensci-archive/rrlite`**, and direct canonical requests succeeded. This is consistent with the old aliases hitting the no-redirect guard; the old worker does not expose their exact HTTP status/Location, so no particular redirect status is claimed. No redirect permission or GitHub grant expansion was needed.
2. **Posit:** `packagemanager.posit.co` is absent from the active allowlist and from v12's compiled reviewed-host catalog. A HEAD attempt was denied before outbound acquisition. A policy edit alone cannot activate it safely on v12.
3. **Large/binary files:** the current metadata worker decodes responses as text, has an active 256-KiB budget and a compiled 1-MiB policy ceiling. CRAN HEAD confirms `TCIU_1.1.0.tar.gz` is accessible, but its 4,257,339-byte binary body needs a dedicated acquisition interface. Increasing the metadata budget would not preserve binary bytes.

Acquired through the actual public connector:

- `https://api.github.com/repos/ropensci-archive/rrlite/commits/b390ba0afb5f1613572ba4ce3d5d733987edd0bd`
- `https://api.github.com/repos/ropensci-archive/rrlite/contents/src/rrlite.c?ref=b390ba0afb5f1613572ba4ce3d5d733987edd0bd`

Verified the returned commit SHA, base64 decoding, declared source size and Git blob identity (`SHA1("blob " + byte_count + NUL + bytes)`). The 4,271-byte source has blob SHA1 `bba6bf7f836a0ebdc52f2554ab32b8bd7410ed1d` and SHA256 `015761af6d0374967c6eb563b211eab208b3b9572673176e659c74fb1d107007`. The saved files were read back through A7Dev and their SHA256s matched.

New quarantined files only:
`/home/yeli/repos/cranary/data-raw/cran-history/reports/2026-10-19-laya-dataset-source-research/a7dev-acquisition-20261021/{commit.json,source-api.json,rrlite.c,acquisition-receipt.json}`.

The original frozen membership, comments, quality gate and training pipeline were preserved. The new receipt resolves the source pointer; it does not adjudicate the review concern. Training/evaluation eligibility and rights clearance remain false. All existing **24 research tests** (8 review evidence + 6 historical population + 10 quality gate) pass through offline A7Dev.

The three root commands required by Cranary's `AGENTS.md` were also attempted through the offline sandbox with Laya off. `exec/cranary .` and `exec/cranary . --check` each reached the 60-second bound (exit 124). `exec/cranary . --json` completed in 54.43 seconds with exit 2: CRAN verdict `unknown`, R CMD check skipped, security `pass_with_waivers`, quality `pass`. Each emitted a `bspm` D-Bus warning; the warning alone does not establish the timeout cause. No system/R profile or package-install workaround was applied. Full R CMD check/submission readiness remains unverified; these infrastructure/access results are not a Cranary release-completion claim.

## Implemented access extension

The proposal retains the four existing hosts and adds **only `packagemanager.posit.co`**, restricted in code to dated CRAN source-snapshot paths. No wildcard hosts, private IPs, metadata IPs, alternate ports, inherited credentials/proxies, shell networking, POST or automatic redirects are enabled.

New dedicated `https_download(workspace_id, url, filename, expected_sha256=None, max_bytes=16777216, timeout_seconds=60)`:

- Independent owner-installed **version-2** `public-https.yaml` approval is required. Existing version-1 policies retain metadata access and cannot enable binary acquisition.
- Download hosts are exactly CRAN and Posit. CRAN paths must be matching `Archive/Package/Package_version.tar.gz`; Posit paths must be `/cran/YYYY-MM-DD/src/contrib/PACKAGES[.gz]` or dated source tarballs. Date validity is checked. Queries, arbitrary service/API paths and `latest` are excluded from binary acquisition.
- GET only, TLS/public-DNS pinning from the existing broker, HTTP 200 only, no redirects, no partial responses, no automatic decompression. Declared lengths and streamed bytes are checked; ambiguous framing and transfer encodings are rejected.
- Hard ceilings: 16 MiB and 60 seconds total via a fixed worker process; at most one download at a time. The hardened source additionally participates in global admission/cgroup controls when those are configured. The acquisition-only v12 derivative retains v12's existing resource profile; it does not claim v17 resource enforcement.
- Bytes spool privately, SHA256 is computed incrementally, a supplied expected SHA256 must match, then the spool is independently rehashed before publication. Without an external expected checksum, the receipt explicitly says `expected_sha256_verified=false`; a first-fetch hash is not external authenticity or historical identity proof.
- Only simple new filenames beneath the owner-fixed research receipt directory. Descriptor-relative traversal rejects symlink directories; atomic linking never replaces existing files or follows destination aliases. No untrusted code is executed or archive unpacked.
- Bounded audit records include URL digest, host, byte count, checksum, outcome and rejected HTTP status; response bodies and credentials are not logged.

Affected source: `scoped_https.py`, new `https_download.py`, `server.py`, `action_policy.py`, `rest/schemas.py`, `rest/routers/exec.py`; the full hardened checkout also maps the new action to the existing public `https` scope in `client_policy.py`. The exhaustive tool catalog becomes 54. REST exists at `/api/v1/workspaces/{workspace_id}/exec/https-download`, hidden from the existing 30-operation Actions schema; MCP exposes the dedicated tool.

Proposal: [examples/a7dev-cranary-acquisition-https.yaml](examples/a7dev-cranary-acquisition-https.yaml), SHA256 **`e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf`**. Installed target remains `/var/lib/agentporter-dev/config/public-https.yaml`, owner/group `agentporter-dev`, mode `0600`. Output subtree: `data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads` in Cranary only.

## Frozen acquisition-only candidate and tests

This candidate is deliberately separate from the broader, uninstalled v17 rollout. It preserves v12's provider broker, worker binaries, shared skills/tools, execution path and agent identities. It carries forward the **already active Wei-free repair**, never the old archive's paid Go default. Phil is unchanged. No production relay is activated.

- Version **`20261021T202703.839741Z`**.
- Archive `/tmp/agentporter-cranary-acquisition-v18.tgz`, SHA256 **`fb6b36a63de7738db09baa6aca0e1b2fcb825ddf2778c1357c6ca3dde084976d`**.
- Read-only review copy: [review-artifacts/agentporter-v18-cranary-acquisition.tgz](../review-artifacts/agentporter-v18-cranary-acquisition.tgz).
- Package fingerprint **`4df2fb253af0f9ccb8e93ebc4797bd1214c51e44bceca27dbc5df3b7e2c437b8`**; 26,346 payload entries and 67 package files.
- Pinned v12 base SHA256 `e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5`; [review copy](../review-artifacts/agentporter-v12-base.tgz).
- Separate streaming base/candidate comparison: PASS, exactly **nine** changed payload files (six source files, inert policy proposal, two venv path relocations). Other payload bytes and non-Wei runtime profiles are preserved apart from necessary release-path relocation.
- Full current source gate: **1,498 tests, 24 subtests, all standalone verifiers PASS**. This includes the broader source hardening and is not presented as the acquisition-only artifact's full regression suite.
- Actual extracted acquisition-only artifact: **181 relevant tests PASS**, including binary REST/stateful MCP, owner grant, native Bubblewrap/identity, old scoped HTTPS, auth, tool policy and metadata. Two explicitly v17-specific acquisition tests are excluded: public-principal scoping and uncertain cgroup cleanup. Both pass in the full source gate. No v17 controls are claimed installed.
- All 26,346 extracted payload entries rechecked after tests, allowing only the recorded two local venv path relocations. Streaming audit, build/harness reports, source pins and logs are in [the evidence index](evidence/cranary-acquisition-20261021/sha256.json).
- Earlier failed runs are retained: one fixture mistakenly registered a workspace containing the protected policy directory; another omitted the required stateful MCP initialization handshake. Fixtures were corrected without relaxing implementation checks. No failed final test is suppressed.

Exact verification entry points:

```bash
bash scripts/verify-development-candidate.sh
/usr/bin/python3 -I scripts/audit-cranary-acquisition-candidate.py --artifact /tmp/agentporter-cranary-acquisition-v18.tgz --base-artifact /tmp/agentporter-development-candidate-v12.tgz --sha256 fb6b36a63de7738db09baa6aca0e1b2fcb825ddf2778c1357c6ca3dde084976d --source-manifest /tmp/agentporter-cranary-acquisition-v18-source/source-manifest.json --report /tmp/cranary-v18-independent-rerun.json
.venv/bin/python scripts/verify-a7dev-cranary-acquisition.py
```

The last command is inspection-only by default. It confirms the actual public/local loaded scope and fingerprint without trying unapproved Posit downloads. The archive cross-check is implementer-authored and is **not independent security clearance**.

## Owner installation boundary — not executed

**Do not install the version-2 policy onto running v12. Its subprocesses independently reload policy, so a policy-only change can break existing HTTPS even before a restart.** Code, policy and rollback control state must be handled together.

After independent review of this exact acquisition-only archive and approval of an A7Dev maintenance window, the owner should:

1. Confirm live v12 fingerprint, no active work to interrupt, private directory ownership/modes, and current policy SHA256 **`0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7`**. Refuse unexpected state. The proposed backup below must not already exist; preserve any existing backup rather than replacing it.
2. Verify the already installed immutable helper `/usr/local/libexec/agentporter/install-development-artifact.py` is root-owned under trusted ancestors and has SHA256 **`84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`**. Direct unprivileged access is denied; this hash was not freshly read from the protected installed helper. The preparation tools used the source helper with that pinned hash. Stop on a mismatch.
3. Execute the following **only after that review/owner approval**, recording the installer's newly generated `rollback_evidence` path:

```bash
sudo /usr/bin/systemctl stop agentporter-development.service
sudo /usr/bin/cp --no-clobber --preserve=mode,ownership /var/lib/agentporter-dev/config/public-https.yaml /var/lib/agentporter-dev/config/public-https.before-cranary-v18.yaml
sudo /usr/bin/python3 -I /usr/local/libexec/agentporter/install-development-artifact.py --artifact /tmp/agentporter-cranary-acquisition-v18.tgz --sha256 fb6b36a63de7738db09baa6aca0e1b2fcb825ddf2778c1357c6ca3dde084976d
sudo /usr/bin/install -T -o agentporter-dev -g agentporter-dev -m 0600 /opt/agentporter-development/versions/20261021T202703.839741Z/operator-plan/public-https.yaml.proposed /var/lib/agentporter-dev/config/public-https.yaml
sudo /usr/bin/systemctl start agentporter-development.service
.venv/bin/python scripts/verify-a7dev-cranary-acquisition.py --after
```

Do not continue past a failed command. These use OS commands and the pre-existing immutable root installer; **never execute mutable repository application code as root**. No production unit/configuration or credential is involved. The normal unprivileged verification script uses the existing connector authentication internally without printing it.

`--after` requires the exact grant and compares actual public/local process/fingerprint. It checks host/workspace/path/budget/POST/shell/redirect-flag denials, downloads the dated Posit snapshot and a 4-MiB CRAN artifact, verifies TCIU's pre-recorded SHA256, rejects a deliberately wrong checksum without publishing a partial file, and runs the existing bounded offline historical-population preview into a **new** report file. It does not train or promote any dataset. Unauthorized HTTP redirect destinations are covered by offline response tests; no live redirect-following permission is granted.

On failure: stop A7Dev; use the immutable helper's `--rollback .candidate-ID_FROM_THIS_INSTALL` **without** `--activate`; restore `public-https.before-cranary-v18.yaml` with `install -T -o agentporter-dev -g agentporter-dev -m 0600`; then start A7Dev. Verify the v12 public/local fingerprint, Wei-free inventory and old Cranary grant. The installer snapshots the **current** free-model runtime; do not substitute the historical v12 archive runtime or older rollback receipt. A rollback has not been exercised live in this task.

## Remaining blockers and research limits

**Implemented → source tests passed → acquisition-only artifact tests passed → independent review pending → not installed → Posit/binary live acceptance pending.** No privileged action, shared-service restart, production change, commit, push or training occurred.

GitHub acquisition is unblocked and resumed. Posit and large-download access are blocked by the installation/review boundary above, not a missing caller flag. Actual publisher responses may reveal further constraints, which must be handled through reviewed scope rather than shell/proxy bypasses.

Even after access succeeds, zero training-ready datasets is the correct status until rights, population coverage, exact historical checked-byte identity, independent adjudication and evaluation-split gates are satisfied. Posit date aliases can resolve to an earlier available snapshot, so preserve publisher metadata and audit the effective snapshot; do not call the requested date proof of the official historical CRAN population. [Posit's repository documentation](https://docs.posit.co/rspm/admin/repositories.html) explains these snapshot semantics.

**Independent reviewer/ChatGPT:** audit the exact small backport, independent authorization, byte/framing/checksum limits, descriptor publication, native compatibility and rollback plan before approving privileged installation. Broader v17 rollout gates remain separate.
