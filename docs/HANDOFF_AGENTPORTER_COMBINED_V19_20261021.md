# AgentPorter combined v19: builder handoff / review hold

Date: 2026-10-21. Checkout: `/home/yeli/agent-work/agentporter-dev`.
Status: **source integration prepared and independently checked; no combined archive yet; nothing installed.**

## Objective
Create a single **immutable, inactive** release that combines the reviewed
`v17-install-r3` cancellation, provider-origin, public-client, and cgroup
controls with Cranary's bounded dated-Posit HTTPS and binary acquisition.
Do not install two separate releases or replace the running v12 or production A7.

## Work completed through public A7Dev

- Created `scripts/prepare-v17-v18-combined.py`, SHA256
  `5277c4be4f29e0325d2f8692ded48f27b3ec536e800e0da4fe604b1fdb0566f1`.
- Created `docs/combined-v19-overlay-pins.json`, SHA256
  `6d593e61a937d3af7e427e15fe308ef03dc1782375b50d4b6f95ad3daa6d4e6b`.
- Created `docs/combined-v19-source-check.json`: passed seven-file
  exact-source-delta check, preserved r3 byte-identical
  `resources.py`, `tools/jobs.py`, `sandbox/bubblewrap.py`,
  compiled all changed source, and verified two allowed and five denied
  Cranary acquisition paths.
- Frozen baseline: `review-artifacts/agentporter-v17-install-r3.tgz`,
  SHA256 `a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac`.
- Operator policy proposal: `docs/examples/a7dev-cranary-acquisition-https.yaml`,
  SHA256 `e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf`.
  This remains inert until separately approved and installed.
- No provider credentials, protected policy, datasets, service units, running
  jobs, production gateway, commits, or branches changed.

**Seven overlay source files:** `action_policy.py`, `client_policy.py`,
`https_download.py`, `rest/routers/exec.py`, `rest/schemas.py`,
`scoped_https.py`, `server.py` (all under `src/agentporter/`).
The builder fails if anything else changes or one pin mismatches. It
preserves v17-r3's runtime aside from release-path relocation.

## A7Dev execution boundary — why local host is required

Two execution attempts ended immediately:

1. `python3 -B scripts/prepare-v17-v18-combined.py ...`: the fixed
   `prepare-development-overlay.py` helper refused to read the protected
   `install-development-artifact.py`: **`ValueError: Unsafe reviewed source`**.
   Do not relax the helper's ownership/mode checks or copy protected files
   into the sandbox to work around the refusal.
2. `bash scripts/verify-development-candidate.sh`: **`ERROR:
   development Python 3.13 environment not installed`** inside the
   A7Dev Bubblewrap execution sandbox.

These are not candidate build or test failures. They mean the restricted
public gateway cannot perform the owner host-side packaging/test task.

## Local Codex — next steps (UNPRIVILEGED ONLY)

Run from the actual authorized Asgard host checkout, with access to its
installed Python 3.13 development environment and reviewed build helpers.

1. Verify pinned builder/helper source and ownership; recheck both source and
   frozen baseline hashes. Stop if the worktree has changed.
2. Build a new, inactive candidate (all output paths must be absent):

```bash
python3 scripts/prepare-v17-v18-combined.py \
  --manifest docs/combined-v19-overlay-pins.json \
  --version 20261021T213000.000019Z \
  --output combined-v19.tgz \
  --extract-to combined-v19-extracted \
  --report docs/combined-v19-build-report.json
```

The script uses a bounded pinned baseline, exclusive outputs, canonical
packing, extracted-member verification, byte-for-byte runtime comparison,
exact expected source delta, and SHA256 recheck of the copied archive.

3. Run `bash scripts/verify-development-candidate.sh` on the complete
   checkout using its real development interpreter. Run the complete suite
   against the **extracted combined artifact**, not merely this checkout.
   Ensure actual native Bubblewrap, strict egress, public-client MCP/REST,
   Headroom, Wei-free, cancellation, cgroup, and new `https_download`
   tests all execute without omissions. Distinguish source-suite and exact
   artifact-suite results.
4. Independently stream-audit every archived payload member and its
   embedded release-files manifest, symlink chains, source hashes, runtime,
   and operator-policy SHA. Preserve the SHA256 and package fingerprint
   in a new review evidence directory.
5. Prepare a **single atomic owner maintenance/rollback proposal** that
   snapshots current v12 plus its active Wei-free runtime and four-host
   Cranary grant. Add reviewed v19 strict public-client and cgroup control
   files **and** the v2 Cranary public-HTTPS policy as a coordinated change
   while A7Dev is stopped. Do not install the v2 policy into running v12.
6. Obtain independent security review and explicit owner permission
   **before any privileged systemd/config writes or service restart**.
   Never modify A7 production, Argie's account/ACL permissions, or Phil.
7. After any authorized installation: verify public and local fingerprints
   and effective scope; use a dedicated `https_download` call to acquire
   dated Posit `PACKAGES.gz`, validate size/hash/provenance, test expected
   bad URLs/checksums/redirect denial, and verify native kernel cgroup
   limits and cancellation. Confirm the connector/Actions client actually
   exposes the new download tool; do not rely solely on the server's tool
   count. Exercise an actual rollback only under the approved maintenance
   plan.

**Keep Argie unavailable under strict ACL policy pending authoritative
semantics; Phil remains deferred.** Do not treat this as seven-agent
production acceptance or research training clearance.

## Return to ChatGPT

Produce `docs/HANDOFF_AGENTPORTER_COMBINED_V19_INSTALL_REVIEW.md` with
the final archive SHA256, exact source/archive tests, package fingerprint,
changed file list, install/rollback commands, owner approvals needed,
live-v12 preservation checks, Argie exceptions, and readiness gates.
Stop before privileged activation. The assistant can independently review
that exact frozen artifact and provide the owner a clear go/no-go.

**Current gate:** Source integration PASSED; actual combined artifact
NOT BUILT; combined regression suite NOT RUN; no installation; no live
Posit acquisition.
