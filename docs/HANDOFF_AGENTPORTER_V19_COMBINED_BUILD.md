# AgentPorter combined v19 candidate — local trusted-run handoff (2026-10-21)

**Purpose:** Produce one inactive build containing v17-install-r3 security/cancellation hardening and v18 Cranary Posit/dedicated binary-acquisition capability, for later independent review and owner-approved installation. Do not install, restart, use sudo, change A7 production, commit or push.

## Prepared by ChatGPT

- Created `scripts/prepare-v19-combined-candidate.py` as a new standalone, nonroot overlay script. Its source SHA256 at preparation was `3c298b5559a87e2b204c6057a7a45e6c36fc0ba6704da385a7aaebb86e877b39`. Syntax compilation passed.
- Frozen base is `review-artifacts/agentporter-v17-install-r3.tgz` SHA256 `a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac`.
- Six exact acquisition-related source files have pinned hashes in the script: `scoped_https.py`, `https_download.py`, `action_policy.py`, `rest/schemas.py`, `rest/routers/exec.py`, `server.py`.
- Proposed Posit/binary authorization comes from `docs/examples/a7dev-cranary-acquisition-https.yaml`, SHA256 `e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf`. This is inert archive content, not an active policy installation.
- Requires strict `provider_origin`, mandatory public-client policy, and Wei `opencode/glm-5.3-flash-free` runtime to remain in candidate.
- Expected release diff relative to r3 is exactly six source files, one new `operator-plan/public-https.yaml.proposed`, and two venv path relocations. The builder performs round-trip manifest verification and rejects all unexpected release-file deltas.

## Environment blocker encountered

The public A7Dev offline Bubblewrap worker runs as uid 65534 with a projection of source files owned by uid 65534. The immutable-reviewed helper refuses to load a helper file unless owned by its **native invoking uid**; here it aborted with `ValueError: Unsafe reviewed source`. The development `.venv/bin/python` symlink also points to a host-private Python 3.13 installation invisible to the public sandbox; the full test script aborted with `ERROR: development Python 3.13 environment not installed`.

These are correct security boundaries. **Do not bypass or relax source ownership checks.** Use the owner's normal, trusted Asgard local Codex or terminal for the next phases. The remote script is not a validated artifact and no archive was built.

## Native continuation

1. Inspect `scripts/prepare-v19-combined-candidate.py` and its pinned source hashes independently. Do not execute until the script itself is reviewed; ensure no other agent has changed the six source files in the meantime.
2. Verify that the base r3 archive, native Python 3.13 venv, release-build helpers and their owner/modes match the frozen handoffs. If the base is only at its `/tmp` name, use the immutable copy verified by hash.
3. Run as the ordinary unprivileged owner, not root, from `~/agent-work/agentporter-dev`:

```bash
python3 -B scripts/prepare-v19-combined-candidate.py \
  --base review-artifacts/agentporter-v17-install-r3.tgz \
  --version 20261021T213000.000019Z \
  --output /tmp/agentporter-v19-combined.tgz \
  --extract-to /tmp/agentporter-v19-combined-extracted \
  --report /tmp/agentporter-v19-combined-build.json
```

4. Create an isolated test harness using the **actual extracted interpreter** and exact extracted source tree; retain v17-r3 process-tree tests and v18 HTTPS acquisition tests. Test both public/internal gateway authorization and scoped-download denials; avoid substituting current checkout modules for extracted release modules. Run the source suite separately.
5. Execute a streaming archive audit, SHA256 verification, entire manifest comparison with r3, verify all six pinned source files, the proposed HTTPS policy, strict runtime/Wei canonical route, and all 73+ package source hashes. Verify no other changed payloads or unexpected runtime/credential/relay changes.
6. Prepare one installer and rollback plan that **backs up the currently active v12 runtime including Wei free settings and the active Cranary v1 policy**, and installs the combined release, public-client policy, internal-client key, systemd cgroup drop-in, and Cranary version-2 policy atomically within one maintenance window. Do not install v2 policy into v12 alone.
7. Stop before privileged work. Return `docs/HANDOFF_AGENTPORTER_V19_INSTALL_REVIEW.md` with exact archive hash, sources, full tests, native negative tests, remaining Argie ACL incompatibility and Phil deferral, as well as owner-approval and post-install verification gates. Do not represent Argie as fixed.
8. Only with explicit approval: install using trusted immutable root installer; conduct live public/local matching-fingerprint tests, kernel cgroup resource tests, Posit historical `PACKAGES.gz` acquisition, independent checksum-verified CRAN tarball test, and rollback validation. Do not train models or change frozen Cranary research datasets.

**Current running state is unchanged:** A7Dev v12, four approved metadata hosts; production A7 unchanged. The earlier GitHub `ropensci-archive/rrlite` source acquisition is already verified and needs no new scope.
