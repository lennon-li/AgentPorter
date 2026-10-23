# Cranary acquisition repair and acceptance

Status: source change prepared; not installed; Posit tarball acceptance blocked.
Target: A7Dev only. No production deployment, service operations, sudo, commits,
pushes, or edits to existing Cranary research files are authorized.

## Evidence and cause

Authenticated A7Dev `https_download` reproduced both failures on 2026-10-22.
For the dated Posit URL below, the service journal reports worker return code 77,
`download_http_rejected` with HTTP 307, and outer `download_failed` with
`ValueError`. This is a GET response rejection, not URL authorization: the dated
source pattern already passes `_download_target`. Authenticated metadata HEAD
returns HTTP 200 with content-length 28034, while metadata GET also fails.
HEAD is not proof that a subsequent GET will return the same status.

The current CRAN URL fails the historical-only path restriction before worker
launch, hence it has no matching worker-rejection event. Owner approval was
subsequently expanded from that one URL to **every path on cran.r-project.org**.
No wildcard host, mirror, query-string or redirect approval was granted.

The source change adds an optional, strictly boolean `downloads.cran_all_paths`.
Only `true` admits all query-free paths on the exact CRAN host. Old policies and
`false` retain historical-only access. Both host lists still gate access. Posit
URL rules are unchanged. Download limits, public-IP-pinned TLS, no redirects,
fixed receipt directory, no overwrite, and integrity checks are unchanged.

The Posit GET still returns 307. This change does not turn that into success.
Following it or silently substituting CRAN would violate the constraints and
misrepresent source provenance. Its redirect destination is not established:
the existing metadata interface suppresses it. Local networking outside MCP
was rejected by automatic review; the owner explicitly chose to keep all
network diagnostics in MCP. Do not retry outside that interface.

## Live regression evidence

Both authenticated downloads returned HTTP 200 and durable receipts. A separate
offline A7Dev `exec_run` recomputed SHA256 of each saved file and compared it to
its persisted receipt; both matched. Receipt files were also read using MCP.
These are newly acquired files under the already approved downloads directory;
existing research files were not edited.

| Source | Bytes | Saved-file SHA256 |
| --- | ---: | --- |
| Posit 2021-06-30 PACKAGES.gz | 710490 | `a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd` |
| CRAN Archive TCIU 1.1.0 | 4257339 | `f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42` |

Filenames: `PACKAGES-gateway-regression-20261022-jax.gz` and
`TCIU-1.1.0-gateway-regression-20261022-jax.tar.gz`, each with a sibling
`.receipt.json`. TCIU also passed the independently supplied expected SHA256.

## Reproducible validation and operator plan

1. Run offline tests as the normal host user. Sandbox-mapped ancestor ownership
   fails trusted-policy tests before download code runs; never relax that check.

   ```bash
   .venv/bin/python -m pytest tests/security/test_cran_download_scope.py tests/security/test_https_acquisition.py tests/security/test_acquisition_receipts.py tests/unit/test_scoped_https.py -q
   git diff --check
   ```

2. Review the source diff and
   `docs/examples/a7dev-cranary-all-cran-paths-https.yaml`. The latter is a proposal,
   not a replacement for live owner settings. Preserve the actual live download
   directory and tighter budgets. Add only `cran_all_paths: true` to the existing
   `workspaces.cranary.downloads` mapping. Do not install the example wholesale.

3. **Separate installation approval required.** Before installation, capture a
   fresh development runtime snapshot and rollback hashes; build the code-only
   derivative with `scripts/prepare-a7dev-cranary-source-repair.py` through the
   existing reviewed development artifact workflow. Verify packaged tests and runtime drift
   gate. Do not reuse old activation archives or hardcoded hash pins. An operator
   must approve the concrete candidate, owner-policy delta and rollback plan
   before installing the immutable development artifact, updating the private
   owner policy, or restarting A7Dev. Production is excluded.

4. Through authenticated development MCP, call `get_capabilities` and verify
   `scoped_public_https.downloads.cran_all_paths == true`, exact host lists,
   directory, 16777216-byte ceiling and 60-second ceiling. Confirm the loaded
   release fingerprint matches the reviewed candidate.

5. Run `https_download` with `workspace_id: cranary`, unique unused filenames,
   `max_bytes: 16777216`, `timeout_seconds: 60`, and each URL below. Never retry
   with the same filename after a partial publication; inspect receipts first.

   ```text
   https://packagemanager.posit.co/cran/2025-06-30/src/contrib/staticryptR_0.1.0.tar.gz
   https://cran.r-project.org/src/contrib/staticryptR_0.1.0.tar.gz
   https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz
   https://cran.r-project.org/src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz
   ```

   Supply TCIU's independent digest above. Read every returned `receipt_path`
   using MCP `read_file`. Independently hash saved bytes using offline A7Dev
   `exec_run` and compare byte count, digest, URL, HTTP 200, workspace and path
   with the persisted receipt; also verify the receipt's own SHA256. Require
   `training_eligible: false` and `historical_identity_verified: false`.
   Retry a successful filename and require no-overwrite rejection with unchanged
   saved-file and receipt hashes. Wrong host/workspace, HTTP, port 444, credentials,
   fragments, queries, over-cap sizes, and timeout 61 must fail. Offline tests
   exercise redirects and malformed/oversize responses without live side effects.

6. If Posit still returns 307, acceptance **fails**. A future, separately approved
   development release may add bounded sanitized redirect diagnostics to MCP;
   it must not follow redirects or expose sensitive Location queries. Establish
   whether upstream can serve this exact URL directly with HTTP 200. If it cannot,
   the owner must resolve the conflict between exact-URL acceptance and the
   no-redirect requirement. No such exception has been authorized.

## Production readiness remains blocked

Validation executed locally after the patch:

- Focused CRAN, acquisition, receipt and HTTPS tests: 223 passed.
- Full repository suite: 1969 passed, 24 subtests passed, one existing dependency
  deprecation warning, in 102.88 seconds.
- All six offline verifier scripts passed: scoped HTTPS, HTTPS integration,
  HTTPS audit regressions, production relay, shared agent resources and worker
  credential refresh.
- Existing continuation/default ACL regressions: 35 passed with real host
  filesystem ownership. This verifies the existing tests, not live ACL repair.
- Subsequent ACL-helper preparation: 59 focused tests passed, including 24 new
  service-directory safety tests. The continuation now requires its helper SHA
  pin to match; a placeholder is a test failure.
- Full suite after the ACL preparation: 1993 passed, 24 subtests passed, one
  dependency deprecation warning, in 98.40 seconds.
- `git diff --check` and continuation launcher shell syntax check passed.
- Installed all-path CRAN policy and both requested tarball successes:
  **NOT verified**; no installation or service restart was performed.

The continuation launcher now pins the reviewed service-directory ACL helper.
Focused offline tests cover effective rights, real ACL apply/rollback, partial
failure journaling, metadata/default changes, and private-path exclusions.
These synthetic tests do not verify repair under the live service identity.
The operator's continuation completed successfully after correcting ancestor
traversal. It repaired 35 service-owned directories and applied defaults in
2079 directories across 33 workspaces. An independent read-only scan verified
2084 ordinary directories across all 33 workspaces with zero access/default-ACL
issues, including all 35 service-owned IRVRI directories. A7Dev restarted on
the expected release and discovery resumed. Discovery upgraded `references`,
so release preparation uses the fresh post-ACL runtime snapshot.

The new immutable operator helper `enable-a7dev-all-cran-paths.py` proposes only
the approved boolean flag. Apply requires a stopped gateway, no cgroup, known
terminal job states, no unresolved admissions and an exact plan SHA256. It keeps
private raw policy backups outside workspaces and offers explicit hash-guarded
rollback that refuses newer owner settings. It preserves hosts, directory and
budgets. The guarded activation launcher verifies artifact/installed-tool hashes
and live runtime before stopping development and immediately before installation;
it pauses discovery and starts development only after the policy update. If
installation begins and then fails, it leaves development stopped for inspection.

Development installation and policy application still require operator approval.
Blocked writable roots, worker-created-file/all-agent acceptance, Phil/Argie,
Jax concurrency evidence, and production relay/rollback validation remain
separate release blockers. The owner-approved CRAN expansion does not authorize
production changes. The Posit example still requires direct HTTP 200 under the
unchanged no-redirect constraint.
