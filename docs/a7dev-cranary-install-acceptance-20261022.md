# A7Dev Cranary installation and live acceptance — 2026-10-22

Status: **partial acceptance; exact Posit tarball remains blocked**. Current-CRAN access is installed and verified. This workflow targeted development only.

## Installed state — verified through authenticated MCP

- Release: `/opt/agentporter-development/versions/20261022T204324.626687Z`.
- PID: `2864006`; loaded and disk fingerprints both `469ac781ff7df26b85f45ae442d70b9bded6f0927bba92a66eb7fc5a2a8e6e9b`; `stale: false`.
- Effective owner policy: `downloads.cran_all_paths: true`.
- Download hosts remain exactly `cran.r-project.org` and `packagemanager.posit.co`.
- Fixed directory: `data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads`.
- Limits remain 16 MiB and 60 seconds; HTTPS/public-IP checks, no redirects, receipts and no overwrite remain enforced. Generic shell networking remains disabled.
- Read-only systemd inspection: development service active/running; discovery timer active/waiting.
- The operator ran the frozen reviewed launcher. Its runtime gates reported `production_changed: false`; no production deployment or service operation was performed by this workflow.

## Root causes and exact rejection stage

1. Current CRAN was rejected by the historical-only URL policy before worker execution. The installed change permits query-free paths on the exact CRAN host only when the owner opts in with a strict boolean. The owner approved every path on that host.
2. The dated Posit URL was already authorized. Its actual GET returns HTTP **307**, although HEAD returns HTTP **200** with Content-Length **28034**. The worker rejects the non-200 status at `https_download.py`'s HTTP response check, exits **77**, and the parent records `download_worker_rejected` followed by `download_failed` (`ValueError`). This is an upstream redirect conflicting with the preserved no-redirect rule.

The post-install sanitized journal confirms:

```json
{"event":"download_http_rejected","host":"packagemanager.posit.co","http_status":307}
```

The same URL's metadata GET through MCP is also denied (exit 77); its metadata HEAD through MCP succeeds. No outside-MCP network probe was used. The redirect destination remains unavailable through this interface, and no redirect was followed.

## Live positive checks — executed through authenticated MCP

All three successful files were independently read and hashed through offline MCP execution. Saved bytes, returned SHA256, receipt SHA256 field, receipt byte count, receipt HTTP status and independently hashed receipt bytes match.

| Source | HTTP | Bytes | Saved-file SHA256 |
| --- | --- | ---: | --- |
| Current CRAN `src/contrib/staticryptR_0.1.0.tar.gz` | 200 | 27129 | `c2178a57032ef53a137e00faec71d09e75ad5e67e8463bf26b2a2fbee59d23ce` |
| Posit `cran/2021-06-30/src/contrib/PACKAGES.gz` | 200 | 710490 | `a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd` |
| CRAN Archive `src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz` | 200 | 4257339 | `f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42` |
| Posit `cran/2025-06-30/src/contrib/staticryptR_0.1.0.tar.gz` | GET 307; rejected | No saved file | No receipt |

The two existing regression sources also passed caller-supplied expected SHA256 checks. The current CRAN file was hashed independently after acquisition; no prior expected hash was asserted. Receipts continue to mark historical identity as unverified and training eligibility as false.

Saved names in the fixed download directory:

- `staticryptR-0.1.0-current-cran-acceptance-20261022-jax-2122.tar.gz`
- `PACKAGES-post-install-regression-20261022-jax-2122.gz`
- `TCIU-1.1.0-post-install-regression-20261022-jax-2122.tar.gz`

Each has a sibling `.receipt.json`. Receipt SHA256 values, respectively:

- `6d063a3bf1aa54c672cfa6938eec4e72217d7380558d7b5e3bac5e45f45eb6e7`
- `2ed75343505e10860f5d7e3e1c9f04896515d6cce48cd1888e3a630351861e08`
- `e138223f0d1e24125ca7555cdcfe9dad04217b8cfe4ea6bd153b693dd2efed18`

Only new authorized acquisition outputs were created through MCP. Existing research files were not edited.

## Negative checks and offline regressions

Eight live download checks were rejected as expected: existing filename/no overwrite, HTTP scheme, unrelated host, query string, requested cap above 16 MiB, timeout above 60 seconds, body exceeding a 1024-byte requested cap, and an all-zero expected SHA256 mismatch. Offline MCP execution confirmed that failed Posit/negative acquisitions left neither final files nor receipts, and the original CRAN file retained its hash after the overwrite attempt. The actual Posit 307 supplies an additional live redirect-rejection check.

Fresh offline results: **53 guard/helper tests + 223 download/receipt/transport tests = 276 passed**. The one warning is the existing Starlette/AnyIO dependency deprecation. The first sandbox run rejected fixtures because filesystem ownership was remapped; the successful runs used real host ownership without relaxing the policy.

Earlier preserved verification: **2052 repository tests passed, 24 subtests passed**; **267 extracted-package tests passed**. Bash syntax, ShellCheck and `git diff --check` passed before operator installation.

## Exact Cranary repair file inventory

The sole installed package-module delta is:

- `src/agentporter/scoped_https.py` — owner opt-in for exact-host CRAN paths.

Preparation, operator workflow and acceptance inputs:

- `scripts/enable-a7dev-all-cran-paths.py`
- `scripts/activate-a7dev-cranary-source-repair.sh`
- `scripts/prepare-a7dev-cranary-source-repair.py`
- `scripts/verify-a7dev-cranary-acquisition.py`
- `tests/security/test_cran_policy_operator.py`
- `tests/security/test_cranary_activation_launcher.py`
- `tests/security/test_cranary_source_candidate.py`
- `tests/security/test_cran_download_scope.py`
- `tests/security/test_acquisition_acceptance_routing.py`
- `tests/unit/test_scoped_https.py`
- `docs/cranary-source-download-repair-20261022.md`
- `docs/examples/a7dev-cranary-all-cran-paths-https.yaml`
- `docs/a7dev-prepared-next-step-20261022.md`

This report is an additional post-install record. The repository has substantial pre-existing untracked work; this inventory identifies reviewed Cranary inputs rather than attributing the entire dirty worktree to this repair. Acquisition transport and redirect handling were not changed.

## Installation, recovery and reproducible acceptance

The installed artifact SHA256 is `a3af98891bb7d9660676656fe8a6c62388e3853710bba23dae965f51ea14a048`; the frozen launcher SHA256 is `db7e60f5e54b271b129e0686ba6a56a5c47aaa61027afb567b75234942723857`. The reviewed installation plan is in [cranary-source-download-repair-20261022.md](cranary-source-download-repair-20261022.md). Do not rerun the completed launcher.

Policy plan SHA256: `800addc7af91e34ddd37658bfc8aed9ca95a2f741668a6f59a9399a5f4c98c23`. Private policy recovery directory: `/var/lib/agentporter-dev/state/cran-download-policy/cran-800addc7af91e34ddd37658bfc8aed9ca95a2f741668a6f59a9399a5f4c98c23`. Installer rollback evidence: `/opt/agentporter-development/.candidate-367f2824e66429547487e67b9245403f`. Recovery is an operator action requiring approval: stop development; restore policy with the new helper while the new release is current; then use the trusted installer rollback evidence and restart development. Do not perform blind rollback.

To reproduce acceptance, use only authenticated A7Dev MCP:

1. Call `server_deploy_info` and `get_capabilities`; require the fingerprint above, matching loaded/disk values, no stale state, true owner flag, exact directory/hosts/budgets, and disabled generic shell networking.
2. Call `https_download` for each source above with a new unique filename. Supply the known expected hashes for the two regression sources.
3. Read each durable receipt with `read_file`; use offline `exec_run` with Python `hashlib` to compare saved-file and receipt bytes against the returned digests.
4. Repeat the negative checks above; prove failed acquisitions create no final file/receipt and overwrite attempts preserve the original.
5. Require HTTP 200, saved-file integrity and durable receipts for **both requested tarballs** before claiming complete acceptance.

No further terminal installation step is currently needed. **Exact Posit acceptance remains blocked upstream:** with no redirects retained, the supplied Posit endpoint must return GET 200, or the owner must approve a different nonredirecting source. Current CRAN success does not establish byte-for-byte equivalence to the Posit historical artifact.

Detailed captured evidence is under `/tmp/jax-a7dev-cranary-candidate-after-acl/`: `activation.log`, `post-install-acceptance.json`, `post-install-download-journal.log` and `review-report.md`. Independent review found no staging blocker when authenticated post-install identity/scope checks remain mandatory; those checks have now passed.

