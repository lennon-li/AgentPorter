# Prepared A7Dev update: directory repair accepted

No installation, live ACL repair, policy update or service operation has been
performed by Jax. The operator supplied the approved read-only runtime snapshot.

## Prepared CRAN candidate

This candidate predates the completed discovery upgrade described below. Do not
install it using the old runtime admission: capture the post-ACL runtime and
rebuild/review the derivative first. The existing archive remains build evidence.

- Version: `20261022T191624.325897Z`
- Base release: `20261022T181133.685266Z`
- Archive: `/tmp/jax-a7dev-cranary-candidate/candidate.tgz`
- Archive SHA256: `151aa3e7f46dfe4aa9ad50c1e1a9024984d509556bb42fe05b7d7d07157af7bc`
- Loaded-code fingerprint if installed:
  `469ac781ff7df26b85f45ae442d70b9bded6f0927bba92a66eb7fc5a2a8e6e9b`
- Report: `/tmp/jax-a7dev-cranary-candidate/report.json`
- Source pins: `/tmp/jax-a7dev-cranary-candidate/input-pins.json`
- Builder: `scripts/prepare-a7dev-cranary-source-repair.py`, which reuses the
  SHA-pinned existing archive verifier and runtime-preservation workflow.
- Exactly one package module changes: `src/agentporter/scoped_https.py`.
  New operator documentation, policy example and tests are inert evidence.
- Verified full manifest after extraction/repacking and checked source pins.
- Packaged-code acquisition/receipt/HTTPS regressions: 223 passed, one dependency
  deprecation warning. The harness explicitly imported the extracted package and
  checked its module SHA; pytest's repository `pythonpath` override was disabled.
- Candidate-preparation and existing snapshot-safety tests: 35 passed.
- All 43 workspace roots and worker settings are preserved exactly except
  relocation of the installed release prefix.
- Required live runtime canonical SHA256:
  `1290a0b8d3506d41359fd330f2aa1a6fe188eeeaa74390022f20d4ab1083e176`.
  If discovery or any operator action changes it, refresh/rebuild the candidate;
  never bypass the mandatory immediate preinstall drift gate.
- The owner-approved all-path CRAN policy is an example in `operator-plan`, not
  an applied setting. A separate reviewed policy update and development-only
  installation/restart approval remain necessary. Posit HTTP 307 remains an
  unresolved live acceptance blocker; redirects are still rejected.

## Completed operator action: directory access continuation

Run this **before** installing any new release. The continuation is pinned to
the currently installed `20261022T181133.685266Z` release and the 33 existing
writable grants. It does not add grants or install the CRAN candidate.

The command requires explicit operator execution/approval: it publishes verified
helpers, repairs ACL access only on validated ordinary service-owned directories
in those workspaces, restarts A7Dev, repairs directory defaults, then restores
development discovery. File contents and production are excluded. It refuses
remaining human-access blockers, metadata drift, active jobs or altered inputs.
Partial application retains recovery journals and does not assume success.

- Launcher: `scripts/resume-a7dev-workspace-writes.sh`
- Launcher SHA256: `10b60ecc3aebefbe9453334e4e54bf0eb7e636d8829d09c473bf972d1d277d19`
- ACL helper SHA256: `1db22bfc6d2f1d831cb5ca7959386c84bffbafdec22ef72177ec9ff0026047b1`
- Focused helper/default/continuation/activation tests: 94 passed.
- Full repository suite after the ACL work: 1993 passed, 24 subtests passed,
  one dependency deprecation warning. The subsequently added candidate guards
  passed separately as recorded above.

```bash
(
  umask 077
  set -o pipefail
  bash /home/yeli/agent-work/agentporter-dev/scripts/resume-a7dev-workspace-writes.sh \
    2>&1 | tee -a /tmp/jax-a7dev-runtime-20261022/acl-continuation.log
)
```

After execution Jax can inspect that log and authenticated live state directly.
Do not declare ACL acceptance, all-agent acceptance or production readiness from
offline tests alone. A failed continuation needs inspection before another run.

## First attempt and corrected retry

The first operator attempt published the verified helpers and paused discovery,
then failed in the initial planning phase. No workspace ACL apply began and the
gateway was not stopped. The opener used readable descriptors for every path
component; the service's execute-only ancestor ACL caused `EACCES` on `home`.

The corrected shared helper uses `O_PATH | O_DIRECTORY | O_NOFOLLOW` for ancestors
and retains `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` for the final workspace root.
No ancestor permissions are changed. Tests reproduce the execute-only failure,
retain the final-root read requirement and reject a symlink swapped after path
validation. The service helper and both launcher dependencies now pin the new
bytes. The retry republishes those verified helpers; do not edit installed files.

Authenticated live inspection after the failed attempt confirmed PID 2516731,
release `20261022T181133.685266Z`, matching loaded/disk fingerprint and no stale
code. Discovery remains paused pending a successful continuation. Preserve the
previous failure log with `tee -a` on retry.

The failed log was also preserved privately as
`/tmp/jax-a7dev-runtime-20261022/acl-continuation-attempt-1.log`, so rerunning the
original logged command from terminal history will not lose that evidence.
Full regression suite after the traversal correction: 2006 tests and 24
subtests passed, with one dependency deprecation warning. No live repair retry
has been executed by Jax.


## Successful operator retry and independent acceptance

The operator retry completed all phases. Its log records 35 service-owned
ordinary directories repaired, directory defaults applied to 2079 directories
across 33 workspaces, and discovery restored. Authenticated gateway inspection
confirmed A7Dev responding as PID 2773566 on the expected 181133 release, with
matching loaded/disk fingerprints and no stale code.

An independent read-only scan as yeli checked access and default ACL metadata in
2084 ordinary directories across all 33 selected workspaces: zero issues. The
IRVRI subset covered 272 directories, including all 35 service-owned directories,
with zero issues. The detailed report is private:
`/tmp/jax-a7dev-runtime-20261022/acl-independent-acceptance.json`.
This verifies directory access and inheritance metadata; worker-created file
acceptance remains a separate check.

Discovery successfully applied an upgrade for `references`, so the active
runtime must be freshly captured before preparing the release update. The old
snapshot had that root as non-writable. The follow-on read-only capture attempt
could not authenticate sudo noninteractively; no new snapshot was written.
The operator's next step is the approved read-only capture to
`/tmp/jax-a7dev-runtime-20261022/development-runtime-after-acl.yaml`.
Do not rerun the completed ACL continuation. Production remains untouched by
this development-only workflow.


## Fresh candidate after directory acceptance

The replacement candidate uses the operator-provided post-ACL snapshot and
preserves all 43 runtime roots and all seven workers exactly, apart from release
prefix relocation. It does not revert the discovery upgrade.

- Version: `20261022T204324.626687Z`
- Archive: `/tmp/jax-a7dev-cranary-candidate-after-acl/candidate.tgz`
- Archive SHA256: `a3af98891bb7d9660676656fe8a6c62388e3853710bba23dae965f51ea14a048`
- Expected active runtime canonical SHA256: `186225cf8c888a2efc4becee7150029d5cc3435777e8306f66d502bca1f5b97e`
- Package fingerprint: `469ac781ff7df26b85f45ae442d70b9bded6f0927bba92a66eb7fc5a2a8e6e9b`
- Root-owned operator helper when installed: `operator-plan/enable-a7dev-all-cran-paths.py`
- Helper SHA256: `35ab27a480d4a53b810773f016fd5de8bfc205dcf5fae5dd7401844513ee7166`
- Frozen private launcher: `/tmp/jax-a7dev-cranary-candidate-after-acl/activate.sh`
- Launcher SHA256: `db7e60f5e54b271b129e0686ba6a56a5c47aaa61027afb567b75234942723857`

The archive and extracted manifests verified successfully. Current source pins,
the frozen launcher bytes, and exact runtime preservation were independently
rechecked. Full suite: 2052 tests and 24 subtests passed, one dependency warning.
Actual packaged code/helper/verifier tests: 267 passed, one dependency warning.
Finalized launcher and candidate-guard tests: 21 passed; shellcheck, Bash syntax
and diff whitespace checks pass.

The source helper permits only the approved CRAN boolean change, uses private
raw backups and guards rollback against newer settings. Its job gate permits
only six known terminal states and no unresolved admissions. The launcher
pauses discovery, verifies runtime both before shutdown and immediately before
installation, checks trusted tool/archive/helper hashes, and starts A7Dev only
after the policy update. An error after installer invocation leaves development
stopped for inspection. Manual rollback must restore the policy with the new
helper while the new release is still current, then invoke the trusted artifact
installer's rollback using its recorded evidence, before restarting the original
release. Never restart the old package with the new unknown policy key present.

Independent review is **pending owner approval**. Proposed route: one native
Codex reviewer, GPT-6 Luna, high reasoning, subscription. Scope is read/execute
review with a named private result artifact, no project edits, sudo, network
probes, deployment, service operations or provider credential reads. The local
review skill mandates an independent reviewer; delegation defaults to APPROVAL.
Do not present the frozen launcher as approved for execution before review and
operator deployment approval. A7Dev remains on 181133, PID 2773566, non-stale as
of the final authenticated inspection. No installation/restart ran in this turn.


## Operator installation and authenticated acceptance — 2026-10-22

The owner executed the reviewed launcher. A7Dev now serves release `20261022T204324.626687Z`, PID `2864006`, loaded/disk fingerprint `469ac781ff7df26b85f45ae442d70b9bded6f0927bba92a66eb7fc5a2a8e6e9b`, stale false. Owner policy advertises `downloads.cran_all_paths: true`; the fixed directory, exact download hosts, 16 MiB/60s caps and disabled generic shell networking are unchanged. Development is active/running and discovery timer active/waiting. Do not repeat installation or the completed ACL continuation.

Live MCP acceptance: current CRAN staticryptR 0.1.0, Posit PACKAGES.gz and CRAN Archive TCIU all return HTTP 200 with independently verified saved-file SHA256 and durable receipt hashes. Eight live security negatives pass; fresh offline regression checks total 276 passing. Exact Posit staticryptR URL still returns GET307 (HEAD200), logged as download_http_rejected -> worker exit77 -> download_failed. No redirect bypass, alternate-source substitution or production change was made. Overall exact-two-tarball acceptance remains partial/blocked by the Posit upstream behavior.

Full installation, file inventory, regression results, recovery evidence and reproducible acceptance: [a7dev-cranary-install-acceptance-20261022.md](a7dev-cranary-install-acceptance-20261022.md). No further operator terminal step is currently required; exact Posit acceptance needs upstream GET200 or explicit owner approval of a different nonredirecting source.
