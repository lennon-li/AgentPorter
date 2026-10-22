# A7Dev acquisition and Git repair

Status: source and frozen package verified; release `20261022T015212.581522Z`
is now active. Public connector checks verified capability advertisement, Cranary
Git status, and saved artifact/receipt SHA256 plus gzip integrity.

Activate with the prepared, checksum-pinned runner:

```bash
cd /home/yeli/agent-work/agentporter-dev
bash scripts/install-a7dev-acquisition-repair.sh
```

The operator activated this release after preparation. Jax did not perform
the activation. Reinstallation requires local sudo authentication.
No commits or pushes were made.

## Changes

- `supported_tools` comes from the running MCP registry. Tests compare it with
  SDK and authenticated HTTP `tools/list`, including dynamic tool registration.
  Registration does not grant a caller permission to use a tool.
- Git trusts only the mounted `/workspace` root through process-scoped protected
  configuration. Dedicated inspection also disables external diff and textconv
  helpers. There is no wildcard trust or host/global Git configuration change.
- Each new successful download saves a bounded `.receipt.json` sidecar with
  source URL, UTC acquisition time, HTTP status, size, SHA256, approved relative
  path, selected response headers and explicit verification flags. The return
  value includes the receipt path and its SHA256. Existing files are never
  overwritten.

Receipt publication uses anonymous Linux `O_TMPFILE` staging. The receipt is
linked first and the artifact last, then the directory is synchronized. An
unsupported filesystem fails closed. A failure after linking preserves the
published names and reports an error for operator inspection; it does not
attempt an unsafe stat/unlink rollback. A competing writer could otherwise
replace a name between the identity check and deletion. No partially published
pair is reported as successful.

## Provenance limits

The receipt documents acquisition and byte integrity, not historical identity.
`historical_identity_verified` and `training_eligible` remain false, and
`historical_validation_status` is `not_verified`. A supplied matching checksum
verifies agreement with that supplied value; it does not establish an
independent historical authority. Older downloads are not retroactively
authenticated or silently given invented acquisition receipts.

## Verification

The complete source gate passed 1,663 tests and 24 subtests. The receipt suite,
including the subsequently added real concurrent-publisher regression, passed
49 tests. The unsafe unlink regression was observed failing before the fix
and passing after it. Native tests reproduced and fixed Git's ownership
rejection while leaving a distinct nested repository untrusted. Twelve
installer recovery scenarios passed. `git diff --check` passed.

The final frozen package passed the complete gate with its bundled Python:
1,664 tests and 24 subtests, followed by every offline security check.
All 26,360 manifest entries, the package fingerprint and preserved runtime
were verified; only the two declared temporary harness path relocations differ
from the archive. Independent review passed with no Critical or Important
findings. The harness imports the canonical package path explicitly. One
unreadable retired source build helper, referenced by no test, was omitted from
the harness's source-script copy; no artifact payload was omitted.

Final archive: `/tmp/a7dev-acquisition-repair-final.tgz`.
SHA256: `e0c709af0251d5725057c6d24f960ed1b58e262a2efa923b4b9bec9dd99126f5`.
Release: `20261022T015212.581522Z`.

The existing Starlette/AnyIO deprecation warning remains upstream of these
changes. The source tests use temporary fixtures and do not modify Cranary
research data or train models.

The runner pins the artifact, immutable root installer, previous release,
runtime and policy hashes. It preserves existing project grants, Wei's free
model, HTTPS host restrictions, the 16 MiB limit, timeouts and no-redirect
policy. Live acceptance checks public/local inventory parity, Git in Cranary,
Qman and m3-poc, and a fresh uniquely named copy of the approved 2022-06-30
Posit `PACKAGES.gz` download. It verifies HTTP 200, file/receipt SHA256 and gzip
integrity, exercises denied requests, and checks production A7 is unchanged.
Failed acceptance triggers the runner's checked rollback path.

Evidence: [source verification](evidence/a7dev-acquisition-repair-20261022/source-verification.json)
and [final package gate](evidence/a7dev-acquisition-repair-20261022/final-artifact-gate.log).
Live repair evidence: [public checks](evidence/a7dev-acquisition-repair-20261022/live-repair-verified.json).
No additional download or research write was needed for these checks.
