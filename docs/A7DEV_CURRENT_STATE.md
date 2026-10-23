# Consolidated A7Dev development status

Snapshot: 2026-10-22. This consolidates the accumulated development work without
rewriting historical review evidence or implying a new deployment.

## Start here

- [Action map](A7DEV_ACTION_MAP.md): all 54 recognized public actions, permission
  boundaries, current locks, human involvement, and verification limits.
- [Automatic workspace discovery](A7DEV_AUTODISCOVERY_20261022.md): enrollment,
  protected roots, ACL safety, and the prepared writable-delegation update.
- [Latest installation](posit-redirect-repair-20261022.md): installed Posit
  diagnostic, artifact pins, verification, and remaining acceptance step.
- [CRAN acceptance](a7dev-cranary-install-acceptance-20261022.md): successful
  bounded downloads and negative checks before the diagnostic-only update.

## Implementation represented in this checkout

- Separate public-client workspace grants and protected operator action policy.
- Confined development workers with separate provider/account routes; production
  relay support remains separately configured and gated.
- Provider-origin egress controls, bounded resource envelopes, admission limits,
  owned process handles, cancellation, cleanup proof, and recovery checks.
- Bounded file/artifact reads and traversal; shared human/service ACL handling
  for writes and privately staged patches.
- Fixed-purpose public HTTPS metadata and binary downloads, receipt verification,
  exact-host CRAN scope, and sanitized Posit redirect diagnostics.
- Guarded candidate preparation, immutable installation, scope/ACL repairs,
  acceptance checks, and regression coverage.
- Versioned automatic-discovery profiles with explicit writable delegation and
  persistent operator-override tombstones. This source update is documented as
  **prepared, not installed**; do not infer activation from this commit.

## Last verified development installation

Release `20261022T224004.423620Z` installed successfully and restarted development.
Both live runtime gates and local health passed. Its installed on-disk package
fingerprint matched the tested candidate. Production was not operated.

The authenticated MCP loaded fingerprint and complete effective workspace grants
have not been freshly verified in this conversation. The source checkout includes
prepared work beyond the installed release; committing it does not activate it.

## Outstanding acceptance and technical limits

- Posit's staticryptR GET still returns a rejected redirect. Retry through an
  authenticated A7Dev client to obtain the sanitized destination, then verify and
  implement the bounded allowance. Redirect following remains disabled.
- General server-verifiable human approval and dedicated Git publication/network
  backends remain unavailable. Commit/push/fetch/pull tool denials remain enforced.
- Provider readiness and quota are not established by agent registration or
  runtime launch checks. Unknown provenance remains unknown.
- Prepared policy/installer scripts are historical, pinned operator workflows;
  an old script may intentionally reject the current release. Review its exact
  prerequisites rather than rerunning it from a historical handoff.

## Repository consolidation

The source, tests, operator scripts, sanitized evidence, and historical reviews
are retained together so their dependencies and audit trail remain available.
Release archives under `review-artifacts/*.tgz` and the root integration bundle
are local build assets, excluded from Git and preserved on disk. The release-file
JSON manifest remains versioned because existing verification scripts use it.

Historical evidence under `docs/evidence/` is a dated record, not the current
authority. Earlier handoffs and review reports remain intact; use this page and
the action map before following an older installation instruction.

Validation for consolidation: full local host suite **2072 passed, 24 subtests
passed**. One existing Starlette/AnyIO deprecation warning remains. Documentation
and artifact exclusions do not change installed services or credentials.
