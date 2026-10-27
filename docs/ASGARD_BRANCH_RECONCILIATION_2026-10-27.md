# Asgard branch reconciliation — 2026-10-27

This source reconciliation preserves the recovered Asgard work while retaining current-main hardening. It does not deploy AgentPorter, activate archived development candidates, install Qman, or run real-account quota/provider operations.

## Inputs and disposition

- Current-main base: `8dec7603307ffa78a9409b00f3ab1ddd5ce2cdd0`.
- Recovery input: `8d7812952bd4d7eed4646dbc80835c2231c13bd0` (`recovery/asgard-20261027`). A normal three-way merge retains its Qman advisory integration and archived development candidate artifacts while preserving the effective-model response fix and BCC acceptance documentation from main.
- Older WIP input: `d7360e29f2baebaa5e27166adf011f3e40a0fa30` (`wip/asgard-20261027`). Its 18 merge-base-relative changed paths were classified: 12 match the reconciled candidate exactly, six are superseded by current-main/recovery behavior. No useful residual WIP-only content was identified. A separate history-only merge records the WIP tip without replacing the reconciled source tree.
- Archived development-candidate source and patch files remain inactive and byte-preserved. Whitespace diagnostics inside preserved patch payloads/archive source are not active-code changes; active-code whitespace checks pass.

## Executed local checks

- Interpreter/dependencies: Python 3.13.15; `uv sync --frozen --python 3.13 --extra dev`.
- Candidate full suite (`tests/unit tests/integration tests/security`): 750 passed, 68 failed, 43 skipped on macOS.
- Parent execution of unchanged main at the pinned base with the same virtualenv: 727 passed, 68 failed, 43 skipped. The local failures require Linux/GNU tooling or unsupported native behavior; they are not claimed as passing coverage.
- Focused Qman, action-policy, public-action inventory, agent-model policy and REST integration: 69 passed, one skipped.
- Archived credential-refresh offline tests: nine passed, one deliberately deselected external-baseline test; standalone offline verification passed. Other archived runners require external pinned runtimes/harnesses and were not executed.
- Credential-shaped scan of introduced paths: no matches reported; no credential values published.

## Publication gates and limits

The parent requires an independent Ming review of the exact candidate and terminal Linux GitHub Actions results before merging the PR or deleting backup refs. The PR records the review verdict, exact revision and CI evidence. Local macOS results do not establish Linux confinement or deployment acceptance. Original SSD-backed checkouts and their uncommitted/unpublished state are outside this isolated reconciliation and remain untouched.
