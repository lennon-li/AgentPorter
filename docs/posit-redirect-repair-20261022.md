# Posit redirect repair — diagnostic installed; destination probe pending

The owner authorized checking Posit's redirect and allowing its verified
destination, development only. Production remains untouched. The exact Posit
staticryptR GET is already authorized, but the installed gateway rejects HTTP307.
Current CRAN access is already installed; do not rerun the earlier CRAN activation.

The current stage only adds a sanitized `redirect_target` diagnostic for Posit
3xx responses. Query/fragment data are omitted; credentials, HTTP destinations,
nonstandard ports, controls and malformed values are excluded. No second request
is made and no redirected file/receipt is published. The actual redirect target
has NOT been observed; no destination has been approved by inference or guessed
from tests. All upstream diagnostics remain authenticated A7Dev MCP operations.
No connected A7Dev MCP tools are currently available to this Prof conversation.
The user previously chose to handle that connection setup themselves.

## Corrected candidate baseline

The saved Jax diagnostic at `/tmp/jax-a7dev-posit-redirect-diagnostic-20261022/`
is superseded and marked `do_not_install`: its runtime contains 12 references to
release `20261022T181133.685266Z`, predating the installed CRAN repair. Its old
canonical runtime hash cannot admit the currently installed release's runtime.
The archived evidence is preserved rather than overwritten or deployed.

The replacement folder is `/tmp/prof-a7dev-posit-redirect-diagnostic-20261022/`.
It is rebuilt from the already installed, SHA-verified CRAN archive:

- Base release: `20261022T204324.626687Z`.
- Base artifact SHA256: `a3af98891bb7d9660676656fe8a6c62388e3853710bba23dae965f51ea14a048`.
- Expected installed-runtime canonical SHA256: `8c9a0491c836043dbdb155f7f8dbbd64feddf2a145fee8ba3d868f79ec572842`.
- Runtime input provenance: the verified installed archive, **not a fresh live capture**.
- Sole admitted package change: `src/agentporter/https_download.py`.
- Other changed files: the two existing Python release-path relocations only.
- No owner-policy changes, added hosts, redirects, ACL repair, research-file edits,
  worker/routing edits, commits or pushes.

The pinned runtime gate must prove the live runtime equals that baseline before
stopping development and again immediately before installation. If discovery or
another action has changed it, refuse installation and obtain a fresh private
runtime snapshot; never bypass the hash gate or silently discard live changes.

## Installation and recovery

The source launcher is `scripts/activate-a7dev-posit-redirect-diagnostic.sh`;
its finalized private frozen copy is `activate.sh` in the replacement folder.
It verifies the archive and trusted root installer/runtime-gate/storage-helper
hashes, pauses discovery, checks terminal jobs/admissions, quiesces development,
and installs with the trusted installer **without `--activate`**. Only then does
it restart development, check local health, and restore the previously active
discovery timer. Only `agentporter-development.service` is operated, never production.
Sudo requires the operator's password; the agent cannot reuse the operator's
terminal authentication.

Failure before installation recovers only a verified unchanged original runtime.
Failure after installation begins leaves development stopped and discovery paused
for inspection. Do not automatically restart an uncertain runtime or roll back
blindly. The trusted installer prints a `.candidate-<id>` evidence directory.
If recovery is needed, inspect that pair, keep development stopped, invoke the
trusted installer's `--rollback EVIDENCE_ID` without `--activate`, validate the
restored original release/runtime, then restart development and restore discovery.
No CRAN owner-policy rollback is needed because this diagnostic does not change it.

After the operator runs the diagnostic, inspect its saved activation log and
verify the loaded fingerprint/effective policy through authenticated A7Dev MCP.
Then trigger the Posit GET via that MCP tool, inspect only the sanitized redirect
event, verify the destination, and implement/test the bounded follow rule before
preparing its separate update. A health response alone does not prove loaded-code
identity or successful Posit acquisition. Redirect success remains NOT verified.

## Verification

Parent review reuses the existing descriptor-safe archive extraction and exact
manifest/delta verification, then tests the actual extracted transport module.
Offline regression coverage includes HTTP redirect rejection, sanitized logging,
no credentials/query leakage, receipts, byte/timeout limits, no overwrite,
integrity failures, runtime relocation, privileged-operation gates, development-only
stop/install/start ordering, and failure recovery. New launcher/preparer tests:
12 passed; the existing focused acquisition suite: 228 passed. One existing
Starlette dependency deprecation is unchanged. The packaged results and finalized
pins are recorded in the replacement folder when preparation finishes.

## Finalized preparation evidence

- Candidate version: `20261022T224004.423620Z`.
- Artifact SHA256: `a5b30705a725369abfd5237f457cf179267af5272f4336967d73bdac82ae5d23`.
- Frozen launcher SHA256: `78f35c3cdd04a5bec594be48f5126b54fe69498f0f3a38745ee63f07420a35a7`.
- Expected package fingerprint after activation: `07439c0f1640b1937d96f9db32df0f2d65a4eb488ebceb0baaaea251a7ce4b63`.
- Full host suite: **2072 passed, 24 subtests passed**.
- Actual extracted-package checks: **240 passed**.
- ShellCheck, Bash syntax, source pins, exact runtime relocation, archive digest,
  and git whitespace checks pass. One pre-existing dependency warning remains.
- Sandbox attempts are preserved separately; their remapped root ownership
  rejects the trusted-directory policy and does not represent host acceptance.
- At preparation time installation had not occurred. The subsequent operator
  installation is recorded below. No redirect target has been observed, and
  the follow rule remains pending.

The private replacement folder contains `report.json`, `preparation-status.json`,
`repository-tests-host.log`, `packaged-tests-host.log`, and `activate.sh`.
Parent code review was performed; no independent worker review is claimed.

## Operator activation verified

The operator ran the frozen launcher. Both live runtime gates passed, the trusted
installer installed `20261022T224004.423620Z`, and development restarted with
PID 2939437 at 2026-10-22 19:59:16 Toronto time. The service is active and the
installed on-disk fingerprint exactly matches the tested candidate. The launcher
verified local health. Production was not operated. Installer rollback evidence:
`/opt/agentporter-development/.candidate-a160de8d35650aee5cd161af5b7e0288`.

The loaded fingerprint/effective scope have not been checked through authenticated
MCP because no A7Dev tools are attached to this Prof session. A filtered host
journal search found no matching post-activation redirect event. The next
required action is an authenticated A7Dev `https_download` retry of
`https://packagemanager.posit.co/cran/2025-06-30/src/contrib/staticryptR_0.1.0.tar.gz`.
An existing authenticated Cranary client can make that request; then Prof can
inspect the sanitized journal event without an outside-MCP upstream probe.
Redirect following remains disabled and full acceptance remains incomplete.
