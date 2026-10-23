# Local Agent Handoff — AgentPorter Public GitHub Publication and A7Dev Git Repair
Date: 2026-10-22

## Goal
Make ChatGPT's A7Dev Git tools capable of securely staging, committing, and pushing reviewed AgentPorter source to GitHub. Maintain **one public canonical repository** (`lennon-li/AgentPorter`) and ultimately **one clean main branch**. A7Dev and A7 remain *separate runtime deployments/checkouts*; do not merge their service credentials or installations.

## Owner decisions
- Public GitHub is acceptable **only if published content contains no sensitive local information**.
- Authorized acceptance target: GitHub `lennon-li/AgentPorter`, branch `test/a7dev-git-publish-20261022`, synthetic non-sensitive test content only. **No force push; do not touch main in acceptance.**
- Publication of cleaned, validated source to main is the ultimate objective, **but not until sensitive-data audit, reconciliation, tests, and approval gates pass**.
- Use a repository-scoped, push-capable credential through an authorized mechanism; do not bypass unavailable `push: false` permission.

## Verified blockers from previous local investigation
- A7Dev native staging denied by workspace policy; attempted `git add --dry-run README.md` in exec_run failed `/workspace/.git/index.lock: Read-only file system`. Diagnose **native Git tool path** separately from generic exec_run; do not just weaken shell confinement.
- Commit/push require a trusted approval mechanism that has not yet been implemented.
- A7Dev checkout: `/home/yeli/agent-work/agentporter-dev`, formerly on `a7dev-autodiscovery-20261022`, with its `origin` pointing to local production checkout `/home/yeli/repos/AgentPorter` (NOT GitHub).
- A7 production checkout: `/home/yeli/repos/AgentPorter`, `main`, remote `https://github.com/lennon-li/AgentPorter.git`; its main previously diverged from GitHub.
- Prior audit identified 25 modified tracked files and hundreds of untracked items in A7Dev, including approximately 9 GB of release archives under `review-artifacts/`; production had untracked staging trees. Re-audit current state.
- Local agent reported 48 regression tests passing, **not** a successful commit/push integration test.
- Prior diagnostic report: `docs/A7DEV_GIT_COMMIT_PUSH_REPAIR_20261022.md`. Prior handoff: `docs/HANDOFF_A7DEV_GIT_COMMIT_PUSH_REPAIR_20261022.md`.

## Execute
1. **Inventory and backup:** Read both previous docs. Record live worktrees, branch/HEAD/upstreams, remotes, divergence, service deployment fingerprints, and uncommitted files. Preserve recovery refs/backups before altering Git state. Do not discard/overwrite any change.
2. **Privacy audit for a public repository:** Audit *all* proposed files and relevant Git history for tokens/keys, private config, identities/personally identifying information, internal paths, user-specific endpoints, agent credentials, private infrastructure detail, logs, environment files, embedded archives, large artifacts, and generated evidence. Classify each as safe/public, sanitize, omit, or undecided. Scan staged diff again before every publication; redact findings in reports. Never paste real secrets into chat, reports, commands, or commit history. Do not blindly add files or publish the full review-artifacts/ tree.
3. **Fix the narrow Git capability:** Trace native A7Dev `git_add`, `git_commit`, and `git_push` from API to authorization to sandbox. Enable bounded writes to the *authorized repository* and only its actual Git metadata paths, including index.lock/objects/refs, while retaining OS isolation, symlink/path containment, worker restrictions, and cross-workspace denials. Preserve explicit approval for destructive/publishing actions. Do not grant generic host shell access or globally relax bwrap mounts.
4. **Trusted publication authorization:** Implement the existing intended trusted approval/receipt model or a narrowly scoped equivalent under AgentPorter policy. Require an identifiable authorized client, explicit repository/branch/ref and operation scope, and fail-closed replay/expiry constraints as appropriate. Do not substitute a static allow-all approval, log fake approval, or assume ChatGPT's ordinary API key alone authorizes unrestricted publication.
5. **GitHub auth + remote:** Provision or request owner provisioning of a push-capable, fine-grained GitHub credential restricted to `lennon-li/AgentPorter` (Contents read/write), stored outside the project and never disclosed. Verify the git remote resolves directly to the approved GitHub repo, not the production local checkout; avoid changing production's origin. Keep dev/prod branches and worktrees intact until reconciled.
6. **Acceptance:** Run regression/security tests; use isolated disposable Git repo plus local bare remote for stage/commit/push and authorization denials. Then test **through ChatGPT-exposed A7Dev tools** end-to-end. Finally push only a benign test commit to `test/a7dev-git-publish-20261022` after verifying target and credential scope. Verify remote commit SHA and absence of unexpected files. No main push or production deployment during acceptance.
7. **Main consolidation proposal:** After acceptance, prepare the precise safe-source manifest, reconcile existing local/remote histories without force-push, document conflicts and branch retirement plan, and produce a reviewed main publication candidate. Only execute publication when content/authorization gates pass; do not delete branches or release archives by default. A7 production promotion and BCC deployment are separate follow-up phases.

## Acceptance / stop conditions
- A7Dev `git_add`, `git_commit`, `git_push` work through ChatGPT tools on approved scope.
- Invalid workspace/path/ref/remote, absent approval, and absent GitHub write auth are rejected.
- Public branch contains *only* reviewed synthetic or sanitized content; GitHub commit SHA verified.
- A7 production and all services unaffected by the repair; no exposure of secrets.
- Full results, code changes, test logs, public audit manifest, rollback steps, and unresolved decisions recorded.
- **Stop** if GitHub push capability is unavailable, approval system cannot be built safely, public privacy cannot be demonstrated, or any required change would weaken production isolation.

## Output
Update `docs/A7DEV_GIT_COMMIT_PUSH_REPAIR_20261022.md` with actual findings and proof; create `docs/AGENTPORTER_PUBLICATION_AUDIT_20261022.md` containing only sanitized public-safe summaries. Report exactly what succeeded, what failed, and what is needed from the owner.
