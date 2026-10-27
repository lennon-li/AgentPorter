# AgentPorter repository cleanup — 2026-10-19

**Scope:** Asgard `~/repos/AgentPorter`. **Status:** preservation verified, local partial cleanup completed; external worktrees and remote branches remain intentionally untouched.

## Source of truth

- Local and GitHub `main` were both `cdfaa2e0` at cleanup start. The running immutable service and security candidate base were `3e70cc9` (Parallel Search), a descendant of `cdfaa2e0`. **Local `main` was safely fast-forwarded on 2026-10-19 to `3e70cc9`**, matching the running release; GitHub `origin/main` remains `cdfaa2e0` (local main ahead one). Do not reset to older remote main and redeploy.
- Active local security candidate: branch `feat/roster-on-active-20261019`, initial checkpoint `b3f2cf3`. It is a **WIP** and not production-ready: delegated execution is blocked until an OS-confined backend and scoped model egress exist.
- `main` has a clean tracked/untracked worktree after private recovery of unrelated untracked content and a verified local fast-forward to the running release. Remote `origin/main` has not been pushed or changed.

## Verified recoveries — do not delete

Stored under repository-private `.git/agentporter-cleanup-20261019/`:

1. `branches-before.json` and **12 preserved Git refs** at `refs/agentporter-cleanup/20261019/<former-branch-name>`; these retain pre-cleanup tips, including removed branch names.
2. Verified archives plus per-file SHA-256 manifests for obsolete working copies `a7-seven-agent-roster-20261019` (198 entries) and `a7-security-acceptance-hotfix-20261019` (132 entries).
3. `main-untracked-recovery/` and `main-untracked-recovery-manifest.json` preserve **11 untracked files** from the main checkout. Recovered files include Parallel Search and Hermes materials and the two `.orig` tests; they were not silently discarded or committed to main.
4. `worktree-preservation/provision-auditfix/MANIFEST.json` and seven SHA-256-checked files preserve **five modified tracked SciNet files and two untracked tests** from `.provision-auditfix`.

Local `.git/info/exclude` excludes the three still-present nested worktree/scratch directories from the parent status. This is local-only metadata, not a repository-wide `.gitignore` change.

## Completed safe cleanup

- Deleted merged local refs `a7-release-20261019`, `feat/laya-scinet-inference-20261014`, `fix/laya-inference-approval-audit-20261014`, `release/laya-inference-20261015` and `feat/seven-named-agent-roster-20261019`; removed clean historical worktrees with Git where valid.
- Deleted redundant local review ref `review/parallel-search-import-20261019` only after verifying its commit SHA exactly matched the retained `feat/roster-on-active-20261019` base and its private backup ref.
- Removed the backed-up older `.a7-seven-agent-roster-20261019` and copied security hotfix scratch directory after verified SHA-256 preservation. Left current roster/security candidate intact.
- Checked active service fingerprint separately; **no service restart or rollout was caused by cleanup**.

## Intentionally retained or blocked

| Item | Git state | Handling |
| --- | --- | --- |
| `feat/roster-on-active-20261019` | WIP active candidate | Retain; must not deploy until OS isolation and approval architecture are validated |
| `asgard-sync-20261001` | Unmerged local + remote | Preserve until independently reconciled |
| `fix/prof-registration-20261019` | Unmerged; host-linked worktree outside registered workspace | Preserve; its filesystem changes could not be inspected from Bubblewrap |
| `feat/scinet-inference-provision-20261015` / `.provision-laya` | Merged into `origin/main`, 123 tracked files byte-identical, no non-cache untracked files | Host-absolute `.git` worktree link inaccessible from Bubblewrap. Do **not** prune or remove through this sandbox; host-side cleanup after verifying no active users |
| `fix/scinet-provision-six-p1-20261015` / `.provision-auditfix` | Merged into `origin/main`; seven files differed from committed base and are fully recovered | Attempted `git worktree remove --force` failed validation because a host-absolute `.git` link cannot be resolved inside Bubblewrap. No forced filesystem deletion. Repair/use the actual host checkout before removal |
| Merged remote `origin/audit-hardening`, `origin/copilot/fix-failing-github-actions-job`, `origin/feat/laya-scinet-inference-20261014`, `origin/feat/scinet-inference-provision-20261015`, `origin/fix/laya-inference-approval-audit-20261014`, `origin/release/laya-inference-20261015` | Reachable from `origin/main`, no open PRs found on GitHub at verification time | Cleanup candidates **only**, not deleted; current GitHub connector exposes no delete-branch operation |
| `origin/asgard-sync-20261001` | Unmerged | Preserve |

Do not mistake Bubblewrap's virtual `/workspace` for the host's `/home/yeli/repos/AgentPorter` when interpreting `git worktree prune` output. The external links show as “prunable” *from inside the sandbox*, which does not prove the host worktrees are stale. Never prune based on that observation alone.

## Required next steps

1. Finish confined worker backend and operation authorization, run host-native full tests and independent audit. Do not claim seven workers are currently delegatable in the WIP candidate.
2. Reconcile `asgard-sync` and `fix/prof-registration` separately against current `main`.
3. Verify Git worktrees directly on Asgard, then clean merged SciNet worktrees without losing preserved file changes or breaking worktree metadata.
4. Confirm remote GitHub branch deletion support and protections, then remove only merged and unused remote refs after owner-authorized publication; no force pushes.
5. Preserve all manifests and private backup refs until the repaired release is deployed, smoke-tested, and the owner approves archival expiration.
