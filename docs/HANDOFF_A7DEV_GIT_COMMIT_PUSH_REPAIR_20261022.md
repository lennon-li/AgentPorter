# Local agent handoff — restore A7Dev Git commit and GitHub push
Date: 2026-10-22
Scope: Asgard local AgentPorter development installation
Priority: Unblock safe, auditable Git staging, committing, and pushing through ChatGPT A7Dev tools.

## Objective
Fix the **actual permission / sandbox / Git-path failure** that prevents ChatGPT's A7Dev connection from staging and committing changes, then validate an authenticated GitHub push. The user explicitly wants ChatGPT to be able to run `git_add`, `git_commit`, and `git_push`, not merely receive manual terminal instructions.

Do not perform a bulk commit or production promotion as part of this repair.

## Known context (revalidate; not a fresh observation)
- A7Dev workspace ID: `agentporter-dev`; checkout: `/home/yeli/agent-work/agentporter-dev`.
- A7 production checkout: `/home/yeli/repos/AgentPorter`. **Keep it isolated.**
- ChatGPT reaches A7Dev through the OpenAI development tunnel; the tunnel client injects an AgentPorter Bearer credential; AgentPorter enforces workspace authorization.
- A7Dev exposes `git_status`, `git_add`, `git_commit`, `git_push`, `git_fetch`, `git_branch` and `exec_run`.
- Prior attempt at staging was blocked because the Git index was mounted read-only inside A7Dev's bubblewrap sandbox. Determine whether the native Git tools use that same sandbox / policy, and find the *precise* failing syscall or guard.
- Earlier audit found many modified/untracked files, including archives and possible sensitive installers. Those counts may now be stale; **never use `git add -A` or `git commit -a` automatically**.
- Prior audit also found distinct production/development Git origins and branch histories. **Do not assume a push to `origin` goes to GitHub.** The workspace metadata returned an empty branch name on inspection; investigate possible detached HEAD before changes.

## Workstream 1 — identify the real Git boundary (read-only)
1. Locate the source and deployed implementation of A7Dev `git_add`, `git_commit`, `git_push`, workspace path guards, bubblewrap mounts, and Git command execution.
2. Capture sanitized diagnostics for the dev checkout: `pwd`; `git rev-parse --show-toplevel`; `git rev-parse --git-dir --git-common-dir`; `git symbolic-ref --short -q HEAD`; `git status --short --branch`; `git remote -v`; `git branch -avv`; and `git worktree list --porcelain`. Resolve any `.git` file, worktree, alternates, and shared index/common-dir paths.
3. Trace how `git_add` enters the sandbox and whether all required writes to the selected repo's `.git` metadata (index, index.lock, refs, logs, objects) are available. Verify filesystem ownership, permissions, bind mounts, uid mapping, and actual denial message. Do not infer a root cause solely from the earlier read-only error.
4. Identify how `git_push` obtains scoped network egress and GitHub credentials. Show remote URL/host but redact credential-bearing portions. Never print env secrets, SSH private keys, tokens, cookies, or full service environments.
5. Record a before-state inventory, including the target GitHub repository identity, current HEAD, branch and upstream, divergence, and pending file classification.

## Workstream 2 — implement the narrowest safe fix
1. Make the Git mutating tools writable **only inside an authorized, resolved workspace/repository**. Preserve read-only behavior for unrelated directories and production checkout. If a Git worktree uses an external common Git directory, authorize only that exact resolved metadata path and assess cross-worktree effects; fail closed on escapes.
2. If bubblewrap is involved, repair its bind/mount or execution policy for Git metadata and the workspace as needed; do **not** disable sandboxing globally, use `chmod -R 777`, elevate the whole gateway, or grant broad home-directory writes.
3. Keep path traversal/symlink checks, repository allowlisting, per-workspace Git permission checks, command argument validation, user identity controls, and audit logs. Handle atomic `index.lock` creation and cleanup only when demonstrably safe; never delete a live lock blindly.
4. Implement explicit push constraints: GitHub remote host/repository allowlist or equivalent target validation, scoped outbound connectivity, noninteractive Git authentication, branch/upstream checks, and clear handling of non-fast-forward / branch-protection failures. Do not weaken gateway API-key controls.
5. Add a repeatable regression test covering staging and committing tracked edits plus selected new files, detached HEAD, bare vs worktree `.git`, unauthorized workspace, symlink/path escape attempts, denied network egress, absent credentials, and protected/mismatched remote targets.
6. If source and installed runtime differ, document the exact deploy/install path and install only the approved development fix; do not touch A7 production. Preserve a rollback artifact and verify the restarted development service/tunnel stays healthy.

## Workstream 3 — validate end-to-end without endangering project history
1. First use a disposable local Git repository or isolated test worktree and a local bare remote to prove the real A7Dev tool path can `git_add` → `git_commit` → `git_push`, with expected file contents and commit hash on the remote. Test that prohibited write targets remain blocked.
2. Repeat through **the ChatGPT-exposed A7Dev tools**, not just a local shell or unit test. Confirm service logs correlate with those calls.
3. Check GitHub auth with a non-mutating authenticated operation (e.g., `git ls-remote` through the approved route). For the first live push, use a dedicated, explicitly approved test branch on the verified GitHub repo; do not push to `main` or force-push during acceptance.
4. Before touching existing pending changes, classify modified/untracked files into source, docs, generated build artifacts, archives, secrets, and uncertain items. Run secret scanning and relevant tests. Prepare a **path-specific candidate manifest**; do not include archives or installers containing credentials. Confirm HEAD/upstream/divergence and any active worktrees.
5. A production GitHub publication is a separate decision: reconcile dev/prod remotes and branches, then use an intentional reviewed release process. Do not merge, delete branches, rewrite history, or promote A7Dev to A7 during this repair.

## Acceptance criteria
- [ ] A7Dev `git_add` succeeds for an explicitly allowed test file and rejects disallowed paths.
- [ ] A7Dev `git_commit` writes objects/index/refs and reports a verifiable commit SHA.
- [ ] A7Dev `git_push` can push the verified test branch to the **intended** authenticated GitHub repository, with no force and no credential leakage.
- [ ] End-to-end behavior is confirmed via ChatGPT A7Dev tools; not only the local agent's shell.
- [ ] Production checkout, service, remotes, and branches are unchanged.
- [ ] Regression/security tests pass; sandbox and workspace isolation remain enforced.
- [ ] No unrelated files, unreviewed archives, or secrets are published.

## Deliverables
1. A short root-cause analysis, including the failing boundary, evidence and exact code/config changes.
2. Changed-file inventory and tests/commands with actual pass/fail results.
3. Proof of successful test staging/commit/push including branch, remote identity and SHAs (no secrets).
4. Remaining blockers (if any), rollback instructions, and whether ChatGPT may safely commit and push reviewed A7Dev changes.
5. A **separate** recommendation for resolving dev/prod Git divergence and promoting A7Dev to A7; do not execute promotion here.

Stop and report if GitHub target cannot be verified, authentication is unavailable, the real tool path remains read-only, or the fix would require broadening production access.
