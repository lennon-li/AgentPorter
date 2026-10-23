# A7Dev Git commit/push repair — blocked acceptance

Date: 2026-10-22. Input:
`HANDOFF_A7DEV_GIT_COMMIT_PUSH_REPAIR_20261022.md` (read through A7Dev because
the local file is owned by agentporter-dev and mode 0600).

## Outcome

**Blocked; no implementation or installation changes made.** The handoff's
explicit stop conditions were reached: the real tool path denies publication,
and the available GitHub identity lacks push permission for the identified
GitHub repository. Production was not changed. No project commit, branch
creation, push, credential change, or service restart was performed.

This is not solely a Bubblewrap mount regression. Removing one mount or
changing directory permissions cannot safely satisfy the requested acceptance.

## Verified boundaries

1. **Public staging policy:** a ChatGPT-exposed A7Dev `git_add` call for a
   deliberately nonexistent acceptance filename returned a tool error. Service
   logs at 11:23:06 EDT record `Operation/workspace outside public-client scope`.
   It was denied before Git or the sandbox ran; no real project file was staged.
   `client_policy.py` requires a separate `git_write` operation for staging.
2. **Commit approval:** the real A7Dev `git_commit` call was rejected. Service
   logs at 11:23:09 EDT record
   `Action git_commit is technically locked pending independently verified approval`.
   `action_policy.py` locks commit/push; `tools/git.py` independently raises
   before either operation. A permissive mode override cannot unlock it.
3. **Filesystem/sandbox:** the native Git helper already passes
   `git_metadata_writable=True` for staging/checkout. Generic execution keeps
   `.git` overmounted read-only. Host ACLs additionally grant UID 994 only
   `r-x` on the checkout's `.git`, and effective `r--` on its index. A harmless
   real A7Dev `exec_run` probe opening `/workspace/.git/index` with `O_RDWR`
   (no truncation and no writes) returned **errno 13, Permission denied**.
   Therefore this investigation did not reproduce an index.lock EROFS syscall;
   it established the earlier policy denial and the actual EACCES independently.
4. **Transport:** generic network execution is refused by the sandbox. Native
   Git fetch/pull are also explicitly locked pending a scoped network backend.
   No approved GitHub publisher/receipt backend is implemented in these paths.
5. **Wrong push target:** development `origin` is the local production checkout,
   `/home/yeli/repos/AgentPorter`, not GitHub. A push to that origin would mutate
   production repository refs and is not an acceptable GitHub acceptance test.
6. **GitHub access:** reading production's remote identifies the candidate
   `https://github.com/lennon-li/AgentPorter.git`. Operator `gh auth status`
   succeeds, but authenticated `gh api repos/lennon-li/AgentPorter` reports
   `pull: true`, **`push: false`**, `admin: false`, `maintain: false`, and
   `triage: false`. This verifies repository identity and read access, not
   write-capable authentication. Operator CLI auth also does not establish that
   an isolated gateway publisher has credentials.

Installed and checkout copies of `tools/git.py`, `sandbox/bubblewrap.py`,
`action_policy.py`, and `client_policy.py` have matching SHA-256 digests.
There is no source-only fix waiting to become live in those files.

The publication design in `docs/action-authorization-design.md` requires a
separately trusted approval issuer and a minimal publisher bound to the staged
tree, branch, remote, expected upstream and one-use receipt. Merely removing
the locks or exposing host GitHub credentials to generic execution would bypass
that boundary rather than repair it.

## Before-state and publication inventory

- Checkout/top-level: `/home/yeli/agent-work/agentporter-dev`.
- HEAD: `ec570bc9041c99e372494de76d1b154c5d742b93`.
- Branch: `a7dev-autodiscovery-20261022`, not detached.
- Upstream: `origin/a7dev-autodiscovery-20261022`; cached divergence 0 ahead / 0
  behind. No fetch was made against the production-backed origin in this repair.
- `.git` and common directory are both the checkout's own `.git` directory;
  `git worktree list --porcelain` lists this checkout only.
- Index/staging inventory was empty before and after probes.
- Path-specific classification is in
  `evidence/a7dev-git-repair-20261022/before-inventory.json`. It contains 364
  dirty/untracked paths at capture, including 8 archives, 25 operator/build
  scripts, 171 generated-evidence paths, and one credential-risk filename.
  A filename classification is not a finding that secret material is present.
  All existing pending project changes are excluded from publication; the
  approved project-publication candidate manifest is empty. The new inventory
  output/report themselves were not included in that before-state count.

No bulk staging, index repair, lock deletion, worktree rewrite, remote rewrite,
or secret publication was attempted. Existing pending work remains intact.

## Tests and acceptance results

Executed natively with the development virtual environment:

```text
pytest -q
  tests/unit/test_git_publication_gate.py
  tests/unit/test_git_fetch_permissions.py
  tests/unit/test_operator_action_policy.py
  tests/unit/test_sandbox_identity.py
  tests/security/test_git_workspace_ownership.py
  tests/security/test_scoped_git_metadata.py
  tests/security/test_closeout_client_policy.py

48 passed, 1 warning in 5.50s
```

The warning is the existing Starlette/AnyIO deprecation. These tests verify
current locks and isolation; they do **not** prove the requested repair works.

| Acceptance | Actual result |
| --- | --- |
| Real A7Dev staging | Failed: public-client scope denied before Git. |
| Real A7Dev commit | Failed: technical approval lock. No commit SHA produced. |
| Real A7Dev push | Not executed: automatic approval review rejected the local production-backed origin. No remote SHA produced. |
| Authenticated GitHub read | Passed using operator gh identity; repository reports no push permission. Not a scoped gateway Git transport test. |
| Disposable add → commit → local bare push | Not performed after mandatory stop conditions; cannot bypass the live locks through a shell fixture and call that tool acceptance. |
| GitHub test-branch push | Not performed: no verified push-capable credential, approved explicit test target/branch, or scoped publisher. |
| Existing regression/security gates | 48 passed; isolation/locks remain enforced. |

Automatic approval review explicitly rejected the push probe because its origin
was the local production repository rather than the verified GitHub target and
GitHub push permission was absent. No alternate route was used to bypass that
rejection. No branch or remote was modified by the rejected request.

## Production and rollback

Production checkout remained on `main` at
`3e70cc9273d226d962b4939399247edf2d02b1e1`, with the same GitHub origin.
The production user service was active at final verification, MainPID 664960,
NRestarts 0. No production writes or restart commands were issued. No attempt
was made to reconcile or push its branches. Development services were not
restarted either. With no code/config/ACL deployment in this repair, no runtime
rollback is needed; original protections remain in place.

Session-created outputs are this report and the before-inventory JSON only.
Regression output is retained at `/tmp/a7dev-git-repair-gates.log`.

## Requirements before continuation

1. Approve the exact GitHub acceptance repository and dedicated test branch;
   do not treat the local production-backed origin as that target.
2. Provision push-capable authentication for that approved target to a separately
   constrained publisher, without sharing credential values in chat or binding
   them into generic Bubblewrap/worker execution.
3. Implement and independently review the trusted approval/publisher mechanism
   and scope policy, then grant only the required staging metadata access.
   Bind approval to exact reviewed files/tree, HEAD, target branch/remote,
   expected upstream, expiry and one-use nonce; reject changed content, replay,
   external/common-directory escapes, force push and unapproved targets.
4. Prepare a disposable, explicitly scoped workspace and local bare remote,
   prove the actual MCP tools end-to-end, then perform only the approved
   synthetic GitHub test-branch push. Keep all 364 existing pending paths out.
5. Prepare a pinned development-only artifact with rollback and repeat the live
   tunnel/gateway acceptance after installation. Production remains separate.

**ChatGPT may not currently commit or push reviewed A7Dev changes through these
tools.** Making the tools appear in the tool list does not implement approval,
credentials, or publication authority.

Separate promotion recommendation (not executed): review and reconcile the
development commits against the GitHub repository in an isolated checkout;
publish reviewed changes through an intentional release/PR process, then use
the existing production promotion/rollback procedure. Do not push this dirty
development checkout into production or rewrite its origin as an implicit fix.
