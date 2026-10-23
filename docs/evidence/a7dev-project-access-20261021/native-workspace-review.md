# A7Dev nested workspace gate and readiness review

Date: 2026-10-21. Scope: source implementation and synthetic security tests only; no service/configuration installation, credentials, real providers, commits, or production changes.

## Implemented

- `src/agentporter/agents/development.py`: a requested read-only approved parent containing approved descendants passes only when the parent and every approved descendant deny writes. Writable parent, child or grandchild still rejects. Existing host-wide, credential, state/configuration, registry execution/delegation and operator allowlist checks remain.
- `status()` now returns `runtime_dispatch_workspaces` only after each exact registry root passes the same `_workspace(path, False, config)` admission check used by `prepare()`. This reuses verified config, does not launch extra probes and does not call providers. Ordinary OS/value errors omit a workspace instead of promoting it.
- `tests/security/test_development_runtime.py`: positive read-only parent/child/grandchild admission and `--ro-bind` construction; negative writable parent/child/grandchild and requested writes; authoritative inventory exclusion for unallowlisted, non-executable, non-delegatable and protected roots; native synthetic Python process verifies reads work while writes at all three levels fail.

## Verification

Exact successful command, executed unprivileged outside the tool sandbox (native namespace/socket access):

```sh
.venv/bin/python -m pytest -q tests/security/test_development_runtime.py --basetemp=/tmp/anr-1021-b
```

Result: **92 passed in 5.67 seconds**. Includes all existing native Bubblewrap fixtures, all seven synthetic executable checks, old writable-parent refusal, protected-file and credential checks, and the new native nested read-only test. `git diff --check` passed.

Earlier sandbox execution failed expected Unix socket/netlink operations; one initial native attempt used an overlong temporary directory causing an AF_UNIX path-length failure. A short private pytest root resolved this without changing security code. One new fixture initially declared a protected config ancestor registry-writable and correctly hit the pre-existing trusted-launcher gate; fixing that fixture to read-only retained the intended protected-root admission test. These failures are not suppressed in the final result.

Final owned file SHA256:

- development.py: `817b7c1a4346ab0dfd665d8e4af3f506bc4c16a929fdbffe97e4dd83791684d9`
- test_development_runtime.py: `04f1b3a6c394a00ad23efefda5417f6fe66fb4c50739d23e7b7d874f768e9adc`

## Independent review of surrounding readiness patch

The original `PublicClientPolicy.result('list_agents')` intersected only public scopes and registry flags. It could positively advertise a root absent from the independent runtime allowlist or rejected by runtime protected/nested checks. Reported this substantive issue to the parent; the implemented runtime field enables an authoritative intersection in the separately owned client-policy change. Public output must remove the unfiltered internal field to avoid revealing hidden workspace IDs. Existing provider execution/quota disclaimer remains necessary: scope readiness cannot prove provider success.

REST workspace inventory now forwards workspace_id and retains scoped readiness fields; dispatch denial remains a PermissionError for REST and a ToolError for MCP. No additional substantive bug found in those inspected routing/schema changes. Their final parent-owned integration remains to be rechecked after the authoritative intersection is updated.

## Independent review of authorization helper

Reviewed `scripts/authorize-a7dev-project-delegation.py` at SHA256 `36c933ce57b3d178a05c3e964b61ddebf6cbfd0ad3b36f5519cf4bf6c3edec92`.

It pins all 46 root IDs/paths, exact existing public policy, semantically frozen runtime except release relocation; grants only ordinary-project public dispatch/exec and registry execute/dispatch; admits new runtime roots read-only; makes the nested shiny parent read-only; excludes protected IDs from new grants; preserves HTTPS scope and worker/credential/provider fields. Application requires service UID, stopped service, absent service cgroup and zero jobs/admissions. Per-file atomic/fsynced replacement, exact input checks, private backups, guarded rollback and preservation of newer state are appropriate. It never executes as root or reads credential contents.

One robustness finding sent to parent: canonical realpath equality does not establish that each pinned workspace currently exists as a directory. A missing ordinary root could produce a plan and then fail dispatch. Require directory existence in the helper or enforce that explicitly in preflight before installation. No authorization bypass found. No privileged execution or live-provider acceptance performed by this review worker.

Verdict: owned nested gate and authoritative runtime inventory **pass native security tests**. Full live activation/acceptance is **not verified by this worker** and must remain parent-owned.

## Follow-up: unreadable child directories

Actual public all-workspace acceptance reported `list_files(m3, path='', depth=1)` failing at recursive child open for `runtime`. Implemented a narrow traversal correction in `src/agentporter/workspaces/bounded.py`: only `PermissionError` from opening an incidental child directory is logged with its workspace-relative path and skipped. Explicit requested-root opening is unchanged and still denies; ELOOP and other OSError values are unchanged; symlink avoidance, traversal/depth budgets and entry accounting are unchanged. No ACLs, root access or credentials changed.

`tests/security/test_closeout_file_bounds.py` adds deterministic fake-open access denial, explicit-private-root rejection, skipped-directory budget accounting and ELOOP propagation. Exact command `.venv/bin/python -m pytest -q tests/security/test_closeout_file_bounds.py`: **7 passed in 0.28 seconds**. `git diff --check` passed.

Development launch is independently affected: `_masks()` uses `os.walk(..., followlinks=False, onerror=failed)`; `failed` always raises `PermissionError('cannot inspect development workspace metadata')`. Therefore unreadable incidental directories still block delegation even after listing is fixed. The current mask architecture emits `(relative, True, False)` for a directory that is replaced by `--ro-bind` of an empty 0555 directory. A narrowly designed unreadable-subtree mask could avoid exposing contents while permitting work on the remaining repository, but the existing 0555 placeholder permits traversal of a fabricated directory. A distinct empty 0000 placeholder better preserves the denied subtree's access semantics. Require native Bubblewrap tests at an unreadable target, fatal requested-root access denial, same-pinned-root relative-path validation, and fail-closed non-permission errors before adopting this behavior. This review worker has **not changed `_masks()` semantics** or granted permissions.

The actual `/home/yeli/repos/m3/runtime` is a yeli-owned directory with a named ACL entry `user:4294967295:---`; no ACL changes were made. This explains why apparent ordinary mode bits alone are not authoritative for service access.

## Final authorized follow-up: opaque denied subtrees and worktree control files

The parent explicitly authorized the bounded semantics correction after reviewing the preceding architecture. The earlier statement that `_masks()` remained unchanged is now superseded by this section.

- Read-only `os.walk` PermissionError handling accepts only a nonempty strict descendant under the same lexical pinned workspace path, with an absolute canonical error filename and no parent traversal. Root failures, absent/outside/noncanonical filenames, writable scans and ELOOP/EIO/ENOENT remain fatal. No denied contents are inspected or copied.
- Accepted denied subtrees receive a separate empty mode-0000 source bound read-only over the target. O_PATH component pinning rejects symlink replacements without reading denied content. The host directory permissions and contents are unchanged. Cleanup restores only the private placeholder's permissions before removing the job directory, preventing inaccessible-placeholder leaks.
- Read-only `.git` **control files** are masked with an empty read-only file before parsing their contents, so external worktree configuration or paths are never loaded or mounted. This deliberately permits repository file inspection without claiming Git operations work inside such a worker. Writable worktree validation/rejection remains unchanged. Symlinked Git control files remain fatal.

Native synthetic proof creates a genuinely unreadable mode-0000 child (the host test itself cannot list it), launches Bubblewrap, confirms visible ordinary source content, mode 0000 at the denied target, and failed listing/reading/writing of that subtree. Host content and permissions remain unchanged and private job directories are removed. A separate native fixture proves an external worktree's control file is empty/read-only, its external configuration is invisible and unchanged, and writable launch still rejects. A synthetic replacement fixture confirms an opaque candidate switched to a symlink is rejected.

Final successful command, unprivileged outside the tool sandbox:

```sh
.venv/bin/python -m pytest -q tests/security/test_development_runtime.py tests/security/test_closeout_file_bounds.py --basetemp=/tmp/anr-1021-d
```

Result: **107 passed in 5.93 seconds**; `git diff --check` passed.

Final file SHA256 (supersedes preceding owned-file pins):

- development.py: `89730afb5bb1fe10b0f96b1334a58f067e9b966f1bb0dcf6a0b4b73fb392d5d4`
- test_development_runtime.py: `7f251bedc3d4197f430664056e933757353e4464975b01fe123463bb69e34906`
- bounded.py: `cc9f9b5188376328a33e0a2c7d9a83e47c37f3c0ef5aa59932c2bb5a4e49448f`
- test_closeout_file_bounds.py: `caf6b00121b7aa59c56c94d6ebaa6595b164c1f6b7289fae378e2dfe9ba4c369`

No service installation, host ACL changes, production changes, real credentials, provider/model calls, commits or pushes were performed by this worker. Live all-project acceptance remains parent-owned.
