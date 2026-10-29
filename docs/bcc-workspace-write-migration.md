# BCC generic workspace write migration — candidate

Generic commands no longer receive a canonical writable workspace bind.
The unsupervised/legacy command path mounts the workspace read-only even when
the workspace permits writes. Writable file tools retain their own scoped
mutation checks. Generic command writes require the supervised private-overlay
transaction path; this is the intended writable BCC production profile, not a
read-only replacement for the requested production workflow.

The protected BCC profile must enable `sandbox.workspace_transactions: true`
and supply verified job resource supervision. Startup refuses that mode without
its resource provider. Existing synchronous commands, queued commands, and
delegated agents then edit private storage and publish eligible changes only
after verified cleanup and conflict checks. The root workspace mount starts
read-only and the transaction wrapper replaces it with its pinned overlay.
The generic mount builder offers no arbitrary-code canonical-write exception.

`get_capabilities().sandbox.workspace_access` reports `read-only` or
`transactional`. A workspace's writable file permission alone does not imply
that legacy generic execution may write it. Check this mode before treating
shell write failures as a repository-permission problem; do not restore a
canonical writable bind to bypass them. The cross-owner overlay probe and
real installed-profile verification remain prerequisites to BCC rollout.

Fixed trusted Git staging and checkout retain their explicit write boundary.
Before granting it, they use the approved backend's bounded metadata inspector
to reject hard links, symlinks, special files, nested mount boundaries, active
locks, and unsupported external metadata layouts. They explicitly set the Git
directory and worktree to the registered in-sandbox paths, preventing
repository `core.worktree` configuration from redirecting staged paths into
Git control data. Existing hook/filter denial remains in force. Owner-approved
commits continue through the protected signed-request backend.

Native regressions cover existing nested history, canonical ref hard-link
aliases, hard-linked reflogs targeting an unrelated repository, worktree
redirection, and direct/nested namespace remount attempts. Disposable Git
computations remain possible in private `/tmp` storage. Supervised ordinary
edits still publish through synchronous, queued, and delegated transaction
paths. Cancellation tests observe descendants through a separate test-only
evidence mount and verify the canonical project remains unchanged.

Delegated runtime launches now reject ordinary hard-linked files in read-only
mode too. A native regression demonstrated that a masked `.env` value could
otherwise be read through an ordinary alias; the previous writable-only check
did not protect read-only agents. Such layouts are refused before launch.

These source changes do not update the existing BCC gateway or worker release.
Source test results do not establish cross-owner operation, provider success,
independent approval issuer deployment, or AP-01 through AP-06 acceptance.
