# Project memory

## Shared policy and worker execution

The optional shared-policy profile compiles ordinary workspace capabilities,
public-client scopes and worker admission from one protected operator policy.
Legacy profiles keep their own defaults. Specialized infrastructure grants remain
explicit, and gateway-only public operations do not become worker capabilities.

Shared-profile delegation and direct execution default to read-only. Writable
tasks require independently signed, expiring authority bound to exact arguments.
Gateway and worker verify it. A stable approved request identity recovers one job
on retry. A failed job is not silently relaunched by replaying that identity.

Private copy-on-write views allow small edits in large workspaces without copying
existing data. Publication validates changed output, rejects unsafe or protected
effects and preserves collaborator access. The view helper must share the
launcher's mount namespace; the trusted bootstrap checks the mounted identity.
Intermediate metadata path descriptors are closed to avoid exhausting service
limits in deep workspace trees.

External and inert Git control files stay masked and read-only during private
code edits. Metadata and signing credentials remain outside publication scope.
Confined public-HTTPS fetch is implemented; pull, commit and push remain locked
behind their missing independent backend/authorization requirements.

## Verification and operating limits

Source tests cover real namespace/FUSE behavior where the environment permits it,
large workspaces, unsafe links and modes, cancellation, source conflicts, signed
grants, retries, scope compilation, service-account preflight and recovery.
Hosted CI may skip kernel-dependent checks; a green hosted run does not establish
another machine's namespace, ACL, FUSE, credential or provider readiness.

Worker registration and runtime eligibility do not prove provider authentication,
account quota or actual model availability. Report provider failures explicitly;
never substitute another account, runtime or model. Keep live job records,
account state, endpoints, registries and recovery journals in private storage.

## Remaining product work

A general trusted confirmation UI and a dedicated Git publisher remain
unimplemented. Publication is not a crash-atomic multi-file commit; operators must
keep non-cooperating host writers quiescent and review the resulting diff.

The reference installer is an operator-reviewed workflow with deployment
assumptions, not an unattended installer for arbitrary machines. Future changes
must preserve private recovery snapshots, pre-shutdown checks and rollback of
only session-owned effects.

See [shared policy](shared-workspace-policy.md), [authorization](action-authorization-design.md)
and [security architecture](../SECURITY.md).
