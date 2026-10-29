# Request authorization and future publication controls

The shared-policy profile implements signed, expiring task approval for writable
delegation, writable direct execution and destructive typed effects. Both MCP and
REST use the same authorization boundary. Both relay ends verify approvals.

See [shared workspace policy](shared-workspace-policy.md) for the implemented
policy compiler, copy-on-write execution, publication validation, fixed Git
transport, migration and test coverage.

## Implemented boundary

A trusted operator process outside model-accessible workspaces holds an Ed25519
signing key. Approval claims bind the canonical workspace, operation, worker when
applicable, exact normalized arguments, expiry and allowed effects. API keys,
model output, conversation text and caller flags do not count as approval.

Missing, forged, expired or modified receipts fail closed. Stable request
identities recover the original job after retry or uncertain delivery. Changing
the requested task or replaying authority for another effect does not produce a
new permission. Receipt values and private keys must never enter public logs.

Read-only is the default for shared-policy delegation and execution. Writable
workspace eligibility alone does not authorize an edit-capable process. A private
copy-on-write view separates execution from validated publication. Protected
controls, Git metadata and unapproved deletions remain prohibited.

The shared profile treats fixed-purpose public-HTTPS Git fetch as a scoped
transport capability. It grants no general networking, private credentials,
pull, commit or push. Specialized scientific and remote-infrastructure grants
remain explicit and separate from ordinary defaults.

## Still unavailable

Git commit/push remain technically locked until a dedicated trusted publisher
checks the reviewed tree digest, exact remote/ref and expected upstream revision.
A task-edit signature cannot unlock those operations. No speech or chat setting
can fabricate a trusted confirmation event.

A general authenticated approval UI, safe action-mode escalation and integration
with a trusted confirmation device/service require their own design and review.
The current offline issuer and restrictive action policy are not such a UI.

Host administration, arbitrary SSH, credential export, force-push, destructive
history rewriting and agent-triggered deployment are not public tool actions.
Operator maintenance remains a separate administrative workflow.

## Verification

Tests exercise missing/forged/expired/modified approvals, request retry identity,
matching relay policy, read-only mounts, protected paths, descriptor closure,
unsafe output rejection, cancellation, conflict refusal, migration and rollback.
Provider credentials, quota and another installation's live service state need
separate operator verification. Public documentation must not contain real
workspace registries, host addresses, account usage, job output or signed tokens.
