# Action authorization design

AgentPorter enforces a protected action policy alongside workspace permissions,
client scopes and backend security checks. The [public action matrix](agent-roster-action-policy.md)
documents the installed defaults. Policy changes cannot grant host privileges or
bypass the isolated runtime.

## Current enforcement

An owner installs `action-policy.yaml` outside agent-writable workspaces. The
loader rejects duplicate keys, unsafe permissions, malformed rules and unknown
actions. Exact workspace and agent `scoped_modes` can narrow defaults. The
server checks effective policy for both MCP and REST, including relayed requests.
The receiving worker independently repeats authorization before admission.

Read-only discovery and workspace inspection remain bounded by registrations.
Writable delegation requires explicit client grants and a verified runtime.
Commands run offline in Bubblewrap; only an owner-installed scoped HTTPS policy
can authorize the fixed metadata/download broker. A network boolean does not
grant arbitrary network access. Model traffic uses a separate bounded egress path.

Ordinary scoped Git fetch, pull, clone and local commit use exact workspace/job
bindings and controlled publication. They do not require phone signing. Agent
push is always denied; the owner performs remote publication independently.
Protected metadata, inode custody, transaction recovery and resource budgets
remain mandatory. Tightening commit policy also blocks writable delegation
because a native worker cannot selectively lose local commit capability.

## Trust boundaries

A model response, voice instruction, repository file or caller assertion is not
an independent approval. ChatGPT's tool confirmation setting controls its own
requests and does not issue server-side receipts. Worker credentials, owner
policy, signing material and deployment tooling stay outside writable projects.
No public tool exposes host service management, unrestricted SSH/shell, account
administration, credential export or approval creation.

## Future approval workflows

Any additional receipt issuer must be independent of worker identities, bind
an exact operation and target, expire promptly, resist replay, and record an
audit trail. A permissive action override cannot substitute for a missing
backend. Existing signed Git protocol and recovery support does not enable
agent pushes. Changes to these boundaries require implementation and review;
editing this document has no effect on runtime authorization.
