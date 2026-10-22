# A7Dev automatic project discovery

User direction: new direct subfolders of `/home/yeli/repos` should become usable
A7Dev workspaces with the same permissions as existing ordinary projects.

Use an owner-installed, immutable root reconciliation helper and a 30-second
systemd timer. It synchronizes the existing workspace registry, public-client
policy, filesystem ACLs and read-only worker runtime allowlist. No gateway
package change, credential access, broad umbrella execution or wildcard
authority is needed. Existing explicit registrations remain authoritative.

Only visible, canonically named, real direct child directories owned by yeli
are eligible. Skip symlinks, hidden/secret names, special files, mount crossings,
registered IDs/paths, and protected roots/aliases (`AgentPorter`, `agentporter`,
`obsidian`, `repos`, `asgard-hermes-review`). Never promote an explicit restricted
workspace. New rows allow read/write, offline execution, Git inspection and
delegation; delegation remains read-only, matching the current ordinary scope.
New rows grant no HTTPS, SSH, SciNet, Git publication or local HTTP authority.
Keep all existing models, credential paths, resource and network settings intact.

The helper runs only from its root-owned installed location with isolated system
Python. Reads are bounded, descriptor-based and no-follow, with strict YAML and
metadata validation. Recursive ACL traversal uses pinned descriptors and skips
symlinks, hardlinked files, other owners/devices and private names. Preserve
existing owner/other ACL entries; never grant access to protected trees or change
the `repos` umbrella ACL. Git metadata remains read-only, private material denied.

Establish a durable admission barrier through the service-account jobs database
before changing configuration or stopping A7Dev. Under `BEGIN IMMEDIATE`, check
for active/unresolved jobs and admissions, then atomically install exact static
INSERT/UPDATE guard triggers on `job_admissions`. Existing jobs defer the update
without cancellation. The triggers prevent new admissions across stop/restart
while allowing gateway startup schema/recovery writes, including empty admission
INSERT SELECT operations. Retaining the SQLite writer lock through startup would
deadlock gateway initialization, so release that lock after guard installation.
Keep the guards through health verification, then verify exact SQL/zero admissions
and remove them transactionally. Record ownership in the root-private journal
before installation; recover only exact owned guards, never unknown trigger SQL.
Do not stop production.

Changes are transactional across all three configuration documents and the
root-private managed-state record. Preserve backups and recover known partial
transactions; refuse to overwrite unknown/newer bytes. Restart only A7Dev when
configuration changes; verify local health before committing state. On failure,
restore exact previous known configuration and service state. An unchanged scan
must not restart anything. Deleted auto-managed roots may be pruned only when
their generated configuration rows still match; never delete project files.

Preserve the existing worker allowlist capacity of 64 roots. Enrollment must not
produce an invalid or silently half-authorized configuration: capacity overflow
is explicitly reported and deferred without breaking registered workspaces.

Prepare a checksum-pinned user-run installer, immutable helper, systemd unit and
timer, plus synthetic security tests. If the acquisition/Git repair is still
pending, install it before enabling reconciliation because its existing runner
pins the previous static registry. Do not commit/push or change live service,
ACLs or registration until the concrete result is verified and local sudo is
available. Document the activation command, interval, exclusions and capacity.
