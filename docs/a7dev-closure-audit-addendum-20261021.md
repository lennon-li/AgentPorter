# A7Dev closure audit addendum — queued handoff
Date: 2026-10-21 (America/Toronto)
Owner: local AgentPorter development agent (implementation and authorized deployment)
Independent reviewer: ChatGPT/A7Dev read-only acceptance review
Status: QUEUED; do not interrupt ongoing v13 work, overwrite in-flight changes, deploy autonomously, or touch A7 production.

## Purpose and timing
This addendum supplements, rather than supersedes, the existing v13 provider-origin broker, Argie, production relay, and installation handoffs. The local agent should acknowledge this addendum at its next safe checkpoint after it finishes or safely parks its current task. Preserve its current work, artifacts, and rollback route. Do not have two agents editing the same source files.

A7Dev closure is distinct from the later A7 production relay rollout. Keep A7 production unchanged throughout this closeout.

## State at handoff (evidence checked 2026-10-21)
- Running A7Dev gateway is the installed v12 build, release 20261021T132836.936455Z; loaded/disk fingerprints match, stale=false; startup was 12:36:46 EDT.
- v13 hardened provider-origin candidate was assembled and its source suite reportedly passed 1,389 tests and 24 subtests; it was not installed at the last check. Re-check before acting.
- All seven agent identities pass sandbox launch-readiness; earlier real provider-backed evidence was 5/7. Owner's new planning assumption that provider credential/quota issues may be treated as resolved is NOT verification of actual model-backed acceptance.
- Additional audit found the public development endpoint's generic tool/workspace registry is wider than the delegated-agent root allowlist; direct generic actions can reach writable Obsidian, Cranary and agentporter-dev resources when authorized with the development key.
- Additional audit observed no clear global active-job admission quota in tools/jobs.py, no verified per-job cgroup CPU/memory quota, and full-file SHA-256 work before a nominal 1-MB read limit in tools/files.py.
- Earlier independent socket reproduction showed Headroom's public HTTPS relay prematurely stopped forwarding on client write-half-close; the current source had a 60-second idle cutoff. Do not assume these are repaired until tested.

## Execution sequence and exit gates

### 1. Provider-origin broker: review, activate, verify
- Reconcile any ongoing v13 work first. Inspect the exact candidate artifact/manifest and deployment launcher/hash; no unreviewed privileged installation.
- Test positive provider routing and negative cases: arbitrary public HTTPS hosts, private/link-local/loopback IPs, DNS redirection/rebinding, prohibited methods and request bodies where applicable, SNI/Host/authority mismatches, unsupported agents, credential and path escape attempts. No external exfiltration testing with real secrets; use synthetic markers.
- Install only through the reviewed authorized rollout process. Verify installed vs loaded fingerprints, no unconfined fallback, and rollback to the last known-good release.
- Do not claim this closes public MCP authorization; it only addresses restricted worker egress.

### 2. Public A7Dev ingress authorization and resource budgets (new audit work)
- Inventory which workspaces and generic tools the public A7Dev API key can actually use, separately from worker sandbox permissions and separately from internal trusted access.
- Enforce server-side least-privilege per principal/scope: public development clients must have an explicit workspace allowlist and per-operation read/write/exec/git/dispatch constraints. Sensitive workspaces (central Obsidian, broader repository umbrella, protected production checkout) need explicit denial unless individually approved. Fail closed for unmapped routes.
- Add regression tests for remote key: permitted read, denied write/exec, workspace-ID and path traversal, symlinks, mismatched workspace, direct REST and MCP, key rejection; verify that approved internal development operations still work. Distinguish a compromised authenticated key's blast radius from an unauthenticated bypass; do not claim the latter without proof.
- Add gateway-wide active-job admission limit plus bounded queue/429-or-equivalent behavior and cancellation/recovery. Establish defensible per-job CPU/memory/runtime/output budgets; use cgroups or demonstrably effective equivalent, not timeout alone. Stress with bounded synthetic jobs and verify fairness, cleanup on restart, and no runaway children.
- Move file-size validation before whole-file hashing, or switch to bounded streaming with explicit byte limits. Test large and sparse files, directories, symbolic links, and read/preview failure paths; prevent unbounded traversal and excessive I/O.

### 3. Headroom connection lifecycle (earlier audit findings)
- Fix request-forwarding behavior for write-half-closed HTTP clients: EOF on client write side must not be mistaken for response cancellation.
- Introduce a workload-appropriate bounded read/idle policy for long provider reasoning periods, preserving finite deadlines and explicit cancellation.
- Add synthetic regression tests for delayed response, full streaming, half-close, cancellation, client disconnect, upstream stall, shutdown, descriptor/resource cleanup; repeat a real allowed model-backed request.
- Keep failure injection bounded and synthetic; don't introduce general-purpose public egress as a testing convenience.

### 4. Final acceptance / freeze A7Dev release
- Run the complete suite and native Bubblewrap negative tests against the **installed** artifact, not just source or a preview; recheck all provider identities using canonical credentials where available, actual tool/skill reads, workspace rules, provenance and Headroom route. Report unavailable external provider tests as unverified rather than passed.
- Independently check public endpoint permissions and isolation as actually deployed. Exercise rollback, interrupted install, uncertain dispatch, job cancellation, restart, old-key rejection and restoration without altering A7 production.
- Produce an acceptance evidence matrix with test IDs, explicit pass/fail/waived status, residual risks, release fingerprint, manifests, hashes, and rollback instructions. No silent waivers of high-severity network/authorization failures.
- Freeze a reproducible A7Dev build and declare development closure only after the above gates pass. Then keep A7Dev for experimentation/maintenance and undertake the **separate** A7 production relay rollout against a pinned worker release.

## Working agreement
- Implementation and privileged deployment: local agent through approved controls.
- Independent review: separate ChatGPT/A7Dev auditor; do not use its implementation work as the only acceptance evidence.
- No concurrent conflicting edits, no unreviewed production change, no use of real secrets in negative tests.
- On reaching a safe checkpoint, report which of the above were already covered by the existing plan, any overlaps/conflicts, the proposed sequencing, and a concise remaining-work table. Do not rebuild infrastructure needlessly.
