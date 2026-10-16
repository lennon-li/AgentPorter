# Asgard SciNet Action Readiness

The expected existing Duo master socket was absent when checked:
`/home/yeli/.ssh/cm-yeli@trillium-gpu.alliancecan.ca:22`.
`ssh -S <socket> -O check` returned `No such file or directory`.
No new Duo login, compute job, or authentication change was attempted.
No GPU inventory or availability count has been verified.

An existing uncommitted implementation already provided configuration,
workspace permission, MCP registration and a REST diagnostic route. That work
was preserved. This review changed only `src/agentporter/tools/scinet.py` and
`tests/unit/test_scinet.py`, adding:

- `ProxyCommand=/bin/false` so an expired control socket cannot fall back to
  a fresh network connection;
- fixed control settings and disabled user authentication mechanisms; no new
  master, Duo approval, agent forwarding or arbitrary SSH options are exposed;
- sanitized failure output, plus tests for fallback denial and secret redaction.

The 12 focused SciNet tests pass. A full-suite run encountered an unrelated
transfer fixture made group writable by the default umask. A private-umask
rerun preserves the existing transfer security policy without changing code.

## Deployment Still Requires Approval

The running Asgard Action schema did not expose `asgard_scinet_diagnostic`.
The registered `cranary` workspace did not have an explicit SciNet grant.
No service restart or active configuration change was performed.

After the human restores or identifies the authenticated master, verify its
status before changing the deployment. With explicit operator authorization:

1. Back up the non-secret configuration and workspace registry.
2. Configure only the approved SciNet host/account/socket and Asgard machine.
3. Grant only `cranary` the `allow_scinet_diagnostic: true` capability, with
   `allow_execute: true`.
4. Restart `agentporter.service`.
5. Reimport Agent7's existing Asgard Action schema, preserving authentication.
6. Call the actual authenticated Action, not just local SSH or a mocked app.

The intended Action invocation is:

```json
{"workspace_id":"cranary","command":"connection_status"}
```

Other enum values are `gpu_partitions`, `gpu_nodes`, and `gpu_allocations`.
The fixed sinfo/squeue executable paths must be verified on the live login host.
Partition/node GRES describes installed capacity, not free GPUs. The current
allocation query reports job resources; do not infer an exact free GPU count
without reliable allocation records and correct shared-resource accounting.

Live end-to-end acceptance, node/GPU counts and Agent7 access remain unverified
until the master is restored and deployment and authenticated Action testing
are completed. No commit or push is authorized by this handoff.
