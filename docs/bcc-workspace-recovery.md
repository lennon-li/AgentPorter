# BCC workspace publication recovery

This owner procedure applies to pending publication journals created by `sandbox.workspace_transactions`. Use the module from the audited immutable release. The current deployed staging release does not contain this candidate module yet.

Recovery is an offline maintenance operation. It is not exposed through MCP or REST. The CLI requires the `agentporter-bcc-worker` identity, refuses root execution, checks that `agentporter-bcc-worker.service` is inactive and its cgroup is empty, and exclusively locks the gateway supervisor and selected workspace. Stop the worker service through the owner-controlled service manager before inspection.

Run `python -I -m agentporter.sandbox.workspace_recovery` using that release's Python, under `sudo -u agentporter-bcc-worker`, with these arguments:

- `--state-dir`: the gateway's private state directory containing `jobs.db`.
- `--workspace`: the exact registered project path requiring recovery.

Without `--apply`, the module only inspects the pending publication and produces JSON. Save the output outside exposed project roots in an owner-private directory. The plan lists each relative file path, its baseline/staged/current SHA256 values, and whether it is pending, already applied, or conflicting. It also identifies the private transaction directory containing the staged files for content review. The `plan_sha256` binds the complete inspected plan.

After reviewing that plan and its staged files, repeat the same invocation with `--apply --expect-plan-sha256 HASH`, substituting the reviewed `plan_sha256`. A changed plan or any conflicting owner edit prevents application. Recovery applies pending files, leaves already-applied files untouched, writes a durable receipt under `state/recovery-receipts`, marks matching uncertain jobs `recovered`, and releases their admissions. It retains unrelated job reservations. Unbound synchronous admissions are released only after every pending publication journal has been resolved. Restart the audited worker service and verify its fingerprint and a bounded follow-up job.

If application fails, preserve the pending journal and private transaction data. Inspect again after resolving the reported cause. Do not remove journals or clear admission rows manually to bypass a refusal. This command handles pending publication journals; it does not reconstruct missing journals, restore deleted project roots, or roll back owner edits. Service release rollback continues to use the independently pinned owner deployment helper.

Repository-defined executable Git filters are refused by the trusted metadata mutation path, including filter definitions loaded from included Git configuration. A separately approved Git backend is required for those repositories; recovery does not grant Git commit or push authority.
