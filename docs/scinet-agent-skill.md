# SciNet agent skill

This is the agent-facing contract for SciNet access through AgentPorter. It is
usable by delegated workers and GPT Actions without exposing SSH credentials,
the user's home directory, or an SSH control socket.

## Transport

Agents call the registered AgentPorter tools only:

- `scinet_diagnostic(workspace_id, command)`
- `scinet_environment_check(workspace_id)`
- `scinet_stage(workspace_id)`
- `scinet_submit(workspace_id, stage_id, experiment="laya_smoke")`
- `scinet_job_status(workspace_id, job_id)`
- `scinet_job_logs(workspace_id, job_id, kind)`

The AgentPorter service talks to a same-user host-side broker over a Unix
socket. The broker owns the authenticated SciNet session and uses fixed
destination, host-key, timeout, and forwarding policy. Agents must never call
`ssh`, `scp`, `sftp`, or the broker socket directly, and must not request
arbitrary remote commands or paths.

## Authentication

Use the consolidated `scinet_setup` Action with `action: "login_start"` to
request a fixed SciNet login using an existing host public key when required,
followed by keyboard-interactive authentication. The broker does not provision
keys or accept credentials from agents. Password authentication and agent
forwarding remain disabled. The host broker sends only
the literal push-selection response at SciNet's Duo-choice prompt; it cannot
approve the push, enter a passcode, or accept caller-supplied SSH options. The
operator must approve the notification on their phone. Poll with
`action: "login_status"`; `authenticated` is returned only after the SSH master
is verified. Requests are single-flight and rate-limited. If the broker reports
a stale socket or failed login, stop and ask the operator to resolve it; do not
retry-loop. Never paste passwords, private keys, or Duo codes into an agent
conversation.

## Training workflow

1. Run `scinet_environment_check` and confirm the account, partition, Python,
   storage, and GPU driver.
2. Stage the exporter-produced handoff with `scinet_stage`.
3. Run the returned setup command through the broker and verify its checksum,
   pinned environment, model, and approval gates.
4. Submit only `laya_smoke`; it is bounded to one H100 and 15 minutes.
5. Poll `scinet_job_status` and retrieve only bounded approved outputs with
   `scinet_job_logs`.

Do not infer free GPUs from `sinfo` capacity alone, submit Experiment B
automatically, or use this capability to inspect unrelated jobs.
