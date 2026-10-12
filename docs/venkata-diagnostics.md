# BCC Venkata Diagnostics

`venkata_diagnostic` provides fixed, read-only SSH diagnostics on Venkata through
BCC's normal `yeli` identity. General sandbox execution is unchanged. Existing
gateway authentication, rate limiting and workspace authorization still apply.

## Deployment Approval Required

The implementation is disabled by default. After human approval, add
`allow_venkata_ssh: true` to only the intended workspace in BCC's existing
AgentPorter workspace registry. That workspace must also have
`allow_execute: true`. Automatically discovered projects do not inherit this
host-access permission. Restart AgentPorter, then reimport Agent7's BCC Action
schema from `https://c3ck0nff-8765.use.devtunnels.ms/openapi.json`.

No sudo, remote installation, authentication changes or sandbox SSH mounts are
required. The service must run as `yeli` on BCC. Keep the existing `venkata` SSH
alias, credentials and known-host verification in their existing host locations.

## Operator Switch

On BCC, run `venkata-access on`, `venkata-access off`, or `venkata-access status`.
The installed operator command is `~/.local/bin/venkata-access`. No service
restart is needed when switching. Agent7 cannot toggle this through the Action.
The gate is checked on every request using an owner-controlled marker at
`~/.config/agentporter/venkata-access.enabled`; missing, symlinked, or insecure
markers deny access. Workspace opt-in is still required when the switch is ON.
OFF rejects new requests; a diagnostic already running may finish within its
fixed timeout. Re-enabling requires the local operator command.

## Action Calls

BCC operation: `bcc_venkata_diagnostic`

REST: `POST /api/v1/workspaces/{workspace_id}/venkata/diagnostic`

MCP: `venkata_diagnostic(workspace_id, command, args)`

For the explicitly opted-in workspace (for example `m3`):

```json
{"workspace_id": "m3", "command": "hostname", "args": []}
```

Expected stdout: `phl-hpcdl-011`.

```json
{
  "workspace_id": "m3",
  "command": "nvidia-smi",
  "args": [
    "--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,driver_version",
    "--format=csv,noheader"
  ]
}
```

The REST body contains only `command` and `args`; the workspace is in the URL.
Other commands: `nproc`, `free` (fixed `-h`), `df` (fixed `-h`), `cuda_version`
(fixed `/usr/local/cuda/bin/nvcc --version`) and `torch_status` (fixed isolated
system-Python version/CUDA availability check). These accept no arguments.
PyTorch results describe system Python, not a Conda environment; report stderr
warnings as well as stdout.

## Controls

- Only `venkata` is reachable; no caller-supplied host, user, path or shell text.
- NVIDIA queries allow only enumerated fields, fixed CSV formats and optional
  numeric `--id=0,1`. Mutation, loop and arbitrary flags are rejected.
- Strict host-key checking and batch authentication; agent and port forwarding
  are disabled. SSH uses host identity files without copying them.
- Fixed 30-second local timeout and 25-second remote timeout; combined stdout
  and stderr are capped at 64 KiB. Timeout/overflow kills the local process group.
- Results include exit code, stdout, stderr, timeout and truncation status.

The reported sandbox UID error was reproduced by inspection: the generated
sandbox passwd file lacks BCC's current UID. AgentPorter creates that file only
when absent, so a stale file can persist across identity changes. Even repairing
the UID record would not authorize host SSH credentials inside the sandbox.
This operation provides a separate opt-in boundary rather than broadening it.
