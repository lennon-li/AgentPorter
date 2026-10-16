# SciNet diagnostics

When `scinet.broker_socket` is configured, AgentPorter uses the host-side
SciNet broker. The broker owns the Duo-authenticated SSH session and its
private transport; agents do not receive `~/.ssh` access or a control-socket
path. The legacy `control_socket` setting remains migration-only and should
not be used for new deployments.

`scinet_diagnostic` exposes four read-only operations to an explicitly opted-in
workspace. It is a host-side capability: it does not mount SSH credentials or
the control socket into the ordinary Bubblewrap sandbox.

## Security boundary

The operation is fail-closed unless the workspace has both
`allow_execute: true` and `allow_scinet_diagnostic: true` and the private
deployment endpoint is configured. It can only use that configured account,
destination, and control socket; callers cannot supply or override any of
them. Machine-specific values are not part of the reusable package or public
Action schema.

SSH always uses `BatchMode=yes`, `StrictHostKeyChecking=yes`, disables agent
forwarding and forwarding options, applies bounded timeouts, and caps output.
No Duo approval is automated and no SSH key, known-hosts file, or master socket
is changed. Arbitrary commands, options, destinations, users, port forwarding,
and job submission are not accepted.

## Operations

REST Action (with the configured Action prefix):

`POST /api/v1/workspaces/{workspace_id}/scinet/diagnostic`

```json
{"command":"gpu_partitions"}
```

The commands are:

- `connection_status`: checks the broker-owned authenticated session.
- `gpu_partitions`: reports Slurm partition capacity/state/GRES.
- `gpu_nodes`: reports node/GRES/state rows.
- `gpu_allocations`: reports Slurm jobs and requested/allocated resources.

`gpu_partitions` and `gpu_nodes` describe installed capacity and node state;
they must not be interpreted as free GPU counts. `gpu_allocations` is separate
so current allocations can be compared with capacity where Slurm exposes them.

## Deployment gate

Adding the workspace flag is a local deployment decision, not a package
default. After reviewing the target workspace, set only:

```yaml
allow_execute: true
allow_scinet_diagnostic: true
```

The private `config.yaml` must also provide the fixed deployment endpoint:

```yaml
scinet:
  host: <approved-host>
  user: <approved-user>
  broker_socket: /run/user/<uid>/agentporter/scinet.sock
  machine: <approved-local-machine>
```

Do not place credentials, private keys, or machine-specific values in the
repository or public package documentation.

The Slurm operations run through a fixed `/bin/bash -lc` login shell on the
remote host. Alliance clusters commonly add `sinfo` and `squeue` through the
login environment rather than installing them under `/usr/bin`. The shell
receives only server-side allowlisted, shell-quoted arguments; this is not an
arbitrary remote command interface.

Then restart the service and re-import the Action schema only with explicit
operator approval. A missing broker or expired authentication returns a
structured failure; it does not initiate Duo authentication.
