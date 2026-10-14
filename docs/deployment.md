# Deploying AgentPorter on Asgard (human-controlled releases)

## Security decision (2026-10-14 audit)

An independent audit rated the earlier proposal CRITICAL. That proposal used an
agent-writable trigger file, `agentporter-activate.path`, which started a
oneshot unit running `~/repos/AgentPorter/scripts/agentporter-activate`. The
problem was that an agent with workspace write access could edit that script,
`tests/conftest.py`, or the repo `.venv` `.pth` files. It could then trigger
unsandboxed host code as the service user, with access to `~/.ssh` and the
SciNet broker socket.

**Decision: all automated or agent-triggerable activation has been removed
entirely.** The `.path`/`.service` activation units and
`scripts/agentporter-activate` are deleted. AgentPorter has no endpoint,
watcher, timer, or socket that restarts or deploys it. A deployment only
happens when a human runs a trusted script from a terminal. Autonomous
deployment is **not** supported, because the current security model does not
allow it safely. `agentporter-deploy` refuses to run while any
`agentporter*.path` unit exists.

## How code becomes live

Python loads modules once per process, so a source edit is served only after a
restart. The gateway runs an **immutable release** rather than the repo
checkout:

```
~/.local/share/agentporter/
  mirror.git/              private bare mirror (our own git config, no hooks)
  releases/<40-hex-sha>/   src/ (git archive of that commit), venv/ (non-editable), RELEASE.json
  current -> releases/<sha>    previous -> releases/<sha>
```

`examples/agentporter.service` runs
`%h/.local/share/agentporter/current/venv/bin/python -I -m agentporter.cli serve`.
The `-I` flag plus `UnsetEnvironment=PYTHONPATH ...` means that no `PYTHONPATH`,
user site-packages, or current directory can inject code. Because the release
is not an editable install, files in the agent-writable working tree, its
`.venv`, and its `.pth` files are never imported by the gateway.

## Read-only verification

- `server_deploy_info` (MCP) and `GET /api/v1/server/deploy-info` (API key
  required; not in the public allowlist or in the GPT Actions schema) report
  `pid`, `started_at`, `package_path`, module paths, `loaded_fingerprint`,
  `disk_fingerprint`, and `stale`. The fingerprint is a SHA-256 over **every**
  package file except `__pycache__`/`*.pyc`. Symlinks are recorded rather than
  followed.
- `agentporter deploy-check [--expect-fingerprint FP] [--expect-path DIR]
  [--expect-pid PID] [--wait SECS]` is strictly read-only (one HTTP GET). It
  prints `ACTIVE` (exit 0), or `STALE`, `MISMATCH` (wrong package copy, or the
  port is served by a PID other than systemd's `MainPID`, which means a
  duplicate server), or `UNVERIFIED` (exit 1).
- `agentporter-deploy status` is the read-only summary of the active release.

Agents may call `server_deploy_info`. They must not report a fix as deployed
until a human has deployed the commit and the live fingerprint matches its
`RELEASE.json`.

## One-time human setup (owner, from a terminal, not via an agent)

1. Review `scripts/agentporter-deploy` at a commit you trust, then install a
   read-only copy outside every workspace:
   ```bash
   cd ~/repos/AgentPorter && git show <reviewed-sha>:scripts/agentporter-deploy > /tmp/apd.$$
   install -d -m 0755 ~/.local/libexec/agentporter
   install -m 0555 /tmp/apd.$$ ~/.local/libexec/agentporter/agentporter-deploy && rm /tmp/apd.$$
   chmod 0555 ~/.local/libexec/agentporter
   ```
   The script refuses to deploy if its file or directory is writable, or if it
   lives under `~/repos`.
2. Make sure that no activation trigger exists. The old units were never
   installed on Asgard, but check anyway:
   ```bash
   systemctl --user list-unit-files 'agentporter*'     # expect no *.path entries
   ```
3. Point the unit at releases. This changes ExecStart away from the repo `.venv`.
   Do not restart yet: the deploy in step 4 performs the single restart.
   First back up the currently installed unit; it is the only rollback for a
   failed first deploy. Diff it against the example and carry over any
   `Environment=`/`EnvironmentFile=` lines (e.g. `AGENTPORTER_CONFIG_DIR`).
   `deploy-check` runs from your terminal environment, so the service must use
   the default config/secrets location, and it must listen on
   `127.0.0.1:8765` (override with `AGENTPORTER_URL=...` when deploying).
   ```bash
   cp -p ~/.config/systemd/user/agentporter.service ~/.config/systemd/user/agentporter.service.pre-release.bak
   diff ~/.config/systemd/user/agentporter.service.pre-release.bak ~/repos/AgentPorter/examples/agentporter.service
   cp ~/repos/AgentPorter/examples/agentporter.service ~/.config/systemd/user/agentporter.service
   systemctl --user daemon-reload
   ```
4. Deploy a reviewed, pushed or committed commit by its **full SHA**:
   ```bash
   ~/.local/libexec/agentporter/agentporter-deploy deploy <40-hex-sha>
   ```
   The first deploy has no `previous` release to roll back to. If it fails
   (exit 1), restore the backed-up unit, then reload and restart:
   ```bash
   cp -p ~/.config/systemd/user/agentporter.service.pre-release.bak ~/.config/systemd/user/agentporter.service
   systemctl --user daemon-reload && systemctl --user restart agentporter.service
   ```
   Do not use `git show HEAD:examples/agentporter.service`: once this change
   is committed, that file is the new release unit, not the old one. Also,
   `current` still points at the failed release, so the next deploy records it
   as `previous`. Do not use `rollback` until a verified deploy has happened.

## Per-release deployment (owner)

```bash
git -C ~/repos/AgentPorter log --oneline -5           # pick and review the commit
~/.local/libexec/agentporter/agentporter-deploy deploy <40-hex-sha> [--skip-tests] [--wait 60]
~/.local/libexec/agentporter/agentporter-deploy rollback      # back to `previous`
~/.local/libexec/agentporter/agentporter-deploy status        # read-only
```

The `deploy` command does the following:

1. It sanitizes the environment: fixed `PATH`; unset `PYTHONPATH`/`PYTHONHOME`/
   `LD_PRELOAD`/`GIT_*`; no global or system git config.
2. It refuses to run from a writable or in-workspace location.
3. It takes a lock in `$XDG_RUNTIME_DIR`, which must be owned by you with mode
   0700. There is **no /tmp fallback**.
4. It refuses if any `agentporter*.path` unit exists, or if
   `agentporter.service` ExecStart does not run `current/venv/bin/python`
   (config drift, e.g. back to the repo `.venv`).
5. It accepts only a full 40-hex SHA, never a branch name. It fetches the
   commit into the private mirror and `git archive`s that commit. The
   working tree is never read.
6. It builds `venv/` with `uv sync --frozen --no-editable --extra dev`. It
   refuses any `.pth` file that executes code or points outside the release.
7. It fingerprints the installed package with a trusted standalone hasher
   (`/usr/bin/python3 -I`, not the release's own code).
8. It runs the commit's own `tests/unit` inside the release using `python -I`,
   then seals the release read-only. If the package fingerprint changed during
   the tests, it refuses.
9. It swaps `current` atomically (`previous` keeps the old target).
10. It restarts **only** `agentporter.service`. The SciNet broker is never
    restarted, so the Duo session survives.
11. It verifies the result with `deploy-check` against the unit's fixed
    `http://127.0.0.1:8765` (`AGENTPORTER_URL` overrides it): fingerprint, package path, and
    the live PID equal to systemd `MainPID`. On failure it switches back to
    `previous`, restarts, and verifies again.

Exit codes: 0 verified, 1 verification failed (rolled back if possible),
2 refused, 3 another run in progress.

## Restrictions and residual risks

- Running `deploy` executes the chosen commit's build backend and unit tests
  on the host as you. Review the commit diff, including `tests/` and
  `pyproject.toml`, before deploying it.
- `uv` (`~/bin/uv`, `~/.local/bin/uv`) and `~/.local/libexec` are user-writable
  paths. The agent workspace APIs cannot reach them. However, any agent that has
  an unrestricted shell as `yeli` can already do anything `yeli` can. This
  design removes the agent-reachable trigger; it is not a sandbox for
  shell-capable agents.
- `agentporter-scinet-broker.service` still runs from the repo `.venv`, which
  agents can write. It is deliberately left untouched to avoid dropping the
  SciNet session. Moving it onto releases is a separate, owner-scheduled change.
  Until then, treat any broker restart (including a host reboot) as running the
  current working tree.
- Until the one-time setup is done, `agentporter.service` still runs the
  editable repo `.venv`.
