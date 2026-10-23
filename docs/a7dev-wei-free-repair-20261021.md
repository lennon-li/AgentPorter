# Wei free-default route repair — 2026-10-21

Status: **owner applied the Wei-only change; public default-model acceptance passed**. Phil is outside this repair and was not dispatched or modified. No further approval is pending for this repair.

## Public acceptance after owner application — executed locally

The owner ran the pinned `--apply` command. Its output confirms `changed=true`, provider `opencode`, model `opencode/glm-5.3-flash-free`, and no other-worker, production, or service-restart change. Exact previous-runtime backup: `/var/lib/agentporter-dev/config/development-runtime.before-wei-free-c9dc9e8caa68e555093c9399f0348f9f6732297fca2b896fa0e557c40cf7f7ee.yaml`.

`.venv/bin/python scripts/verify-a7dev-wei-free.py --execute-free-check` subsequently passed over the public MCP endpoint. The public roster exposes the free provider and default with verified development confinement. Job **`job_d067ca9669534b88ad51024c`** ran as Wei, used no caller model override (`requested_model` empty), completed with exit 0 in **11.51 seconds**, and returned README SHA256 `e31d5ff1618d4fd6d8f22e108ec0af165a2f802dc6c88cd488e2129efb2c7d97`, independently matched against the local unchanged file.

Evidence: `/tmp/a7dev-wei-free-public-hjb5uxs9/results.json` and `gateway-audit.log`. The gateway journal records Wei dispatch and the matching async-job completion at 13:01:02–13 EDT. The public result records the configured free route; its separate `actual_model` field remains `unknown`, so it is not treated as independent provider-reported model metadata or a native tool trace. The separate native compatibility test below verifies real local-tool execution.

Before/after public roster comparisons confirmed all six other workers retain the same provider, configured/default model, and executable, including Phil. A7Dev remains active at PID `4102155`, `NRestarts=0`; production remains active at unchanged PID `664960`. No service restart, production activation, dataset edit, training, commit or push occurred.

## Root cause

Interactive `wei` aliases OpenCode. The owner's actual OpenCode configuration defaults to **`opencode/glm-5.3-flash-free`**. Before this repair, the public A7Dev roster reported **`opencode-go/glm-5.3-flash`**, provider `opencode-go`. Its isolated key was copied from the canonical paid Go key. The existing credential timer reported Wei's copy `current`, so repeating credential synchronization could not correct this provider/model mismatch. The previous expired-key failure described the incorrectly selected Go route; it did not establish that interactive free Wei was broken.

Public baseline, executed locally without a model call: `/tmp/a7dev-wei-free-public-x37q53xl/results.json`. Current service executable: `/opt/agentporter-development/versions/20261021T132836.936455Z/cli/wei/opencode.exe`, **OpenCode v2.1.1**. Interactive OpenCode is v2.1.2; compatibility below was repeated against the actual installed v2.1.1 binary.

## Exact applied change

Only the Wei entry in `/var/lib/agentporter-dev/config/development-runtime.yaml` changes:

```yaml
provider: opencode
model: opencode/glm-5.3-flash-free
credentials:
  .config/opencode/wei-key: /var/lib/agentporter-dev/credentials/wei/.config/opencode/free-access
```

Create that separate `free-access` regular file, service-owned mode `0600`, containing the non-secret public placeholder `public` followed by a newline. The existing runtime requires a nonempty private provider-profile file even for this anonymous free route. The successful native compatibility check used exactly this placeholder; no paid key was supplied.

The existing paid `wei-key` file remains untouched. Its credential timer remains untouched and continues writing its old destination, which the free profile will no longer select. No canonical owner credential is changed. Every other worker entry, including Phil, is preserved. No new executable or package is installed. No production admission or strict-provider candidate is activated.

The runtime already supports an explicit `opencode/*-free` route, reads its configuration for new dispatches, and invalidates its admission cache when the config inode/mtime/size changes. **No service restart is required.** Existing in-flight jobs retain their original profiles; new Wei jobs select the free default.

## Operator action — performed by the owner

[repair-a7dev-wei-free.py](../scripts/repair-a7dev-wei-free.py) defaults to a proposal. Its `--apply` action requires the owner's terminal, pins the v12 release and installed runtime source, then uses sudo **only to switch to `agentporter-dev`**. The fixed Python payload runs as that unprivileged service account, never as root. It refuses an unexpected old/new route, unsafe files, symlinks, conflicting placeholder or backup content, and detected concurrent config edits. It saves the exact prior runtime in a private hash-named backup and atomically publishes the updated runtime. The public placeholder remains inert if a later configuration check fails.

Installer SHA256: `ea308357500a72b08aea7bdb2c0e319a661056a80c7284971b5a141c6f565fd9`.

The owner authorized and performed the protected change with this exact pinned action:

```bash
/usr/bin/python3 -I -c 'import hashlib,pathlib; p=pathlib.Path("/home/yeli/agent-work/agentporter-dev/scripts/repair-a7dev-wei-free.py"); b=p.read_bytes(); assert hashlib.sha256(b).hexdigest()=="ea308357500a72b08aea7bdb2c0e319a661056a80c7284971b5a141c6f565fd9", "Repair changed: stop"; exec(compile(b,str(p),"exec"))' --apply
```

This boundary comes from the user's infrastructure handoff: “If the authorization configuration requires privileged changes, present the exact proposed changes for human approval before applying them,” and “Do not use sudo ... without explicit authorization.” The live service-owned runtime is outside the agent's writable project. No sudo or live configuration update has been performed by the agent.

## Validation

- **Executed locally:** a synthetic read-only worker using installed v12 runtime and the exact installed v2.1.1 OpenCode binary selected `opencode/glm-5.3-flash-free`, completed a native `read` tool call, and returned the undisclosed fixture nonce. Exit 0, 4.65 seconds, no paid credential. Evidence: `/tmp/a7dev-wei-free-native-inoluxjg/summary.json` and `native-output.private`; reproducer `/tmp/verify-wei-free-native.py`. This is unprivileged client compatibility evidence, **not service-UID/public-dispatch acceptance**.
- **Unit test / executed locally:** 17 focused installer/Wei runtime tests passed, including a real Wei Bubblewrap confinement probe. Coverage includes other-worker preservation, old-key preservation, exact backup, private modes, idempotence, unsupported-route refusal, symlinks, conflicting marker, and concurrent config edits.
- **Executed locally:** operator proposal produced no writes or subprocesses; script syntax and `git diff --check` passed.
- **Executed locally:** the owner applied the protected change; the actual public gateway's default free-route dispatch passed, with matching read-only README digest, no caller model override, and correlated successful job audit events. All six other worker routes/executables remain unchanged.

Focused command:

```bash
.venv/bin/python -m pytest -q tests/security/test_a7dev_wei_free_repair.py tests/security/test_development_runtime.py -k 'wei or opencode'
```

The post-application acceptance command passed:

```bash
.venv/bin/python scripts/verify-a7dev-wei-free.py --execute-free-check
```

That verifier uses the actual public MCP endpoint, first requires the exact free provider/default and verified confinement, then submits one read-only Wei task with **no model override** and checks its returned README SHA256 against the local file. It refuses a paid/default mismatch before dispatch. It never dispatches Phil and does not edit files, restart services, or expose credentials. Private evidence is retained under `/tmp/a7dev-wei-free-public-*`.

Scope is the existing A7Dev v12 connection. No research dataset, Laya training, production gateway, commit, or push is involved. The owner's exact free default is the target; no silent fallback to another model is introduced.
