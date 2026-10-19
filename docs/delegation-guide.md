# Worker Delegation Guide

AgentPorter worker delegation is asynchronous. A successful `dispatch_agent` response means the worker process started; it does **not** mean the worker finished or that its final answer has been collected.

## Writing within authorized workspaces

An implementation task requires both `writable: true` and
`allow_agent_dispatch: true` on its registered workspace. Use that workspace ID,
not a host path or an unrelated workspace. Private identities in `agents.yaml`
inherit their runtime's launch controls; a name or persona does not add access.
Keep personal worker names and roles in local configuration, not package code.

Writable launches use these per-invocation controls:

- Codex identities: `--sandbox workspace-write`.
- Copilot: workspace directory plus tool permissions and central command denials.
- Claude: headless `dontAsk` with explicit read/edit/write/shell tools and central
  command denials; no permission-bypass mode or global settings change.
- OpenCode: a temporary invocation-only dispatch profile permits edits, denies
  external-directory tools and central restricted command prefixes. The CLI
  version selects its v1/v2 permission schema; unknown versions fail closed.
- Antigravity: `--mode accept-edits --sandbox`. This CLI does not expose the same
  fine-grained command-denial controls; terminal operations may still require
  approval or fail. Do not represent it as equivalent enforcement to the others.

These are trusted host-user CLI workers, not AgentPorter's ordinary Bubblewrap
execution sandbox. CLI permissions and command-prefix rules are defense in
depth, not OS-level confinement or protection against arbitrary shell syntax.
Do not use delegation for untrusted tasks or to grant unrestricted host access.
Commit, push, credentials, deployment and administrative operations remain
separate from permission to edit project files. Read-only workspaces are refused
by adapters that cannot enforce read-only operation.

**Task-level safety:** Every MCP/REST `dispatch_agent` call now defaults to
`read_only: true`, even in a writable workspace. For a bounded implementation
that genuinely needs edits, the caller must explicitly set `read_only: false`;
the workspace must still permit writes and delegation. Read-only dispatch selects
the worker CLI's enforceable read-only mode, and is refused when an adapter cannot
enforce that mode. Delegated commit and push requests are **currently refused**
even when `read_only: false`, because a caller-supplied boolean is not evidence
of independent human authorization. Use owner-controlled Git publication
outside the worker until a verified approval receipt mechanism is implemented.
The response includes the effective `read_only` setting.

Codex/Jax/Liz/Prof launches use an isolated Python interpreter (`-I`) and a
sanitized environment at the initial launcher boundary, then create a temporary,
0700-protected `CODEX_HOME`
containing only model routing settings and a reference to the existing
authentication file. User MCP servers, plugins, hooks and notifications are
not copied. AgentPorter verifies the effective Codex MCP roster before starting
the worker. Only the optional Parallel Search server described below is permitted;
failed discovery or any other enabled tool blocks launch.
Project-level Codex MCP/plugin configurations block launch as well.
All Codex worker command sandboxes explicitly set
`sandbox_workspace_write.network_access=false`, overriding inherited values.
Worker environment variables are reduced to a model-auth allowlist. Selected
Codex profiles and unrecognized model-provider settings fail closed rather
than silently changing the selected account or provider.

This is configuration and command-sandbox hardening, **not host-user
isolation**. The CLI still uses host-user credentials, local files remain
readable subject to the CLI sandbox, and model API traffic necessarily uses
a network connection. Keep a7's UI permission setting on Always ask, and do
not delegate untrusted tasks or grant edit mode merely because an agent
requests it. Non-Codex worker adapters do not yet receive this temporary
profile treatment; permit only carefully scoped, approved editing with them.


After a code change, a restart alone does not update an immutable release.
Follow [deployment.md](deployment.md) for owner-controlled activation. Verify
live `list_agents`, then dispatch a bounded file-write check in the intended
workspace and collect its result before claiming remote editing works.

### Parallel Search MCP

Parallel Search is optional and disabled by default. Enable it in the operator's
AgentPorter `config.yaml` with `parallel_search: {enabled: true}`. When enabled,
dispatched Jax, Liz, Prof, Phil, and Wei receive an additive, keyless remote MCP server:
`parallel-search` at `https://search.parallel.ai/mcp`. It exposes only
`web_search` and `web_fetch`. The server is configured at dispatch time:
temporary screened Codex homes for Jax/Liz/Prof, Copilot's documented
additional-MCP file for Phil, and OpenCode's per-run configuration for Wei.
No user profile, account, model, reasoning preference, credential, or persistent
MCP setting is overwritten. Existing user MCP servers remain excluded from the
isolated Codex worker profile; only the fixed search server is added.

An unreachable or rate-limited Parallel endpoint is reported by the respective
CLI as an MCP connection/tool error. AgentPorter does not retry against a paid
provider or silently substitute another search service.

Verify search with actual MCP calls in a fresh dispatched job for each identity:
request `parallel-search` `web_search` for current CRAN policies, then
`web_fetch` of the official documentation URL. Retain tool-call events and the
job ID, including connection errors or HTTP 429 responses. Links in an answer,
`mcp list`, or successful host requests are not live tool proof. If a CLI
continues after an MCP failure, report search as unavailable.

Codex shell networking remains disabled by dispatch policy. A failed shell
`curl` probe is not equivalent to a failed remote MCP call: inspect MCP
startup/tool events separately. Compare non-secret proxy variable presence,
DNS errors, and TLS errors before changing network policy. Do not enable
unrestricted shell networking to repair MCP access. There is no paid fallback.

## 1. Preflight

An installed CLI or `available: true` is discovery evidence, not a successful
delegation. Verify the tracked job's result before declaring a worker operational.
OpenCode startup can require local HTTP connections and package downloads even
when the requested model uses a public provider endpoint. If the parent execution
sandbox rejects these connections, preserve the run ID and report the exact denied
destination. An empty user configuration and `OPENCODE_PURE=1` distinguish optional
plugin dependencies from a failure that persists in the runtime itself. Do not
diagnose an authentication or model failure when startup was blocked first, weaken
the worker's permissions, or claim another worker's success verifies Wei.

Built-in Prof (`prof`) uses `~/.codex-prof` and built-in Wei (`wei`)
uses the dedicated free-model OpenCode credential policy. Older operator
configurations may contain `prof: {runtime: codex}` and
`wei: {runtime: opencode}`. These two legacy entries are accepted
**as identity metadata only**: dispatch continues through the protected
built-in Prof/Wei adapters rather than silently weakening their account or
free-model restrictions. All other redirects of registered worker names are
rejected. To keep a separately billed OpenCode Go route, configure a distinct
identity such as `wei-go: {runtime: opencode}` explicitly in owner-controlled
`agents.yaml`, and inspect its model/provider before delegation.
Do not assume the previous `wei` alias still selects OpenCode Go.
Built-in Prof requires its own `config.toml` and `auth.json` for
availability. Omit `model` to preserve the worker's configured model;
missing values remain `unknown`, not invented.
Dispatch still enforces workspace/task read-only and publication controls.

Argie may be configured as a private `argie` identity in `agents.yaml`; the
underlying `agy` identifier remains available. AgentPorter does not reserve
`argie` globally, so existing private mappings to other runtimes remain valid.
Discovery does not establish provider authentication, entitlement, or execution.

Always call `list_agents` before dispatching substantial work.

Check:

- `available` is true;
- `effective_model` is acceptable for the task;
- the worker provider/capabilities match the work;
- `reasoning_level` is appropriate.

AgentPorter delegation policy currently prohibits GPT-5.6 variants. Inherited OpenAI configurations that still name GPT-5.6 are routed to `gpt-6-luna`. Explicit requests for a prohibited model are rejected.

Treat the live `list_agents` response as authoritative for preflight. If a worker's `effective_model` is itself prohibited (for example, it still reports a GPT-5.6 variant), **do not dispatch that worker**, even if the checked-out source or documentation says the model should have been remapped. That is runtime/policy drift: repair or restart the serving AgentPorter instance, or choose another worker whose live `effective_model` is allowed.

`configured_model` may still show a stale inherited model for diagnostic purposes; the hard dispatch gate is the resolved live `effective_model`.

Prefer leaving `model` unset after checking `effective_model`. Set it explicitly only when a particular allowed model is required.

## 2. Dispatch bounded work

Keep delegated tasks bounded enough to finish within the worker timeout and the 30-step control-packet budget. Split unrelated implementation, architecture, and review work into separate agents.

For read-only reviews, keep `read_only: true` (the default), and say explicitly:

> READ-ONLY. Do not call write/edit tools and do not create a report file. Return the complete findings in the worker's final stdout response.

A read-only prompt is **not a substitute** for the `read_only` parameter. Confirm
that the returned dispatch metadata reports `read_only: true` and that the
worker launch uses the appropriate read-only CLI sandbox. If the worker lacks
such enforcement, dispatch must fail rather than silently run with write access.

For implementation tasks, name the allowed files/directories and state whether commit/push is forbidden.


## 2A. Host orchestration contract

When AgentPorter is used under the Asgard agent-system delegation policy, the parent must also honor the host orchestration contract:

Before a host-governed dispatch, load exactly: `policies/ROUTING_QUICK_CARD.md`, `policies/DELEGATION.md`, and one matching runtime adapter. Do not load the full model catalogue unless the route actually needs current quota/model facts.

- **APPROVAL mode:** propose worker, model, reasoning effort, and bounded task before dispatch; one approval covers one procedural retry.
- **UNATTENDED mode:** announce the selected route, then dispatch without an extra approval prompt.
- Keep at most **3 concurrent workers** by default unless the active host policy explicitly authorizes more.
- Use the task profile explicitly in the packet: **implementation** (scoped writes/tests), **review** (no authored implementation; inspect/execute as needed), or **survey** (read-only synthesis).
- When project policy requires independent review, do not run delegated implementation against real/consequential project data until a different author/provider has reviewed it.
- A procedural/runtime failure gets **one repaired retry**. If the native subagent path fails again, fall back to the tracked CLI adapter. A capability failure is different: change model/provider/route instead of repeating the same worker.
- Never redispatch merely because a final message was lost. Recover by the durable `job_id` first.

These host rules supplement AgentPorter's execution policy; they do not expand worker permissions.

## 3. Preserve the job ID

`dispatch_agent` returns both `dispatch_id` and `job_id`. Treat `job_id` as the authoritative handle and retain it until the result is collected.

Do not dispatch a replacement solely because the worker has not answered yet. First inspect the existing job.

## 4. Poll status, not result

Use `job_status(job_id)` to monitor the worker.

Terminal statuses are:

- `completed`
- `failed`
- `timed_out`
- `cancelled`

`job_result` is a snapshot/result retrieval call; it does not block until the worker finishes. Calling it while status is `running` can make a partial response look like the final worker answer.

Avoid high-frequency polling. For long work, inspect occasional bounded `job_output` chunks only when useful.

## 5. Always collect the terminal result

Once `job_status` is terminal, call `job_result(job_id)` **even when the job failed or timed out**. Workers often leave useful final/partial analysis, changed files, tests, or an actionable error before a non-zero exit.

Inspect both `stdout` and `stderr`.

If `next_cursor` indicates more stdout than was returned, request the next chunk using that cursor. Do not assume the first 64 KiB contains the worker final conclusion.

After implementation jobs, inspect `git_diff`/`git_status` and named artifacts independently. Never treat worker prose as proof that edits or tests succeeded.

## 6. Recovering from failures

For `failed` or `timed_out` jobs:

1. collect `job_result`;
2. inspect partial stdout/stderr;
3. inspect the worktree for partial edits/artifacts;
4. decide whether to resume the existing work directly or delegate a narrowly scoped follow-up.

Do not blindly rerun the full task: a timed-out worker may already have produced most of the implementation.

If a worker requests interactive permission despite an autonomous read-only task, rewrite the follow-up task to forbid file writes and require the answer in final stdout.

## 7. Model provenance

Prof accepts explicit `model` and `reasoning_effort` dispatch arguments and
retains its own Codex account profile; a model override does not switch accounts.

Argie is an optional private identity. Its model and reasoning-override
capabilities depend on its configured runtime. The underlying `agy` adapter
currently rejects per-call model and reasoning overrides because their
enforcement is unverified. Inspect `list_agents` before requesting overrides.
Model availability depends on each worker's account; passing a selector is
not proof that the requested model was used.

The dispatch response records `requested_model`; terminal job status/result also records `actual_model` when the underlying CLI exposes it. `actual_model = "unknown"` means runtime model provenance could not be verified; it must not be invented from the configured route.

When model choice matters, record both requested and actual model fields in the parent review.

## Recommended orchestration pattern

1. `list_agents`
2. choose worker by capability and verify `effective_model`
3. `dispatch_agent` and save `job_id`
4. `job_status` until terminal
5. `job_result` after terminal (page with cursor if necessary)
6. inspect diffs/artifacts/tests independently
7. synthesize or dispatch a narrower follow-up if needed

This protocol is the default for AgentPorter-driven multi-agent work.
