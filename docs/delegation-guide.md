# Worker Delegation Guide

The public MCP/REST delegation interface uses the [seven named agents and action policy](agent-roster-action-policy.md). Generic runtime adapter IDs remain internal.

Worker discovery reports `available`, `delegatable` and `confinement_status`
separately. Installing a CLI does not authorize execution. Delegation requires a
verified isolated runtime, configured credentials, resource limits and admitted
workspace roots. Missing prerequisites fail closed.

AgentPorter worker delegation is asynchronous. A successful `dispatch_agent`
response means the job was accepted; it does not mean that the worker finished
or that its final answer has been collected.

## Writing within authorized workspaces

Implementation requires `writable: true` and `allow_agent_dispatch: true` on the
registered workspace, plus the client's explicit `write`, `dispatch` and
`dispatch_write` grants when a public-client policy is installed. Use the
workspace ID and relative paths. A private identity or persona cannot add scope.

Every dispatch defaults to `read_only: true`. A bounded edit task must explicitly
request `read_only: false`; the runtime independently checks whether that worker
and workspace admit writes. Read-only workspace views are enforced by kernel
mounts. Provider-specific CLI flags and command denials are additional controls,
not substitutes for that confinement.

Worker launches use screened, temporary profiles, separate credential copies,
private HOME/tmp paths, masked secret locations and bounded provider egress.
Codex account/model routing is screened without silently switching accounts.
User MCP servers, plugins, hooks and notifications do not become worker authority.
Generic command networking stays disabled. Approved shared resources are mounted
read-only and cannot grant permission to install or execute privileged tools.

Ordinary scoped fetch, pull, clone and local commit operate through exact job
bindings and controlled private Git publication. They require no phone signing.
Every agent push remains denied; the owner publishes independently. Tightening
the protected commit policy also blocks writable delegation. Caller booleans,
model output and conversational requests cannot grant missing permissions.

Keep actual credentials, routing and local orchestration rules outside this
repository. After changing code, follow [deployment.md](deployment.md) for
owner-controlled activation of an immutable release. Verify the live fingerprint,
then collect a bounded synthetic job result before claiming a deployment works.

### Parallel Search MCP

Parallel Search is optional and disabled by default. Enable it in the operator's
AgentPorter `config.yaml` with `parallel_search: {enabled: true}`. When enabled,
dispatched codex_review, codex_impl, codex_research, copilot_agent, and opencode_free receive an additive, keyless remote MCP server:
`parallel-search` at `https://search.parallel.ai/mcp`. It exposes only
`web_search` and `web_fetch`. The server is configured at dispatch time:
temporary screened Codex homes for codex_review/codex_impl/codex_research, Copilot's documented
additional-MCP file for copilot_agent, and OpenCode's per-run configuration for opencode_free.
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
the worker's permissions, or claim another worker's success verifies opencode_free.

Built-in codex_research (`codex_research`) uses `~/.codex-research` and built-in opencode_free (`opencode_free`)
uses the dedicated free-model OpenCode credential policy. Older operator
configurations may contain `codex_research: {runtime: codex}` and
`opencode_free: {runtime: opencode}`. These two legacy entries are accepted
**as identity metadata only**: dispatch continues through the protected
built-in codex_research/opencode_free adapters rather than silently weakening their account or
free-model restrictions. All other redirects of registered worker names are
rejected. To keep a separately billed OpenCode Go route, configure a distinct
identity such as `opencode_free-go: {runtime: opencode}` explicitly in owner-controlled
`agents.yaml`, and inspect its model/provider before delegation.
Do not assume the previous `opencode_free` alias still selects OpenCode Go.
Built-in codex_research requires its own `config.toml` and `auth.json` for
availability. Omit `model` to preserve the worker's configured model;
missing values remain `unknown`, not invented.
Dispatch still enforces workspace/task read-only and publication controls.

agy_agent may be configured as a private `agy_agent` identity in `agents.yaml`; the
underlying `agy` identifier remains available. AgentPorter does not reserve
`agy_agent` globally, so existing private mappings to other runtimes remain valid.
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


## 2A. Local orchestration policy

Apply any independently configured owner policy for routing, concurrency and
review. Keep those deployment rules outside the public package. They may narrow
AgentPorter's permissions but cannot expand workspace access or bypass runtime
admission. Recover an existing durable job before dispatching a replacement.

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

codex_research accepts explicit `model` and `reasoning_effort` dispatch arguments and
retains its own Codex account profile; a model override does not switch accounts.

agy_agent is an optional private identity. Its model and reasoning-override
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
