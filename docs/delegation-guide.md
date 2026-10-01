# Worker Delegation Guide

AgentPorter worker delegation is asynchronous. A successful `dispatch_agent` response means the worker process started; it does **not** mean the worker finished or that its final answer has been collected.

## 1. Preflight

Always call `list_agents` before dispatching substantial work.

Check:

- `available` is true;
- `effective_model` is acceptable for the task;
- the worker provider/capabilities match the work;
- `reasoning_level` is appropriate.

AgentPorter delegation policy currently prohibits GPT-5.6 variants. The
supported OpenAI delegate targets documented here are:

- `gpt-6.1-sol` for an explicit Sol delegation;
- `gpt-6-luna` for the normal OpenAI route and safe fallback.

These names are allowed delegate targets, subject to the live worker being
available and supporting model overrides. Inherited OpenAI configurations that
still name GPT-5.6 are routed to `gpt-6-luna`; explicit requests for a
prohibited model are rejected.

Treat the live `list_agents` response as authoritative for preflight. If a worker's `effective_model` is itself prohibited (for example, it still reports a GPT-5.6 variant), **do not dispatch that worker**, even if the checked-out source or documentation says the model should have been remapped. That is runtime/policy drift: repair or restart the serving AgentPorter instance, or choose another worker whose live `effective_model` is allowed.

`configured_model` may still show a stale inherited model for diagnostic purposes; the hard dispatch gate is the resolved live `effective_model`.

Prefer leaving `model` unset after checking `effective_model`. Set it explicitly only when a particular allowed model is required.

## 2. Dispatch bounded work

Keep delegated tasks bounded enough to finish within the worker timeout and the 30-step control-packet budget. Split unrelated implementation, architecture, and review work into separate agents.

For read-only reviews, say explicitly:

> READ-ONLY. Do not call write/edit tools and do not create a report file. Return the complete findings in the worker's final stdout response.

This avoids workers attempting interactive write permissions when the desired deliverable is only a review.

For implementation tasks, name the allowed files/directories and state whether commit/push is forbidden.

GitHub pushes are denied by default. A push delegation must target a writable
workspace and explicitly set `allow_push: true`; committing requires the
separate `allow_commit: true` confirmation. This only permits pushes to an
existing remote. Force-push, remote reconfiguration, branch deletion, and
other destructive remote operations remain blocked.


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
