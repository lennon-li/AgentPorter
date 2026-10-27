# AgentPorter 1.0 — BCC Production Acceptance Contract

**Status:** Frozen acceptance criteria (not yet tested). **Target:** BCC only. **Owner:** single user.

## Objective and stopping rule

AgentPorter is production-ready when an independent local auditor operating **outside AgentPorter** verifies every mandatory criterion below against the **running BCC deployment**, with reproducible evidence. The auditor must report PASS, FAIL, or NOT VERIFIED for each criterion; only PASS counts. When all criteria PASS, record the audited release identifier and begin a **30-day feature freeze** so the owner can return to scientific research.

Do not add criteria during the audit. New ideas and nonblocking findings belong in the backlog. A demonstrated critical/high-severity security vulnerability affecting this workflow remains blocking.

## Fixed acceptance tests

### AP-01 — Phone-to-BCC control path
From ChatGPT on the owner's phone, connect to BCC, enumerate configured agents, submit a bounded job, poll its status, and retrieve its result without manually operating a BCC terminal. Record task IDs, timestamps, and results.

### AP-02 — Seven-agent delegation
Individually delegate a small, bounded task to **Jax, Liz, Prof, Phil, Wei, Ming, and Argie** via ChatGPT. For each, verify the actual agent identity, workspace scope, successful execution, and returned evidence. Every agent must be delegatable; not every agent must support every Git operation. No silent agent/model substitution.

### AP-03 — Authorized repository workflow
In a disposable test repository, demonstrate read, fetch/pull where authorized, feature-branch creation, scoped edit, test execution, diff review, and commit. Demonstrate push only through the independently authorized publication mechanism. Sensitive actions must fail closed when approval is absent. Do not weaken authorization to make the test pass.

### AP-04 — Real scientific workflow
Complete one bounded, genuine Qman development task from ChatGPT through BCC, including relevant tests, diff review, and a verifiable result, without manual SSH or terminal steps in the normal task flow. Avoid unreviewed changes to Qman main.

### AP-05 — Security boundary negative tests
From an unprivileged/delegated task, verify denial of (a) access to unrelated workspaces and secrets, (b) writes in read-only mode, (c) unauthorized commit/push or equivalent shell/CLI bypass, (d) alteration of the running AgentPorter service, protected authorization policy, deployment mechanism, or approval issuer, and (e) agent-triggered deployment/restart. Verify consistent denials through exposed MCP and REST paths where applicable, and capture sanitized audit evidence. Test actual OS/process boundaries, not just absence of exposed tool names. Do not run destructive tests against production data; use safe fixtures. Any exploitable critical/high-severity failure blocks acceptance.

### AP-06 — Failure, recovery, and release parity
Deliberately fail or cancel a bounded test job. Verify accurate status, retained logs, no unintended writes/credentials exposure, and a clean subsequent job. Verify owner-controlled deployment/rollback procedure using a safe test or staging release; independently compare live process/package fingerprint with the audited immutable release. Do not claim live parity based solely on source checkout.

## Independent audit protocol

- The auditor runs locally outside AgentPorter, with separately controlled credentials and read-only inspection wherever feasible.
- Before execution, record the test plan, target BCC host, target commit/release SHA, exact commands/requests, expected outcomes, and evidence locations. Freeze the acceptance criteria; test implementation may be corrected only to fix invalid tests, with documented rationale.
- For each AP-01 through AP-06: record PASS, FAIL, or NOT VERIFIED, reproducible steps, actual observations, and sanitized evidence references.
- The auditor must not certify its own fixes. Development fixes are made separately; the auditor retests affected criteria.
- A finding that cannot be verified is **NOT VERIFIED**, not PASS. Nonblocking low/medium-risk hardening ideas go to backlog, provided no credible escalation to a blocking risk is demonstrated.
- Produce a signed or otherwise owner-attributable report identifying tested commit/release, auditor environment, date, all six verdicts, unresolved blocking findings, and the overall verdict.
- **Overall PASS** requires six PASS verdicts, all seven agent subtests PASS, and no unresolved critical/high security issue affecting the tested workflow.

## Freeze policy

On overall PASS, record the acceptance date and release SHA. For the next 30 calendar days, allow only demonstrated security vulnerabilities, production-breaking defects, and reproducible blockers to the established scientific workflow. Defer new agents, machine integrations, model-routing redesigns, speculative optimizations, and general architectural work. No moving the goalposts mid-audit.

**Out of scope for 1.0:** Asgard, Mac Studio, enterprise multi-user features, and perfecting every capability of every agent.

**Success is an evidence-backed operational verdict, not the absence of possible improvements.**
