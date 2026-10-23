# A7Dev v10 live acceptance — 2026-10-20

Status: v10 activation verified; provider acceptance incomplete. Production
relay remains inactive. No production writes/restart, credential changes,
commits or pushes occurred in this acceptance pass.

## Service proof — executed locally

Operator executed scripts/run-approved-a7dev-v10.py successfully. Rollback
evidence: `.candidate-6d40b2791ef30d19eb47751f88cc0bc3`.

Parent verified the current symlink and authenticated deploy-info identify
release `20261021T020503.171884Z`; installed, loaded and disk fingerprints match
`38ead25120fc363fde47b363d34e3d8bea364283a3b3d3ebb594e051a426c5ea`, stale=false.
Systemd reports active, PID3421685, NRestarts0. Health HTTP200 healthy.
Inventory HTTP200: all seven available/delegatable with verified_development_bwrap.
First inventory16.942s; later warm inventory0.522s. Unauthenticated inventory401.

Production authenticated deploy-info remains PID664960, start2026-10-19T21:21:28-0400,
release65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8 and loaded/disk fingerprint
`8de423283d3db8938a226719650a6c3b8fb325c534154992636bb6c51bf490a8`, stale=false.
Production was only read during this pass.

## Provider acceptance — actual jobs

Each request used existing configured account/model defaults, read_only=true,
allow_commit=false, allow_push=false. Intent was durably recorded before each
request. At most three jobs were outstanding. No implementation was delegated
through AgentPorter. Local evidence: `/tmp/agentporter-v10-acceptance/`.

| Agent | Job | Result |
| --- | --- | --- |
| Prof | job_2a84224ae0fa4178a942c7d6 | Executed locally: completed exit0; model-backed workspace/skills/tool check passed. |
| Ming | job_dd92a8b453d44c469a6339eb | Executed locally: completed exit0; model-backed workspace/skills/tool check passed. |
| Liz | job_0bb430d48473490d85e1225a | Blocked: canonical OpenAI account usage limit before model/tool output. |
| Wei | job_7a44ca884c134e43bffccc7c | Blocked: OpenCode Go reports API key expired; signing in again does not renew it. No Vertex fallback. |
| Argie | job_31e516c3d03c4994b99e2385 | NOT verified despite exit0: headless command permission denied, no output. |
| Argie survey retry | job_1f38351d48e14831815f60ad | NOT verified despite exit0: native read_file permission denied, no output. No further retry. |
| Jax | Earlier job_fd15717555d6429c87f2c1dd | Earlier canonical Headroom usage-limit failure; not retried. Headroom optimization NOT verified. |
| Phil | No new dispatch | Previously recorded external Copilot quota exhaustion; not retried. Current reset/entitlement NOT verified. |

Prof/Ming each ran inside /workspace and returned a README SHA256 matching the
parent's actual source file. Both read the installed shared skill index with
SHA256 `a6cbcaac285278c4f12ea2f15ab0489312fda512da40dd6775197682adefce59`;
reported os.access(index,W_OK)=false. All38required commands resolved on PATH.
They actually executed rg --version, git --version, Rscript -e 'cat(1+1)' and
quarto --version with exit0; R returned2 and a missing D-Bus/bspm warning.
This proves four command executions, not all38executions per provider. Earlier
38-tool offline namespace functionality evidence remains separately scoped.
Gateway actual_model/provider metadata for these jobs is unknown; Prof's CLI
transcript identifies gpt-6.1-sol/OpenAI/low. No inferred actual-model claims
are made for Ming or Argie.

Prof/Ming succeeded on agentporter-dev. Cranary jobs were attempted with Liz,
Wei and Argie but none yielded accepted workspace evidence, so the two-project
model-backed acceptance gate remains NOT verified.

## Argie repair specification — awaiting worker approval

Current disposable-home generation in DevelopmentRuntime._build writes only
model to .gemini/antigravity-cli/settings.json. Native read_file therefore
requires interactive approval, which headless mode denies. Existing model-only
regression coverage does not establish useful survey execution.

Prepare a narrowly scoped read-only native file permission policy for the exact
/workspace and approved immutable shared-doc paths, using the installed CLI's
verified rule grammar. Preserve survey-only role: no command, write, network,
credential/config-home access, hooks, MCP imports or unrestricted skip flags.
Add positive and negative regression coverage and verify policy against the
installed CLI before any provider retry. Preserve existing identity, model and
kernel namespace/mount boundaries. No live settings/deployment change is
approved by this note. A bounded local worker approval was requested under
AgentSystem/agent-memory/policies/DELEGATION.md; the parent must verify results.

Security and production activation gates remain tracked in
production-relay-security-review-20261020.md and production-relay-activation-gates.md.
Do not call production ready from a healthy gateway or delegatable inventory.
