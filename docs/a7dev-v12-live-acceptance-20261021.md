# A7Dev v12 live acceptance

User-local reviewed activation completed. Authenticated deployment query:

- Release: `20261021T132836.936455Z`
- PID: `3769995`
- Loaded and disk fingerprint: `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`
- `stale=false`
- Retained rollback evidence: `.candidate-32a8c77e2ae39572aa57f417d0b40960`

Actual Argie delegation in `cranary`: `job_445ea6b1624c400185864840`, completed in 20.40 seconds using canonical CLI/model configuration. Private result: `/tmp/agentporter-v12-argie-result-20261021.json`. The prompt provided neither the skill heading nor its content. The answer returned the expected nonce, project title, exact first heading `## Mindset`, and the canonical skill's matching review check about error propagation, cleanup and resource ownership. Citations use `/workspace/README.md` and the mounted shared skill path. Parent independently matched heading and quoted check against the immutable installed snapshot. API actual-model/provider metadata remains `unknown`; do not invent those fields.

The v12 repair changes only native read permissions for the existing readonly shared snapshot. Snapshot admission digest, executable toolkit and Bubblewrap read-only mounts remain unchanged. Earlier native synthetic permission canaries and real namespace read-only checks remain separate supporting evidence, rather than assuming process exit zero proves access or immutability.

| Identity | Latest real evidence | State |
|---|---|---|
| Jax | v10 real project/tool/skill task; isolated Headroom optimization probe | Working on existing route |
| Liz | v10 `cranary` real project/tool/skill task | Working |
| Prof | v10 real delegated acceptance | Working |
| Ming | v10 real delegated acceptance | Working |
| Argie | v12 real `cranary` and canonical skill acceptance | Working |
| Wei | Canonical OpenCode Go key expired | External authentication condition |
| Phil | Copilot quota exhausted | External entitlement condition; not bypassed |

Production remains unchanged and inactive for delegation. The new provider-origin/body-capability broker is source-only, under independent review, and is not present in this running v12 release. Its receiving runtime and production relay gate must be reviewed, deployed and actually tested before production activation.
