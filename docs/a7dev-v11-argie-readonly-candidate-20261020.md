# A7Dev v11 Argie read-only candidate — 2026-10-20

Status: candidate prepared; operator activation and post-activation Argie survey
are pending. Production remains unchanged.

The candidate carries forward the v10 broker and development runtime sources,
then adds the narrowly scoped Antigravity CLI file-read policy for Argie's
survey role. The policy allows reads from `/workspace` and four approved
immutable shared documents; it denies commands, writes, URL access, MCP, and
reads from credential/configuration directories. The existing bwrap boundary
and worker identity remain in place.

The frozen v8 archive was extracted and verified against its release manifest,
then the v11 archive was extracted and verified again. Only these release
entries differ from v8: `src/agentporter/agents/broker.py`,
`src/agentporter/agents/development.py`, `venv/pyvenv.cfg`, and
`venv/lib/python3.13/site-packages/agentporter_development.pth`. The first
three source/path changes preserve accepted v10 behavior; no payload was
executed during packaging. Candidate version: `20261021T032623.535287Z`.

The full offline development verification passed 1,248 tests and 24 subtests;
the runtime security test file passed 64 tests, including both absent and
present shared-snapshot policy cases. Argie's native CLI permission rules were
also checked against the installed CLI's static permission listing. Provider
execution under the new policy has not yet been verified.

Candidate archive: `/tmp/agentporter-development-candidate-v11.tgz`

SHA256: `cb3cca21086baefb8e811fff6b6a2a7c86d1f93e7177ae8c12f87f0e0ea0b68d`

The pinned launcher checks this exact digest and requires the current release
to be v10. It records the exact prior release/runtime pair for rollback and
checks all seven confined workers before restarting A7Dev. To activate from
the Asgard shell, run:

```sh
python3 -I /home/yeli/agent-work/agentporter-dev/scripts/run-approved-a7dev-v11.py
```

After activation, run exactly one Argie read-only survey in Cranary and verify
its returned evidence against the actual workspace and shared skill index.
Do not count the earlier Argie permission-denied attempts as provider
acceptance. No production activation, credential change, commit, or push is
part of this candidate.
