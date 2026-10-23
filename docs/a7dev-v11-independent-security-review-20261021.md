# Independent A7Dev v11 security review — 2026-10-21

Scope: local, unprivileged independent review of candidate v11 (`20261021T032623.535287Z`), archive expected SHA256 `cb3cca21086baefb8e811fff6b6a2a7c86d1f93e7177ae8c12f87f0e0ea0b68d`, and launcher SHA256 `610846cff654ebacf81d357c06ee25a0adbbcb38fc1f6f4485247a1df719751f`. No provider calls, privileged commands, service changes, or AgentPorter delegation were performed. This is not production clearance.

Decision: **hold v11 activation for mission acceptance**. The generated Argie policy has a functional gap, and native permission enforcement needs adversarial execution evidence. Neither a generated policy assertion nor a successful inventory establishes credential confidentiality during tool execution.

## Findings

1. **Acceptance blocker: actual canonical skills cannot be read.** Argie allows `/workspace` and exactly four approved shared documents. The canonical skill index can be read, but the task-specific skill files and Toolbox resources it references cannot. The mission requires accessible canonical skills for every worker. Smallest proposed revision: allow `read_file(/opt/agentporter/shared/obsidian)` for the already vetted immutable public snapshot, retain its exact admitted-file manifest and existing command/write/URL/MCP/auth-directory denies. Do not expand the snapshot to private vault content.

2. **Security evidence gap: traversal and symlink handling unproven.** The policy denies direct reads under `/home/worker/.gemini/antigravity-cli`, `.config`, and `.local/share`. It allows workspace paths. The installed Antigravity executable is a stripped Go ELF, and the reviewed repository tests assert policy JSON; these do not establish whether the native permission matcher canonicalizes `..` and symlinks before choosing an allow rule. Test synthetic credentials with traversal, repeated separators, absolute/relative aliases, and workspace symlinks targeting the credential directory, including symlinks to individual files. Also test an allowed shared document followed by traversal. No real credential content should be requested or returned. Until actual native tool behavior is established, do not claim this finding resolved.

3. **Publication restrictions remain layered.** Argie's new policy denies command, file write, URL access/execution, and MCP tools. These rules are application controls, not an independent network boundary. Existing namespace/relay enforcement remains necessary; this candidate supplies no new proof that provider-facing access cannot publish arbitrary content. Production's separately reported public-egress blocker remains outside this clearance.

## Privileged launcher and artifact handling

The reviewed launcher pins the installed artifact helper, expected archive digest, exact v10 base, and exact v11 candidate; uses a nonblocking lock on the root-owned installation directory; checks private data ownership/mode and ACLs; stops A7Dev; installs through the existing helper; then probes seven workers as the service UID before restart. Its failure path selects newly created rollback evidence only when it matches the exact previous runtime digest and release/candidate pair. Production is not the service target.

The artifact helper source copies a bounded, nonblocking-opened regular input into root-private staging, then hashes that frozen copy before extraction. Thus the launcher's earlier path digest check is not the final source-substitution boundary. Mutable repository Python is not executed as root by this launcher. The installed helper itself could not be read by this unprivileged reviewer; its runtime digest admission must still be enforced by the launcher. These observations do not authorize a different archive, helper, or launcher.

## Independent verification

- Launcher SHA256 independently matched the value above.
- `.venv/bin/pytest -q tests/security/test_development_runtime.py -k 'not real' tests/security/test_development_artifact.py`: **97 passed, 12 deselected**. Log: `/tmp/v11-security-focused.log`.
- Complete runtime security file: **54 passed, 10 failed** because this review environment cannot create the Bubblewrap network namespace (`Failed create NETLINK_ROUTE socket: Operation not permitted`). Log: `/tmp/v11-security-runtime-test.log`. These are an environment limitation, not successful isolation evidence.
- Parent's reported complete source gate was not represented as independently rerun here.

Required before acceptance: revise canonical skill accessibility, independently verify the new frozen candidate, and run native synthetic credential-escape and publication restrictions tests in the actual installed confinement. Model-backed task success remains a separate acceptance requirement for provider-ready agents.
