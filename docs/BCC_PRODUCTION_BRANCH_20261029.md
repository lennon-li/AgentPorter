# BCC production preservation branch — 2026-10-29

Branch: `production/bcc-20261029`.

This branch preserves the BCC working source, related tests and deployment tooling from the October 29 production session. Its parent is BCC's existing checkout revision `8dec760`; it deliberately does not merge or replace upstream main `e7184e4` or the Asgard installation. It is a preservation and review branch, not a claim of completed common-version integration or full acceptance.

The original working checkout remains on its existing branch with its local changes. The publication was assembled in an isolated worktree. Inherited development/Asgard helper scripts are retained because the accumulated source and regression suite reference them; their presence does not instruct anyone to run them on Asgard.

## Installed BCC environment

- Installed release: `/opt/agentporter-bcc/releases/bcc-stage-20261029-19`.
- Release fingerprint: `96812fbaf766cfb4a121f47efd61091fdc86b47895fc9416abcde5f00ff6852c`.
- System gateway: `agentporter-bcc-gateway.service`, enabled at boot.
- Worker: `agentporter-bcc-worker.service`, started through gateway dependency.
- Workspace views: `agentporter-bcc-project-views.service`.
- User production tunnel: `agentporter-openai-tunnel.service`, with user lingering enabled.
- Former user gateway: `agentporter.service`, disabled/inactive at cutover.
- Gateway/worker limits: 8 GiB memory, 400% CPU, 512 tasks and NoNewPrivileges.
- Required behavior: local commits allowed in authorized writable repositories without phone approval; agent pushes denied.

`deploy/bcc/release19/` preserves the reviewed cutover, policy, projection, updater and gateway-service source. Its manifest hashes the published files. The public gateway URL is replaced with an example, so this directory is a sanitized deployment reference and its manifest is not the original live-bundle manifest. No privileged apply launcher is included. The scripts retain BCC-specific IDs, release paths and state-journal assumptions; review those and generate a newly pinned installer before reuse. Do not replay a historical cutover against the running system.

Credentials, OAuth/provider caches, local configuration, databases, journals, release virtual environments, binaries and privilege grants are excluded. Tunnel URLs in newly copied text are replaced with an example. Recovering an environment also requires separately provisioned host configuration and credentials; cloning this branch alone does not recreate them.

The installed release's 94 Python source files were hashed and compared with BCC's working source: all 94 matched. `deploy/bcc/release19/installed-package-manifest.json` records those hashes. This establishes the Python package identity, not the identity of host configuration, binaries or dependencies.

Two test dependencies on ignored private/local artifacts were removed for publication: cutover tests load the published release19 source, and fixture-enrollment tests use synthetic policy documents. CI includes `production/**` branches. No live runtime code or configuration was changed by these publication adjustments.

## Acceptance and future alignment

Publication checks executed locally: all 94 installed Python hashes match the published source, and 45 focused tests passed across workspace projections, production relay, published cutover tooling and synthetic fixture enrollment. Secret-scan findings were reviewed: detected values were file hashes and synthetic test constants; the added example-policy directory had no findings. The broader regression suite is reported separately below and must not be inferred green from the focused checks.

Final broad run (`pytest -q tests/unit tests/security tests/integration --tb=short`): **2,625 passed, 29 failed, 23 skipped, 24 subtests passed** in 119.86 seconds, using `/tmp/agentporter-review-tests-venv/bin/python`. Failures include the host `/usr/bin/bwrap` rejecting `--disable-userns`, a provisioning test expecting a worktree-local `.venv`, and BCC projection tests requiring a source under `/home/yeli/repos` rather than this `/tmp` worktree. These failures were not repaired by changing the live host or weakening confinement. This branch is a preserved production source snapshot with explicit verification limits, not a green integration candidate. The full local log is `/tmp/agentporter-bcc-branch-tests-final.log` and is transient evidence.

Cutover evidence exercised fourteen worker workspace probes, native shell and REST commits without a phone receipt, push denial, gateway workspace probes and seven-worker inventory. Inventory does not establish actual execution through every provider. Independent audit, phone flow, all seven real providers and an actual Qman job were not all verified. See `bcc-production-acceptance.md` for the frozen acceptance contract.

Recommended integration: start from current upstream main in a separate worktree, retain BCC's sealed installation and Git semantics, reconcile Asgard's centralized workspace policy and newer features, then deploy one tested source version with host-specific configuration. Validate BCC first and repeat acceptance on Asgard. Publishing this branch does not authorize or perform that merge or deployment.

Detailed comparison: Obsidian `AgentSystem/agent-memory/projects/agentporter/BCC_ASGARD_ALIGNMENT_20261029.md`.
