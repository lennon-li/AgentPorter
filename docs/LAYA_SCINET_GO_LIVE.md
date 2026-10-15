# Laya SciNet inference: go-live runbook

Owner: Lennon. Prepared by Ming (Claude Opus 5.5, `claude-opus-5-5`) on Asgard, 2026-10-15.

**Historical pre-release inventory**: statuses in §1 were recorded before the security patch was published; the Asgard public key was subsequently installed and host-verified root:root 0644. Re-check release, service and runtime facts against the actual environment before following the execution sequence.
Scope: one `laya_inference` run, 42 frozen development cases, 1x H100, 30 minutes or less.
Never use the legacy `laya_expA` / `laya_expB` experiments for this run.

## 1. Verified state (2026-10-15)

| Item | Verified value | Status |
|---|---|---|
| Cranary published branch | `feat/laya-scinet-inference-20261014` = `58f8122` | Pushed. Not in Cranary `main`. |
| Cranary bundle on disk | `~/repos/cranary/data-raw/cran-history/training/trillium/standalone-inference/package-v2` | 60 files. All byte-identical to `58f8122`. Untracked in the dirty `main` checkout. |
| Manifest SHA-256 | `d0032d8a9bb6fc3580b2e1d9118bc5ca6f99defd6bfdfdf641a3e59fc02a91c7` | Disk = `58f8122` = code pin (`scinet_inference.py:43`). |
| Model | `convaiinnovations/laya`, `laya==0.3.28`, revision `7b928d82…0148`, weights `891102d3…d86c` | Pinned in manifest and code. |
| AgentPorter published branch | `feat/laya-scinet-inference-20261014` = `12f3134` | Parent `429c474`. Not in `main`. |
| Hardening worktree | `.audit-laya-inference`, branch `fix/laya-inference-approval-audit-20261014` at `12f3134` | 12 modified files and 1 new test file. **Uncommitted** (+871/-132). Contains the Ed25519 approval, results transport and catalog binding. |
| AgentPorter `main` | `682e31e` (`721bd4a` verified release deploy, `aef6f54`, `682e31e`) | Diverged from the Laya branch at `429c474`. |
| Live service release | `~/.local/share/agentporter/current -> releases/682e31e…` | **Contains no inference code.** |
| Trust key | `/etc/agentporter/laya-inference-approval.pub` | **Installed and independently verified after this inventory was recorded:** root:root, 0644, 32-byte decoded public key. Private signing key remains on Knowhere. |
| Merge `main` + `12f3134` | `git merge-tree` | **1 conflict:** `src/agentporter/rest/routers/scinet.py` (`confirmation` `max_length` 128 vs 2048). |
| Tests (worktree source, `PYTHONPATH=src`) | 401 passed, 1 failed, 24 subtests | The failure is `test_venkata_transfer.py::test_atomic_publish_race_does_not_clobber`. It also fails on `main`. A later targeted security regression run by Ming reported 268 passed; deployment still runs its own unit gate. It is environmental and unrelated to Laya. (Liz reported 261 passed / 2 skipped. That count does not match this run.) |

Worktree note: `.audit-laya-inference/.git` points to `/workspace/.git/worktrees/...` (container path). On the host, use
`GIT_DIR=~/repos/AgentPorter/.git/worktrees/-audit-laya-inference GIT_COMMON_DIR=~/repos/AgentPorter/.git GIT_WORK_TREE=~/repos/AgentPorter/.audit-laya-inference git ...`.

## 2. Tools: actual vs hypothetical

| Capability | Reality today |
|---|---|
| `scinet_setup` / `scinet_stage` / `scinet_submit` (MCP + REST) | Live in release `682e31e`. Training (`laya_smoke`) only. They cannot stage or submit inference. |
| `scinet_inference_preflight/stage/approve/submit/results` (MCP) and `inference_*` actions on `POST /workspaces/{id}/scinet/setup` | Code exists only in the uncommitted worktree. **Not deployed.** |
| GPT Actions bridge (`docs/agent7-asgard-actions.openapi.json`) | Has no `inference_*` actions or `signature` field. The live bridge **cannot** call the new typed actions until the schema is regenerated and re-imported. |
| Fresh GPU approval | No tool or prior approval grants it. Only a new Ed25519 signature over a new stage challenge grants it. |
| SciNet runtime provisioning (wheelhouse, HF cache, catalog) | No AgentPorter tool exists, by design. Owner runs it manually on SciNet. |
| Job tracking | `scinet_job_status` / `scinet_job_logs` (existing). |
| Cranary evaluation | `code/evaluate_return.py` in the bundle (local, no GPU). |

## 3. Owner-only actions (in order; no agent may do these)

**O1. Signing key.** On a separate trusted machine (not Asgard), generate the Ed25519 key. Use the commands in `docs/scinet-training.md` § Standalone Laya inference. Then, as root on Asgard:

```bash
install -d -o root -g root -m 0755 /etc/agentporter
install -o root -g root -m 0644 /human-reviewed-transfer/laya-inference-approval.pub /etc/agentporter/laya-inference-approval.pub
```

Check: the file has 44 base64 characters plus an optional LF. It is root-owned with mode 0644. The private key never touches Asgard.

**O2. Trusted code release.** Authorize commit, merge and push. Then deploy the resulting SHA:

```bash
# a) commit the hardening worktree (env from §1 note)
git add -A && git commit -m "Harden Laya inference approval, results transport, and catalog binding"
# b) integrate with main on a new branch
git switch -c feat/laya-inference-release main && git merge fix/laya-inference-approval-audit-20261014
#    resolve scinet.py:42 -> keep `max_length=128` (inference_approve rejects `confirmation`;
#    training already validates <=128), then:
uv run pytest -q          # expect only the known venkata_transfer failure
# c) review, push, merge to main (human), then:
~/.local/libexec/agentporter/agentporter-deploy deploy <40-hex-merged-sha>
agentporter deploy-check --expect-path ~/.local/share/agentporter/releases/<sha>   # expect ACTIVE
```

Also regenerate and re-import the Actions OpenAPI schema if ChatGPT will drive the run. Otherwise drive the run through MCP.

**O3. SciNet runtime.** Do this on a SciNet login node, under private scratch `S` with mode 0700. Download the wheels listed in `code/requirements-inference.lock` into `S/wheelhouse`. Snapshot `convaiinnovations/laya@7b928d82…` into `S/hf-cache`. Then:

```bash
python3.12 -I -B code/runtime_preflight.py --hf-cache S/hf-cache --wheelhouse S/wheelhouse --candidate-out S/runtime-catalog.json
# HUMAN reviews the candidate catalog, then: sha256sum S/runtime-catalog.json  -> CAT_SHA
bash code/prepare_runtime.sh S /path/to/python3.12 S/wheelhouse S/hf-cache S/runtime-catalog.json CAT_SHA
```

Set the following in the private service config (not the repo), then restart through the trusted deploy path:
`scinet.inference_scratch_root=S`, `inference_python=<S venv python>`, `inference_hf_cache=S/hf-cache`, `inference_runtime_catalog_sha256=CAT_SHA`, `inference_approval_reviewer=<signer id>`, plus reviewed `training_account` / `training_partition` / `training_bootstrap_python`.

## 4. Execution sequence (after O1-O3)

| # | Actor | Action | Pass check |
|---|---|---|---|
| 1 | Agent | `scinet_inference_preflight(ws)` | Bundle verified; manifest `d0032d8a…` |
| 2 | Agent | `scinet_inference_stage(ws)` | Returns 32-hex `stage_id`, `approval_payload_base64`, `payload_sha256`, `not_after` |
| 3 | Agent → **Lennon** | Show the full decoded challenge. **Ask for intent: "Approve stage `<id>`: 1x H100, 00:30:00, account/partition X/Y, catalog CAT_SHA?"** | Explicit yes |
| 4 | **Lennon (offline)** | `base64 --decode` → `openssl pkeyutl -sign -rawin` → `base64 -w0` | 88-char signature, within 1 h |
| 5 | Agent | `scinet_inference_approve(ws, stage_id, reviewer, signature)` | Signature verified |
| 6 | Agent | `scinet_inference_submit(ws, stage_id)` | Remote read-only preflight passes; numeric job ID. Failure means re-stage; no replay. |
| 7 | Agent | `scinet_job_status` / `scinet_job_logs` | `COMPLETED`, `0:0` |
| 8 | Agent | `scinet_inference_results(ws, job_id)` | 42 files, one typed H100, local receipt and digest |
| 9 | Agent | Materialize the files, then run `python3 -I code/evaluate_return.py --bundle … --sha256 d0032d8a… --results … --receipt … --receipt-sha256 … --stage-id … --out …` | Development metrics. Compare against the CPU baseline of 7/42. |

## 5. Blockers

- **P0 (deploy):** the code is uncommitted and not in a trusted release. Live `682e31e` has no inference path. Fixed by O2.
- **P0 (trust):** owner has completed O1; public key now installed and independently verified. Continue requiring verification at run time; never relax the signed approval gate.
- **P0 (runtime):** no reviewed catalog or checkpoint cache exists on scratch. Remote preflight blocks `sbatch`. Fixed by O3.
- **P1 (bridge):** the Actions schema lacks the `inference_*` actions. Fix by regenerating it in O2, or use MCP.
- **P2:** one trivial merge conflict (resolution given in O2). The `venkata_transfer` test failure is pre-existing and unrelated.

No code defect blocking launch was found in the hardening diff.
