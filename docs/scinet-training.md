# SciNet training Actions

AgentPorter exposes a separate, fail-closed training capability for the
registered cranary workspace. Read-only scinet_diagnostic remains independent
and unchanged.

## Private deployment configuration

Do not put these values in the repository. In the private AgentPorter
configuration, set the endpoint and the dedicated experiment root:

~~~yaml
scinet:
  host: <approved-trillium-host>
  user: <approved-user>
 broker_socket: /run/user/<uid>/agentporter/scinet.sock
  machine: <asgard-hostname>
  training_remote_root: <dedicated-scratch-root>
  training_account: <approved-slurm-account>
  training_partition: <approved-gpu-partition>
  training_python: <fallback-or-preprovisioned-laya-environment-python>
  training_bootstrap_python: <absolute-python-3.12-path>
  training_cpus_per_task: 4
  # training_allow_full_runs: false   # human opt-in for laya_expA/laya_expB
  # training_full_walltime: "02:00:00"

workspaces:
  cranary:
    allow_execute: true
    allow_scinet_training: true
~~~

Training Actions stay disabled unless every value is present and the workspace
has the separate allow_scinet_training permission.

## Action sequence

- scinet_environment_check(workspace_id) runs fixed read-only checks for
  identity, Slurm visibility, configured account/partition, Python, storage,
  quota, and GPU driver visibility.
- scinet_stage(workspace_id) stages only the exporter-produced
  data-raw/cran-history/training/trillium/handoff-out files. It verifies the
  local SHA256SUMS, uses a unique remote stage ID, writes files exclusively,
  and verifies each remote SHA-256.
- scinet_setup(workspace_id, stage_id) starts (or resumes/retries, max 5
  attempts) the staged scinet_login_setup.sh on the login node. The remote
  runner re-verifies the SHA-256 of every staged file against the ledger
  before launching, derives all paths from the stage ID, pins PYTHON312 and
  CRANARY_SCRATCH, holds a lock, and runs the script detached under a
  3600 s timeout with a log in runs/<stage_id>/setup/. Calling it again
  while running or after success is a no-op that reports status. Each call is
  a short (<100 s) broker request, so the broker's fixed 120 s envelope is
  not a limit. It requires an already-authenticated session; otherwise it
  fails closed with scinet_auth_required and a human must do the interactive
  Duo login on Asgard. AgentPorter never automates Duo.
- scinet_setup_status(workspace_id, stage_id) reports not_started / running /
  complete / failed / interrupted plus a bounded (8 KiB) log tail.
- scinet_preflight(workspace_id, stage_id, experiment) is read-only. It runs
  the experiment's gates, reports each exit code/output, shows which *_by
  approval fields in pins.json are recorded (flagging agent-like names) and
  the pins.json SHA-256. ready is true only if all gates pass and every
  required approval is recorded.
- scinet_record_approvals (REST: `/scinet/setup` with `action: record_approvals`,
  which keeps the API at 30 operations) records the five laya_smoke approvals
  (head_contract_reviewed_by, compute_approved_by, gpu_allocation_approved_by,
  experiment_b_approved_by, smoke_approved_by) plus `device: cuda` in the
  stage's pins.json. Fail-closed requirements: the exact text
  `I approve all 5` as `confirmation`, `reviewer` equal to the authorized
  reviewer (`AGENTPORTER_SCINET_APPROVAL_REVIEWER`, default = the broker's
  SciNet `user`; agent-like names are rejected), `approved_fields` listing
  exactly those five, and a stage created by the calling workspace. Only
  laya_smoke is supported; no paths or commands are accepted. On SciNet a
  fixed script takes an exclusive lock, refuses null-only exceptions (any
  existing non-null value differing from the request, including device,
  aborts with no change), updates atomically (temp file + fsync + rename),
  is idempotent (re-run reports `unchanged`, no write), and appends
  time/reviewer/stage/before+after SHA-256 to `pinned/approvals.audit.jsonl`
  and the stage ledger. Gates and preflight are unchanged; run scinet_preflight
  afterwards. **Limitation:** the confirmation is caller-supplied text, so
  AgentPorter cannot cryptographically prove a human typed it; it relies on
  the operator invoking it only after the user's explicit statement. A caller
  with workspace training permission could spoof it. Stronger evidence (e.g. a
  human-held signed grant) is not implemented. Manual pins.json editing
  remains available.
- Each staged run creates its environment at
  `<training_remote_root>/runs/<stage_id>/envs/laya-expA/bin/python`.
  Submission derives that path from the recorded stage; the setup command
  pins `PYTHON312` to `training_bootstrap_python`.
- scinet_submit(workspace_id, stage_id, experiment=laya_smoke) runs the pinned
  gates, then submits the fixed one-GPU template for that experiment. Smoke is
  15 minutes. laya_expA / laya_expB are refused unless the private config
  sets training_allow_full_runs: true; walltime comes only from
  training_full_walltime (HH:MM:SS, under 24 h, default 02:00:00), the staged
  template hash must match, nodes/GPU are exactly 1, and a stage can submit
  each full experiment only once. Published sbatch names embed the script hash
  so retries are idempotent.
- scinet_job_status(workspace_id, job_id) accepts only job IDs recorded from
  scinet_submit and queries only the configured user.
- scinet_job_logs(workspace_id, job_id, kind) returns bounded metadata/content
  for stdout, stderr, metrics, manifests, or checkpoint inventory under the
  recorded experiment root.

No Action accepts a remote path, shell command, Slurm option, arbitrary file
list, SSH option, hostname, username, credential, or Duo code. The SSH control
socket must already be authenticated; missing or expired masters fail closed.

## Required deployment sequence

1. Run scinet_environment_check and verify the returned account, partition,
   Python, scratch, and GPU information.
2. Run scinet_stage.
3. A human completes the Duo login (broker control master), then call
   scinet_setup and poll scinet_setup_status until complete.
4. Run scinet_preflight; a human reviews pins.json and the gates, then either
   edits the approvals themselves or explicitly states "I approve all 5" so
   scinet_record_approvals can record them under their identity.
5. Re-run scinet_preflight until ready, then scinet_submit laya_smoke; full
   A/B only after private opt-in.
6. Monitor with scinet_job_status and retrieve bounded results with
   scinet_job_logs.

AgentPorter does not submit a job during tests or deployment validation.


## REST consolidation

To stay within the 30-operation Actions limit, setup, setup status, preflight
and the environment check share one operation, POST .../scinet/setup with
action in start|status|preflight|environment_check (the standalone
/environment-check route was folded into it). MCP tools remain separate.

## Standalone Laya inference

The `standalone-inference` package is a separate `laya_inference` experiment. It runs the fixed `convaiinnovations/laya` protocol (`laya==0.3.28`, revision `7b928d828b7b0e022f929d9bd2e44165aa270148`, checkpoint SHA-256 `891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c`) over 42 frozen development cases. It does not use A/B training approvals or the A/B stage path.

The fixed v2 bundle is read from the registered Cranary workspace at `data-raw/cran-history/training/trillium/standalone-inference/package-v2`. The manifest SHA256 is `d0032d8a9bb6fc3580b2e1d9118bc5ca6f99defd6bfdfdf641a3e59fc02a91c7`; the template SHA256 is `5d41bf4b5b533e8147ba7c6a38e31fc4ef19bbe1d2d4f8c17f3d15d870e2b79f`. The v1 package and pins are rejected. An optional `scinet.inference_manifest_sha256` may repeat the code pin, never replace it. Verification requires exactly 60 files including the manifest (42 contexts and 17 static files), matching hashes, single-link regular files, no symlinks, a 2 MiB per-file limit and 32 MiB total limit. The allowlist includes `runtime_preflight.py`, `prepare_runtime.sh`, `requirements-inference.lock`, and `evaluate_return.py`; staging these files does not authorize provisioning or evaluation.

MCP exposes `scinet_inference_preflight`, `scinet_inference_stage`, `scinet_inference_approve`, and `scinet_inference_submit`. REST uses `POST /workspaces/{workspace_id}/scinet/setup` with the corresponding `inference_*` actions. Existing `allow_execute` and `allow_scinet_training` permissions are required. Action callers cannot supply a catalog path, digest, interpreter, command, cache, or destination. Local preflight checks only bundle integrity and reports remote readiness unverified and submission disabled in that report.

Private configuration must supply `scinet.inference_scratch_root`, `scinet.inference_python`, `scinet.inference_hf_cache`, **`scinet.inference_runtime_catalog_sha256`**, and the reviewed `training_account`/`training_partition`. Each has the corresponding `AGENTPORTER_SCINET_*` environment setting. The interpreter environment and materialized offline checkpoint cache must already exist beneath the scratch root, separately from stages and job outputs. The catalog path is fixed to `<inference_scratch_root>/runtime-catalog.json`. Its SHA256 must come from independent human review; an adjacent checksum or candidate catalog is insufficient. Missing or invalid configuration fails closed. AgentPorter never installs packages, invokes `prepare_runtime.sh`, downloads weights, or generates/approves a runtime catalog.

Stage copies only the verified package into `<scratch>/stages/<generated-stage-id>` and records the manifest, runtime catalog path/digest, interpreter, cache, destination, account, and partition in the private inference ledger. IDs contain 32 hexadecimal characters and start with a letter for bridge v2 compatibility. Existing v1 stage records cannot be reused. Approval requires an Ed25519 signature bound to the stage ID, v2 manifest SHA-256, runtime catalog SHA-256, scratch destination, account, partition, **1 H100 / 00:30:00**, configured reviewer identity, fixed v2 approval domain, fresh single-use nonce, workspace ID and resolved path, SSH host/user, inference Python and HF cache paths, template SHA-256, and integer `issued_at` / `not_after` timestamps. The challenge expires after one hour; approval and submission both check its validity, including after remote preflight immediately before allocation. Expired or old-format challenges require staging again. The stage response provides canonical payload bytes as base64 and the payload digest; it does not provide a reusable confirmation phrase. `scinet_inference_approve` requires the exact configured reviewer and a base64 64-byte signature. AgentPorter verifies the signature when recording approval and again at submit against the immutable challenge and current runtime configuration. Approval cannot be replayed across stages or used after runtime configuration changes.

Configure only `scinet.inference_approval_reviewer` (or `AGENTPORTER_SCINET_INFERENCE_APPROVAL_REVIEWER`). There is no SSH-user fallback for the reviewer. The reviewer string identifies the intended signer; the separate trusted signer must validate human authority and intent. Its string alone grants no authority.

The verifier key is fixed at **`/etc/agentporter/laya-inference-approval.pub`**. YAML and environment public-key settings are ignored and cannot override its path or contents. Inference staging, approval, and submission fail closed if it is absent or unsafe. AgentPorter never creates it, invokes sudo, or falls back to a workspace key. Both file and parent must be root-owned, non-symlinks, and have no group/other write bits. The file must be regular with one link. The verifier compares `lstat`/`fstat` identity and permissions around `O_NOFOLLOW` opens and reads at most 46 bytes. Accepted contents are exactly 32 raw Ed25519 public-key bytes, or their canonical standard base64 encoding (44 ASCII bytes, optionally followed by one LF). PEM, SSH public keys, whitespace, and noncanonical base64 are rejected.

Generate the private key **on a separate trusted signing machine, off Asgard**, using a protected directory that already exists. These commands are for the human signer; do not run them in AgentPorter's workspace or on Asgard:

```bash
umask 077
openssl genpkey -algorithm ED25519 -out /secure/offline/reviewer-ed25519.pem
openssl pkey -in /secure/offline/reviewer-ed25519.pem -pubout -outform DER -out /secure/offline/reviewer-ed25519.pub.der
python3 - <<'PYKEY' > /secure/offline/laya-inference-approval.pub
import base64
from pathlib import Path
spki = Path('/secure/offline/reviewer-ed25519.pub.der').read_bytes()
# Exact RFC 8410 Ed25519 SubjectPublicKeyInfo prefix plus 32 public bytes.
assert len(spki) == 44 and spki[:12] == bytes.fromhex('302a300506032b6570032100')
print(base64.b64encode(spki[12:]).decode('ascii'))
PYKEY
```

Transfer **only the public file** through a human-reviewed channel and verify its fingerprint independently. A human root operator on Asgard installs that reviewed public file from a trusted transfer location, outside all agent workflows:

```bash
install -d -o root -g root -m 0755 /etc/agentporter
install -o root -g root -m 0644 /human-reviewed-transfer/laya-inference-approval.pub /etc/agentporter/laya-inference-approval.pub
```

Never place a private signing key in the repository, production configuration, environment, workspace, or anywhere on Asgard. For each approval, the human signer independently inspects every field of the returned challenge, including workspace, destination, SSH endpoint, runtime/template digests, nonce, resources, and validity times. On the separate trusted signing machine, decode `approval_payload_base64` into `approval.payload` and sign the **exact canonical UTF-8 JSON bytes including the final LF**:

```bash
printf '%s' '<copied-base64-payload>' | base64 --decode > approval.payload
openssl pkeyutl -sign -rawin -inkey /secure/offline/reviewer-ed25519.pem -in approval.payload -out approval.sig
base64 -w0 approval.sig
```

Return the base64 64-byte raw Ed25519 signature and configured reviewer identity to the authenticated client for `inference_approve`. Do **not** use `ssh-keygen -Y sign`: its SSHSIG envelope/domain is incompatible with this raw Ed25519 protocol. Reject any payload that differs from the human's intent; the signer must not automatically sign challenges merely because an agent supplies the configured reviewer name.

The key-file gate prevents another unprivileged process sharing the `yeli` account from substituting an approval key through writable config or env. It assumes trusted root administration of `/etc` and its parent chain, a trusted clock, protected service code/interpreter and process, and an independently controlled signer. It does not protect an agent-writable service installation, process injection, root compromise, or tampering with other files under the service's own OS identity. Deploy AgentPorter's verifier code and launch environment under separate operator control if same-account hostile code is in scope; a fixed public key alone cannot make arbitrary modified verifier code trustworthy.

Submit rechecks local fingerprints, approval and resource limits, and reserves the stage before remote contact. A fixed read-only remote preflight runs through the pre-provisioned interpreter with `-I -B`, verifies all 60 staged files, and checks the independently pinned runtime catalog, full checkpoint/cache inventory and hashes, locked installed versions, Python 3.12, Torch CUDA build, and the Laya import/loader seam. It embeds verified local preflight/provenance code, disables network access and filesystem mutations through Python audit checks, and does not load weights, discover a GPU, install anything, or allocate resources. Missing catalog/cache/runtime, failure, timeout, truncation, or an invalid receipt prevents `sbatch`. The environment prefix, catalog, cache, and scratch must resolve under private owned scratch. These are trusted-code checks, not an OS sandbox against hostile native code or another process using the same identity.

Only after preflight succeeds does submit use the fixed rendered template through `sbatch --wrap`. It exports the five original inference settings plus `CRANARY_INFERENCE_STAGE_ID`, `CRANARY_INFERENCE_RUNTIME_CATALOG`, and `CRANARY_INFERENCE_RUNTIME_SHA256`, with a fixed PATH. It uses an explicit export list; [Slurm forbids combining `NONE` with explicit environment variables](https://slurm.schedmd.com/sbatch.html#OPT_export). No resume inputs are accepted. The job independently rechecks bundle and runtime bytes, scratch/cache/log isolation, pinned checkpoint provenance, and one visible H100 before inference. The hard cap remains one H100 / 30 minutes, with the template's 25-minute inference budget and two-minute reserve. Account, partition, H100 syntax and CPU count still require operator verification. Pre-submit checks do not establish compute-node compatibility. Failed/ambiguous submissions and even failed reserved preflights cannot replay; stage a new ID for retry. This favors duplicate-allocation prevention over automatic retries.

**Trusted retrieval is available after a submitted job completes.** `scinet_inference_results` is exposed through MCP and the REST `inference_results` action. It accepts only a numeric job ID recorded by `scinet_inference_submit` in AgentPorter's protected ledger for the same workspace, then resolves the linked stage, pinned v2 manifest, runtime catalog digest, and fixed `$scratch/runs/<job_id>/results` location. It retrieves only the fixed 42-case JSON allowlist over the configured authenticated SSH session and requires `sacct` to report `COMPLETED`, `ExitCode=0:0`, and exactly one typed H100 allocation. The identical normalization snippet runs remotely and locally: exactly one `gres/gpu:h100=1` or `gres/gpu:nvidia_h100_80gb_hbm3=1` resource is required, `gres/gpu` must equal 1 when present, and `node` must equal 1 when present. Mixed types, duplicate resources, two GPUs, generic GPU-only records, and missing or ambiguous type evidence fail closed; no A100 or other generic GPU fallback is used. It rejects missing or extra cases, unsafe files, invalid canonical JSON, mismatched per-piece digests, and case/model/stage/runtime mismatches. AgentPorter computes a canonical Cranary-compatible receipt and digest locally from the verified bytes, and returns the per-file bytes as bounded base64 so a caller can materialize the exact source directory for Cranary evaluation. The standard-library-only reader runs through fixed `/usr/bin/python3 -I -B`, independently of the job-writable inference venv. Its exact source SHA-256 is pinned in service code and checked before transport; no remote reader upload/download is performed. SSH output and API response are capped at 256 KiB.

### Inference results return path

The dedicated `inference_results` transport independently pins the reviewed reader's SHA-256 in the broker and validates the exact `/usr/bin/python3 -I -B -c` argv plus four arguments: scratch path, recorded numeric Slurm job ID, stage ID, and 42 unique fixed-format case IDs. The application resolves the recorded job and case inventory from its ledger and pinned manifest. Both broker and migration fallback reject stdin and use `exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/timeout 60s ...` without an added login shell. The reader calls only absolute `/usr/bin/sacct` for accounting and fails closed if it is absent; this path must exist on the real cluster. Training and diagnostic login environments remain unchanged. SSH still relies on sshd's account shell, which may execute startup files before the command; the remote account, shell startup, system binaries, and accounting service remain trusted. This is not a full sandbox.

The signed stage approval context includes validated `bootstrap_python` from `training_bootstrap_python`, alongside the inference interpreter and cache. Approval and both submit checks reject configuration drift, including a bootstrap change during remote preflight.

The read-only `scinet_inference_results(workspace_id, job_id)` MCP tool and `inference_results` action on consolidated `/scinet/setup` accept only numeric job IDs recorded by `scinet_inference_submit` in AgentPorter's protected ledger for the same workspace. They resolve the associated stage, pinned v2 manifest, runtime catalog digest, and fixed expected `$scratch/runs/<job_id>/results` location.

AgentPorter does not accept a remote-generated receipt or a self-declared result checksum as trust input. The local receipt binds the stage ID, pinned manifest, runtime catalog, H100 allocation, original protocols, Slurm job ID, and SHA-256 of every returned result file. This bridge trusts the configured SSH identity and session, Slurm accounting records, and remote sandbox/filesystem; it is not cryptographic proof that the model executed on a GPU. The receipt digest records the bytes AgentPorter authenticated and checked, not an independently signed GPU attestation.
