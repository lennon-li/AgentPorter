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
  exactly those five, and a stage created by the calling workspace.
  `experiment: laya_expA` is also supported: it records only
  head_contract_reviewed_by, compute_approved_by and gpu_allocation_approved_by
  (plus `device: cuda`) and requires the exact confirmation
  `I approve laya_expA on 1 H100 GPU for at most 01:00:00`. The approved
  limits (1 GPU, H100, max 01:00:00) are stored in the stage ledger;
  scinet_preflight then reports `resource_limits` and is not ready, and
  scinet_submit refuses laya_expA, if the configured training_full_walltime
  exceeds 01:00:00. It does not enable full runs (training_allow_full_runs is
  still required) and writes none of the smoke/expB-only fields.
  `experiment: laya_expB` records only experiment_b_approved_by (plus
  `device: cuda`) and requires a **separate, stage-bound** confirmation that
  embeds the exact 32-hex stage id:
  `I approve laya_expB for stage <stage_id> on 1 H100 GPU for at most 01:00:00`.
  For the current B stage that is exactly
  `I approve laya_expB for stage 9879564934e94665b71d8947ef74d896 on 1 H100 GPU for at most 01:00:00`.
  The A and smoke confirmations never satisfy it, and a confirmation for one
  stage is refused on any other. The ledger entry stores reviewer, stage_id,
  confirmation and limits (1 GPU, H100, max 01:00:00). laya_expB is fail-closed
  on that ledger entry: scinet_preflight reports `ledgered_approval` and is not
  ready, and scinet_submit refuses laya_expB before any remote call, unless an
  untampered entry for this exact stage exists and (preflight) the pins.json
  approver equals its reviewer. A pins.json value alone (for example
  experiment_b_approved_by written by the smoke approval or by hand) does not
  authorize a full B run through AgentPorter. The same 01:00:00 walltime cap,
  training_allow_full_runs opt-in and once-per-stage rule apply. Only the human
  may state the B confirmation; agents must never supply it on their own. No
  paths or commands are accepted. On SciNet a
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
  template hash must match, nodes/GPU are exactly 1, the template must contain
  exactly one `#SBATCH --time=@WALLTIME_HH_MM_SS@` and no other Slurm time
  directive (the placeholder may recur outside `#SBATCH` lines, e.g. a soft
  trainer budget, and receives the same walltime), and a stage can submit
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
   scinet_record_approvals can record them under their identity. laya_expB
   needs its own later statement of the stage-bound B confirmation above.
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
