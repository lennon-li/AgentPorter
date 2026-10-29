#!/usr/bin/env bash
# Run as operator on Asgard. Only this pinned A7Dev candidate and workspace scope.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

artifact=/tmp/a7dev-shared-access-active-runtime.tgz
artifact_sha=3f35441c59a392c6ca940915309fe26511eb17adfe09ba8a1b1674f95202c78d
gate_source=scripts/verify-a7dev-runtime-install-gate.py
gate_dir=/opt/agentporter-development/activation-tools
gate="$gate_dir/runtime-install-gate.py"
gate_sha=9d57de9d99ea9b6e619a5542a92fecda52a4e0e0f7ab778d9272bf5380099c92
old=/opt/agentporter-development/versions/20261022T015212.581522Z
new=/opt/agentporter-development/versions/20261022T165047.488565Z
installer=/usr/local/libexec/agentporter/install-development-artifact.py
installer_sha=84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58
storage_sha=e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0
unit=agentporter-development.service
expected_runtime_sha=e11cb3ef478c2f95349862fea9769cc5d86f3878e5fdb181857b4624718cb77d
stopped_by_launcher=0
install_started=0

activation_failed() {
  local code=$?
  trap - ERR
  set +e
  echo 'Activation failed; no failed gate will be bypassed.' >&2
  if [[ "$stopped_by_launcher" == 1 && "$install_started" == 0 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] &&
      sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
        --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha" >/dev/null; then
    if sudo /usr/bin/systemctl start "$unit"; then
      echo 'Original A7Dev release restarted; installer was never invoked.' >&2
    else
      echo 'Original release restart failed; inspect development service logs.' >&2
    fi
  elif [[ "$stopped_by_launcher" == 1 ]]; then
    echo 'A7Dev remains stopped: inspect runtime and recorded installer rollback evidence.' >&2
  fi
  exit "$code"
}

# Lifecycle tests may source the recovery function without activating anything.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
trap activation_failed ERR
[[ $(id -un) == operator ]] || { echo 'Run as operator, not root.' >&2; exit 1; }
[[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] || {
  echo 'Development release changed; rebuild/review before activating.' >&2; exit 1;
}
[[ ! -e "$new" ]] || { echo 'Candidate already installed; inspect state before retrying.' >&2; exit 1; }
printf '%s  %s\n' "$artifact_sha" "$artifact" "$gate_sha" "$gate_source" \
  "$storage_sha" "$old/operator-plan/authorize-a7dev-project-delegation.py" | sha256sum --check

sudo -v
printf '%s  %s\n' "$installer_sha" "$installer" | sudo /usr/bin/sha256sum --check
# The service helper executes only after its installed root-owned copy is pinned.
# /usr/local/libexec is root-private on Asgard. Keep it private and use a
# development-only root-owned location traversable by the service account.
sudo /usr/bin/install -d -o root -g root -m 0755 "$gate_dir"
sudo /usr/bin/install -o root -g root -m 0555 "$gate_source" "$gate"
printf '%s  %s\n' "$gate_sha" "$gate" | sudo /usr/bin/sha256sum --check
# Verify the final installed path as its actual consumer before stopping A7Dev.
sudo -u agentporter-dev /usr/bin/python3 -I -B -c \
  "import hashlib; from pathlib import Path; p=Path('$gate'); assert hashlib.sha256(p.read_bytes()).hexdigest() == '$gate_sha', 'Service-account gate access/hash mismatch'"
# Catch archived-runtime drift BEFORE any service shutdown, then repeat after
# quiescing to reject configuration changes between preflight and installation.
sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
  --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha"
# Check the real worker's writable-mount safety rules too. In particular,
# package-manager hardlinks must not expose a shared cache to workspace writes.
sudo -u agentporter-dev "$old/venv/bin/python" -I -B -c \
  'from pathlib import Path; from agentporter.agents.development import DevelopmentRuntime; runtime=object.__new__(DevelopmentRuntime); runtime._masks(Path("/home/operator/agent-work/agentporter-dev"), True); print("Writable-workspace confinement preflight passed")'

# Refuse to interrupt active work. These are metadata-only, read-only queries.
sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import sqlite3
with sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro", uri=True, timeout=2) as db:
    db.execute("PRAGMA query_only=ON")
    assert db.execute("SELECT count(*) FROM jobs WHERE status IN (\x27running\x27,\x27cancelling\x27,\x27queued\x27,\x27cleanup_failed\x27)").fetchone()[0] == 0, "Wait for A7Dev jobs before activation"
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type=\x27table\x27")}
    assert "job_admissions" not in tables or db.execute("SELECT count(*) FROM job_admissions").fetchone()[0] == 0, "Unresolved A7Dev admissions"
'
sudo /usr/bin/systemctl stop "$unit"
stopped_by_launcher=1
# Repeat stopped/cgroup/jobs admission after stopping, before any installation.
sudo -u agentporter-dev /usr/bin/python3 -I -B -c \
  "import runpy; runpy.run_path('$old/operator-plan/authorize-a7dev-project-delegation.py')['quiet_and_stopped']()"
sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
  --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha"

# Keep the service stopped until its explicit local-write grant is installed.
install_started=1
sudo /usr/bin/python3 -I -B "$installer" --artifact "$artifact" --sha256 "$artifact_sha"
authorizer="$new/operator-plan/authorize-a7dev-writable-delegation.py"
plan=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$authorizer" --plan --workspace agentporter-dev)
printf '%s\n' "$plan"
plan_sha=$(printf '%s\n' "$plan" | /usr/bin/python3 -I -B -c 'import json,sys; print(json.load(sys.stdin)["plan_sha256"])')
sudo -u agentporter-dev /usr/bin/python3 -I -B "$authorizer" --apply \
  --workspace agentporter-dev --expected-plan-sha256 "$plan_sha"
sudo /usr/bin/systemctl start "$unit"
for (( attempt=0; attempt<15; attempt++ )); do
  if /usr/bin/curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:8876/health; then
    /usr/bin/systemctl is-active --quiet "$unit"
    echo
    echo 'A7Dev activated; writable delegation enabled for agentporter-dev. Live tool/worker acceptance remains to be run.'
    exit 0
  fi
  sleep 1
done
echo 'A7Dev health check failed. Inspect service logs and recorded installer rollback evidence.' >&2
exit 1
