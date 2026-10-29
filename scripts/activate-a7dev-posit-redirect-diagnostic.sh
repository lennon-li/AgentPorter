#!/usr/bin/env bash
# Operator action: pinned development-only Posit redirect diagnostic; no policy change.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

artifact=/tmp/prof-a7dev-posit-redirect-diagnostic-20261022/candidate.tgz
artifact_sha=a5b30705a725369abfd5237f457cf179267af5272f4336967d73bdac82ae5d23
old=/opt/agentporter-development/versions/20261022T204324.626687Z
new=/opt/agentporter-development/versions/20261022T224004.423620Z
expected_runtime_sha=8c9a0491c836043dbdb155f7f8dbbd64feddf2a145fee8ba3d868f79ec572842
installer=/usr/local/libexec/agentporter/install-development-artifact.py
installer_sha=84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58
gate=/opt/agentporter-development/activation-tools/runtime-install-gate.py
gate_sha=9d57de9d99ea9b6e619a5542a92fecda52a4e0e0f7ab778d9272bf5380099c92
storage_sha=e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0
unit=agentporter-development.service
timer_unit=agentporter-dev-autodiscovery.timer
discovery_unit=agentporter-dev-autodiscovery.service
stopped_by_launcher=0
install_started=0
timer_stopped=0
timer_was_active=0

run_gate() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
    --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha"
}

quiet_jobs() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import sqlite3
with sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True,timeout=2) as db:
    db.execute("PRAGMA query_only=ON")
    terminal=("completed","failed","cancelled","timed_out","output_limit_exceeded","interrupted")
    assert db.execute("SELECT count(*) FROM jobs WHERE status IS NULL OR status NOT IN (?,?,?,?,?,?)",terminal).fetchone()[0]==0, "Wait for active or unresolved A7Dev jobs"
    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type=\x27table\x27")}
    assert "job_admissions" not in tables or db.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0, "Unresolved A7Dev admissions"
'
}

healthy_development() {
  local attempt
  for ((attempt=0; attempt<15; attempt++)); do
    if /usr/bin/systemctl is-active --quiet "$unit" && /usr/bin/python3 -I -B -c '
import http.client,json
c=http.client.HTTPConnection("127.0.0.1",8876,timeout=2)
try:
    c.request("GET","/health"); r=c.getresponse()
    assert r.status==200 and json.loads(r.read(1025))=={"status":"healthy"}
finally:
    c.close()
' 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

pause_discovery() {
  local state attempt
  state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$timer_unit")
  case "$state" in
    active|activating) timer_was_active=1 ;;
    inactive|failed) ;;
    *) echo 'Unknown discovery timer state; refuse activation.' >&2; return 1 ;;
  esac
  sudo /usr/bin/systemctl stop "$timer_unit"
  timer_stopped=1
  for ((attempt=0; attempt<30; attempt++)); do
    state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$discovery_unit")
    case "$state" in
      inactive|failed) return 0 ;;
      active|activating|deactivating) sleep 1 ;;
      *) break ;;
    esac
  done
  echo 'Discovery is still reconciling; leave timer paused and inspect.' >&2
  return 1
}

restore_timer() {
  if [[ "$timer_stopped" == 1 && "$timer_was_active" == 1 ]]; then
    sudo /usr/bin/systemctl start "$timer_unit"
    timer_stopped=0
  fi
}

activation_failed() {
  local code=$?
  trap - ERR
  set +e
  echo 'Development activation stopped; no failed check is bypassed.' >&2
  if [[ "$install_started" == 1 ]]; then
    sudo /usr/bin/systemctl stop "$unit"
    echo 'Installation began. Leave A7Dev stopped; inspect installer evidence and immutable installation evidence before recovery.' >&2
  elif [[ "$stopped_by_launcher" == 1 || "$timer_stopped" == 1 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] && run_gate && quiet_jobs; then
    if [[ "$stopped_by_launcher" == 1 ]]; then
      if sudo /usr/bin/systemctl start "$unit" && healthy_development; then
        restore_timer
        echo 'Unchanged original A7Dev recovered; no installation began.' >&2
      fi
    elif healthy_development; then
      restore_timer
    fi
  fi
  if [[ "$timer_stopped" == 1 ]]; then echo 'Discovery timer remains paused pending inspection.' >&2; fi
  exit "$code"
}

# Tests source only these functions; no privileged command runs while sourcing.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
trap activation_failed ERR
[[ $# == 0 && $(id -un) == operator ]] || { echo 'Run as operator with no arguments, never root.' >&2; exit 1; }
[[ "$artifact_sha" =~ ^[0-9a-f]{64}$ && "${new##*/}" =~ ^[0-9]{8}T[0-9]{6}\.[0-9]{6}Z$ ]] || {
  echo 'Candidate pins are not finalized; refuse activation.' >&2; exit 1;
}
[[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] || {
  echo 'Development release changed; rebuild and review.' >&2; exit 1;
}
[[ ! -e "$new" && ! -L "$new" ]] || { echo 'Candidate already installed; inspect state before another run.' >&2; exit 1; }
printf '%s  %s\n' "$artifact_sha" "$artifact" "$storage_sha" "$old/operator-plan/authorize-a7dev-project-delegation.py" | /usr/bin/sha256sum --check
sudo -v
printf '%s  %s\n' "$installer_sha" "$installer" "$gate_sha" "$gate" | sudo /usr/bin/sha256sum --check
healthy_development
pause_discovery
run_gate
quiet_jobs
sudo /usr/bin/systemctl stop "$unit"
stopped_by_launcher=1
sudo -u agentporter-dev /usr/bin/python3 -I -B -c \
  "import runpy; runpy.run_path('$old/operator-plan/authorize-a7dev-project-delegation.py')['quiet_and_stopped']()"
quiet_jobs
run_gate
install_started=1
sudo /usr/bin/python3 -I -B "$installer" --artifact "$artifact" --sha256 "$artifact_sha"
sudo /usr/bin/systemctl start "$unit"
healthy_development
restore_timer
echo 'Posit redirect diagnostic activated in A7Dev. Redirects remain rejected; live destination inspection is still required. Production was not changed.'
