#!/usr/bin/env bash
# Run as operator on Asgard. Only this pinned A7Dev candidate and workspace scope.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

artifact=/tmp/a7dev-workspace-writes-activation.tgz
artifact_sha=ce546675f17f6e6e70a39d196ac763b3bbe155de67ad39f24af057e95e22d5b9
gate_source=scripts/verify-a7dev-runtime-install-gate.py
gate_dir=/opt/agentporter-development/activation-tools
gate="$gate_dir/runtime-install-gate.py"
gate_sha=9d57de9d99ea9b6e619a5542a92fecda52a4e0e0f7ab778d9272bf5380099c92
old=/opt/agentporter-development/versions/20261022T165047.488565Z
new=/opt/agentporter-development/versions/20261022T181133.685266Z
installer=/usr/local/libexec/agentporter/install-development-artifact.py
installer_sha=84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58
storage_sha=e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0
unit=agentporter-development.service
expected_runtime_sha=b8e1d9b98398e5b3a3776670ccb98e718c02468c023d6b859254783c79365d9c
stopped_by_launcher=0
install_started=0
discovery_was_active=0
grant_launcher_sha=de47c32cad64fbb33ab15f960e088c217b8b7546ef587fa1ab8d582f491ebe37
discovery_installer_sha=107bdca3aee8bb22de624b9153f73398e9d2577bb64a5782bf1b3ec55371a01c
directory_repair_launcher_sha=075ee6b6f6b085cc28adf9982971b7cc71f09446778fe04dfc7cc4c28fe0e702

run_verified_child() {
  /usr/bin/python3 -I -B -c '
import hashlib,os,stat,subprocess,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_size<=131072, "Unsafe child launcher"
    body=os.read(fd,131073)
    assert len(body)<=131072 and hashlib.sha256(body).hexdigest()==sys.argv[2], "Child launcher hash mismatch"
finally:
    os.close(fd)
# Execute the checked in-memory bytes. A later path replacement is irrelevant.
if sys.argv[3] == "--emit":
    sys.stdout.buffer.write(body)
elif sys.argv[3] != "--check":
    result=subprocess.run(["/bin/bash","-c",body.decode("utf-8")])
    if result.returncode:
        print("Verified activation step failed (exit %s); inspect its preceding message." % result.returncode,file=sys.stderr)
        sys.exit(result.returncode)
' "$1" "$2" "${3---run}"
}

development_is_active() {
  /usr/bin/systemctl is-active --quiet "$unit"
}

activation_failed() {
  local code=$?
  trap - ERR
  set +e
  local old_service_recovered=1
  echo 'Activation failed; no failed gate will be bypassed.' >&2
  if [[ "$stopped_by_launcher" == 1 && "$install_started" == 0 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] &&
      sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
        --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha" >/dev/null; then
    if sudo /usr/bin/systemctl start "$unit"; then
      echo 'Original A7Dev release restarted; installer was never invoked.' >&2
    else
      old_service_recovered=0
      echo 'Original release restart failed; inspect development service logs.' >&2
    fi
  elif [[ "$stopped_by_launcher" == 1 ]]; then
    echo 'Inspect A7Dev state, runtime and recorded installer rollback evidence; discovery remains paused.' >&2
  fi
  if [[ $install_started == 0 && $discovery_was_active == 1 && $old_service_recovered == 1 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$old" ]] &&
      development_is_active &&
      sudo -u agentporter-dev /usr/bin/python3 -I -B "$gate" \
        --expected-version "${old##*/}" --expected-canonical-sha256 "$expected_runtime_sha" >/dev/null; then
    sudo /usr/bin/systemctl start agentporter-dev-autodiscovery.timer
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
run_verified_child scripts/enable-a7dev-workspace-writes.sh "$grant_launcher_sha" --check
run_verified_child scripts/install-a7dev-autodiscovery.sh "$discovery_installer_sha" --check
run_verified_child scripts/repair-a7dev-shared-directory-defaults.sh "$directory_repair_launcher_sha" --check

sudo -v
if /usr/bin/systemctl is-active --quiet agentporter-dev-autodiscovery.timer; then discovery_was_active=1; fi
sudo /usr/bin/systemctl stop agentporter-dev-autodiscovery.timer
case $(/usr/bin/systemctl show agentporter-dev-autodiscovery.service --property=ActiveState --value) in
  inactive|failed) ;;
  *) echo 'Wait for the development discovery reconciler before activation.' >&2; exit 1 ;;
esac
printf '%s  %s\n' "$installer_sha" "$installer" | sudo /usr/bin/sha256sum --check
# The service helper executes only after its installed root-owned copy is pinned.
# /usr/local/libexec is root-private on Asgard. Keep it private and use a
# development-only root-owned location traversable by the service account.
sudo /usr/bin/install -d -o root -g root -m 0755 "$gate_dir"
# Read mutable input as operator into a root-private staging file. A changed
# input can never publish private root-readable data before its hash passes.
root_stage=$(sudo /usr/bin/mktemp -d "$gate_dir/.gate-stage.XXXXXXXX")
run_verified_child "$gate_source" "$gate_sha" --emit |
  sudo /usr/bin/install -o root -g root -m 0600 /dev/stdin "$root_stage/gate.py"
printf '%s  %s\n' "$gate_sha" "$root_stage/gate.py" | sudo /usr/bin/sha256sum --check
sudo /usr/bin/install -o root -g root -m 0555 "$root_stage/gate.py" "$gate"
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
sudo /usr/bin/systemctl start "$unit"
for (( attempt=0; attempt<15; attempt++ )); do
  if /usr/bin/curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:8876/health; then
    /usr/bin/systemctl is-active --quiet "$unit"
    echo
    echo 'Default-ACL core installed; discovery remains paused during scoped grants.'
    run_verified_child scripts/enable-a7dev-workspace-writes.sh "$grant_launcher_sha"
    run_verified_child scripts/repair-a7dev-shared-directory-defaults.sh "$directory_repair_launcher_sha"
    run_verified_child scripts/install-a7dev-autodiscovery.sh "$discovery_installer_sha"
    echo 'A7Dev activation completed. Review printed blocked roots and run live acceptance; production promotion remains gated.'
    exit 0
  fi
  sleep 1
done
echo 'A7Dev health check failed. Inspect service logs and recorded installer rollback evidence.' >&2
exit 1
