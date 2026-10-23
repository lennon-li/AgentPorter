#!/usr/bin/env bash
# Run as yeli. All current eligible owner-scoped project leaves; no release installation.
set -Eeuo pipefail
cd /home/yeli/agent-work/agentporter-dev

live=/opt/agentporter-development/versions/20261022T165047.488565Z
unit=agentporter-development.service
helper_source=scripts/authorize-a7dev-writable-delegation.py
helper_sha=74e44d361c54a48ded57dcbb22704d60189313fc5cd1e1d63d16e4f21fad0eb8
storage_source="$live/operator-plan/authorize-a7dev-project-delegation.py"
storage_sha=b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b
helper_dir=/opt/agentporter-development/activation-tools/workspace-writes
helper="$helper_dir/authorize-a7dev-writable-delegation.py"
storage="$helper_dir/authorize-a7dev-project-delegation.py"
stopped_by_launcher=0
apply_started=0
plan_sha=
before_hashes=
grant_args=(--all-eligible)
timer_unit=agentporter-dev-autodiscovery.timer
discovery_unit=agentporter-dev-autodiscovery.service
timer_was_active=0
timer_stopped=0

pause_discovery() {
  local state
  state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$timer_unit")
  case "$state" in
    active|activating) timer_was_active=1 ;;
    inactive|failed) ;;
    *) echo 'Unknown discovery timer state; refuse grant.' >&2; return 1 ;;
  esac
  sudo /usr/bin/systemctl stop "$timer_unit"
  timer_stopped=1
  state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$discovery_unit")
  case "$state" in
    inactive|failed) ;;
    *) echo 'Discovery reconciliation is active or changing; leave timer stopped and retry when quiet.' >&2; return 1 ;;
  esac
}

restore_discovery_timer() {
  if [[ "$timer_stopped" == 1 && "$timer_was_active" == 1 ]]; then
    sudo /usr/bin/systemctl start "$timer_unit"
    timer_stopped=0
  fi
}

publish_pinned() {
  local source=$1 destination=$2 digest=$3 private_stage
  private_stage=$(sudo /usr/bin/mktemp -d "$helper_dir/.verified-source.XXXXXXXX")
  # Bound and verify the source as yeli before sending data to root. The root
  # copy remains private and gets an independent digest check before publish.
  /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_size<=131072, "Unsafe helper source"
    body=os.read(fd,131073)
    assert len(body)<=131072 and hashlib.sha256(body).hexdigest()==sys.argv[2], "Helper source hash mismatch"
finally:
    os.close(fd)
sys.stdout.buffer.write(body)
' "$source" "$digest" | sudo /usr/bin/install -m 0600 /dev/stdin "$private_stage/input"
  printf '%s  %s\n' "$digest" "$private_stage/input" | sudo /usr/bin/sha256sum --check --status
  sudo /usr/bin/install -m 0555 "$private_stage/input" "$destination"
  sudo /usr/bin/unlink "$private_stage/input"
  sudo /usr/bin/rmdir "$private_stage"
}

plan_digest() {
  /usr/bin/python3 -I -B -c 'import json,sys; value=json.load(sys.stdin)["plan_sha256"]; assert len(value)==64 and all(c in "0123456789abcdef" for c in value); print(value)'
}

quiet_stopped() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c \
    'import runpy,sys; runpy.run_path(sys.argv[1])["quiet_and_stopped"]()' "$storage"
}


config_matches_before() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import json,os,runpy,sys
h=runpy.run_path(sys.argv[1])
fd=h["open_directory"](h["CONFIG"],os.getuid())
try:
    actual={name:h["digest"](h["private_read"](fd,name,os.getuid())) for name in h["FILES"]+(h["HTTPS"],)}
    assert actual==json.loads(sys.argv[2]), "Private delegation config changed"
finally:
    os.close(fd)
' "$storage" "$before_hashes"
}

grant_failed() {
  local code=$?
  trap - ERR
  set +e
  echo 'Workspace enablement failed; no scope or recovery gate will be bypassed.' >&2
  if [[ "$stopped_by_launcher" == 1 && "$apply_started" == 0 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$live" ]] &&
      quiet_stopped &&
      config_matches_before; then
    if sudo /usr/bin/systemctl start "$unit"; then
      echo 'Unchanged A7Dev restarted; Workspace grant was not applied.' >&2
      restore_discovery_timer
    else
      echo 'Unchanged A7Dev restart failed; inspect development logs.' >&2
    fi
  elif [[ "$stopped_by_launcher" == 1 ]]; then
    echo 'Apply may have started or config changed. Inspect the per-plan receipt; no partial apply is assumed restored.' >&2
  elif [[ "$apply_started" == 0 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$live" ]] &&
      config_matches_before; then
    restore_discovery_timer
  fi
  if [[ "$timer_stopped" == 1 ]]; then
    echo 'Discovery timer remains stopped; inspect grant and reconciliation evidence before restoring it.' >&2
  fi
  exit "$code"
}

# Recovery behavior can be tested with stub commands without changing services.
if [[ ${BASH_SOURCE[0]-$0} != "$0" ]]; then return 0; fi
trap grant_failed ERR
case ${1-} in
  '') ;;
  --qman) grant_args=(--workspace Qman) ;;
  *) echo 'Use no arguments for all eligible project leaves, or --qman.' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
[[ $(id -un) == yeli ]] || { echo 'Run as yeli, not root.' >&2; exit 1; }
live=$(readlink -f /opt/agentporter-development/current)
case "$live" in
  /opt/agentporter-development/versions/20261022T165047.488565Z|/opt/agentporter-development/versions/20261022T181133.685266Z) ;;
  *) echo 'Live A7Dev release changed; review before applying workspace grants.' >&2; exit 1 ;;
esac
storage_source="$live/operator-plan/authorize-a7dev-project-delegation.py"
/usr/bin/systemctl is-active --quiet "$unit"
printf '%s  %s\n' "$helper_sha" "$helper_source" "$storage_sha" "$storage_source" | sha256sum --check
sudo -v
pause_discovery
# Copy pinned code as DATA only. Execute it solely from the verified root-owned
# development tools directory; never execute a workspace script as root/service.
sudo /usr/bin/install -d -o root -g root -m 0755 "$helper_dir"
sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import stat,sys
from pathlib import Path
path=Path(sys.argv[1])
for item in (path,*path.parents):
    info=item.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022, "Untrusted helper staging ancestor"
' "$helper_dir"
publish_pinned "$helper_source" "$helper" "$helper_sha"
publish_pinned "$storage_source" "$storage" "$storage_sha"
printf '%s  %s\n' "$helper_sha" "$helper" "$storage_sha" "$storage" | sudo /usr/bin/sha256sum --check
sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import hashlib,stat,sys
from pathlib import Path
for name,digest in ((sys.argv[1],sys.argv[2]),(sys.argv[3],sys.argv[4])):
    path=Path(name)
    for item in (path,*path.parents):
        info=item.lstat()
        assert not stat.S_ISLNK(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022, "Untrusted helper or ancestor"
    assert hashlib.sha256(path.read_bytes()).hexdigest()==digest, "Installed helper hash mismatch"
' "$helper" "$helper_sha" "$storage" "$storage_sha"

plan=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --plan "${grant_args[@]}")
printf '%s\n' "$plan"
plan_sha=$(printf '%s\n' "$plan" | plan_digest)
before_hashes=$(printf '%s\n' "$plan" | /usr/bin/python3 -I -B -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["plan"]["before"],sort_keys=True))')
# Refuse to interrupt active work. All queries are metadata-only, read-only.
sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import sqlite3
with sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True,timeout=2) as db:
    db.execute("PRAGMA query_only=ON")
    assert db.execute("SELECT count(*) FROM jobs WHERE status IN (?,?,?,?)",("running","cancelling","queued","cleanup_failed")).fetchone()[0]==0, "Wait for A7Dev jobs before granting workspace writes"
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type=?",("table",))}
    assert "job_admissions" not in tables or db.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0, "Unresolved A7Dev admissions"
'
sudo /usr/bin/systemctl stop "$unit"
stopped_by_launcher=1
quiet_stopped
[[ $(readlink -f /opt/agentporter-development/current) == "$live" ]]
stopped_plan=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --plan "${grant_args[@]}")
[[ $(printf '%s\n' "$stopped_plan" | plan_digest) == "$plan_sha" ]]
# Storage rechecks stopped/quiet state and exact input bytes immediately before
# any mutation; the SHA-derived recovery namespace preserves prior grants.
apply_started=1
sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --apply "${grant_args[@]}" --expected-plan-sha256 "$plan_sha"
sudo /usr/bin/systemctl start "$unit"
for ((attempt=0; attempt<15; attempt++)); do
  if /usr/bin/curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:8876/health; then
    /usr/bin/systemctl is-active --quiet "$unit"
    restore_discovery_timer
    echo
    echo "Selected workspace writable delegation enabled. Recovery: writable-delegation-recovery-$plan_sha"
    echo 'Excluded and blocked roots remain listed in the printed plan. Run live worker/file acceptance; production was not changed.'
    exit 0
  fi
  sleep 1
done
echo 'A7Dev health check failed after the grant; inspect service and per-plan recovery evidence.' >&2
false
