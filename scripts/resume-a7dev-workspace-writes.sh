#!/usr/bin/env bash
# Continue the installed 181133 release and 33 grants. Never install/regrant.
set -Eeuo pipefail

live=/opt/agentporter-development/versions/20261022T181133.685266Z
unit=agentporter-development.service
timer_unit=agentporter-dev-autodiscovery.timer
discovery_unit=agentporter-dev-autodiscovery.service
helper_dir=/opt/agentporter-development/activation-tools/directory-access
helper="$helper_dir/repair-a7dev-service-directory-access.py"
helper_source=scripts/repair-a7dev-service-directory-access.py
helper_sha=1db22bfc6d2f1d831cb5ca7959386c84bffbafdec22ef72177ec9ff0026047b1
defaults="$helper_dir/repair-a7dev-shared-directory-defaults.py"
defaults_source=scripts/repair-a7dev-shared-directory-defaults.py
defaults_sha=62f2e0e566515ece9260beb3322ef763998bce76f2c52df550921b3cb8c1b8df
default_launcher_sha=c522f8b6d4305e7b2c782dbbb69b9668b59a503d16f87bc5e7ae7d566cf32473
discovery_installer_sha=476b014e02bb98a68a399b1081d05ade5791c3259f7f6ddc6b691f57279534ff
storage="$helper_dir/authorize-a7dev-project-delegation.py"
storage_sha=b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b
stopped_by_launcher=0
apply_started=0
timer_was_active=0
timer_stopped=0
before_hashes=

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

publish_pinned() {
  local source=$1 destination=$2 digest=$3 private_stage
  private_stage=$(sudo /usr/bin/mktemp -d "$helper_dir/.verified-source.XXXXXXXX")
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

pause_discovery() {
  local state
  state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$timer_unit")
  case "$state" in
    active|activating) timer_was_active=1 ;;
    inactive|failed) ;;
    *) echo 'Unknown discovery timer state; refuse ACL repair.' >&2; return 1 ;;
  esac
  sudo /usr/bin/systemctl stop "$timer_unit"
  timer_stopped=1
  state=$(sudo /usr/bin/systemctl show --value --property=ActiveState "$discovery_unit")
  case "$state" in
    inactive|failed) ;;
    *) echo 'Discovery reconciliation active or changing; leave timer stopped and retry when quiet.' >&2; return 1 ;;
  esac
}

restore_timer() {
  if [[ "$timer_stopped" == 1 && "$timer_was_active" == 1 ]]; then
    sudo /usr/bin/systemctl start "$timer_unit"
    timer_stopped=0
  fi
}

configuration_hashes() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import json,os,runpy,sys
h=runpy.run_path(sys.argv[1]); fd=h["open_directory"](h["CONFIG"],os.getuid())
try:
    print(json.dumps({name:h["digest"](h["private_read"](fd,name,os.getuid())) for name in h["FILES"]},sort_keys=True))
finally:
    os.close(fd)
' "$storage"
}

config_matches_before() {
  [[ -n "$before_hashes" && $(configuration_hashes) == "$before_hashes" ]]
}

quiet_jobs() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c '
import sqlite3
with sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True,timeout=2) as db:
    db.execute("PRAGMA query_only=ON")
    terminal=("completed","failed","cancelled","timed_out","output_limit_exceeded","interrupted")
    assert db.execute("SELECT count(*) FROM jobs WHERE status IS NULL OR status NOT IN (?,?,?,?,?,?)",terminal).fetchone()[0]==0, "Wait for active or unresolved A7Dev jobs"
    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type=?",("table",))}
    assert "job_admissions" not in tables or db.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0, "Unresolved A7Dev admissions"
'
}

quiet_stopped() {
  sudo -u agentporter-dev /usr/bin/python3 -I -B -c \
    'import runpy,sys; runpy.run_path(sys.argv[1])["quiet_and_stopped"]()' "$storage"
}

development_is_active() {
  /usr/bin/systemctl is-active --quiet "$unit"
}

healthy_development() {
  local attempt
  for ((attempt=0; attempt<15; attempt++)); do
    if /usr/bin/curl --noproxy '*' --fail --silent --max-time 2 http://127.0.0.1:8876/health >/dev/null; then
      development_is_active
      return
    fi
    sleep 1
  done
  return 1
}

repair_failed() {
  local code=$?
  trap - ERR
  set +e
  echo 'Service-owned directory access repair stopped; no failed gate is bypassed.' >&2
  if [[ "$apply_started" == 0 ]] &&
      [[ $(readlink -f /opt/agentporter-development/current) == "$live" ]] &&
      config_matches_before; then
    if [[ "$stopped_by_launcher" == 1 ]]; then
      if quiet_stopped && sudo /usr/bin/systemctl start "$unit" && healthy_development; then
        echo 'Unchanged A7Dev restarted; no directory apply began.' >&2
        restore_timer
      fi
    elif quiet_jobs && development_is_active; then
      restore_timer
    fi
  fi
  if [[ "$apply_started" == 1 ]]; then
    echo 'An apply began; preserve each root-private backup and inspect actual ACL state. No automatic rollback or recovery is assumed.' >&2
  fi
  if [[ "$timer_stopped" == 1 ]]; then
    echo 'Discovery timer remains stopped pending inspection.' >&2
  fi
  exit "$code"
}

plan_digest() {
  /usr/bin/python3 -I -B -c '
import json,sys
plan=json.load(sys.stdin); value=plan["plan_sha256"]
assert isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)
blockers=plan["remaining_human_access_blockers"]
assert type(blockers) is int and blockers==0, "Some blocked directories are outside service ownership; no broad ACL bypass is allowed"
print(value)'
}

# Allow only local function tests when sourced; no live actions occur.
if [[ ${BASH_SOURCE[0]-$0} != "$0" ]]; then return 0; fi
cd /home/yeli/agent-work/agentporter-dev
trap repair_failed ERR
[[ $# == 0 && $(id -un) == yeli ]] || { echo 'Run as yeli with no arguments.' >&2; exit 1; }
[[ "$helper_sha" =~ ^[0-9a-f]{64}$ ]] || { echo 'Service access helper final SHA is not pinned; refuse activation.' >&2; exit 1; }
live=$(readlink -f /opt/agentporter-development/current)
case "$live" in
  /opt/agentporter-development/versions/20261022T181133.685266Z) ;;
  *) echo 'Unreviewed live release; refuse directory ACL repair.' >&2; exit 1 ;;
esac
storage_source="$live/operator-plan/authorize-a7dev-project-delegation.py"
development_is_active
healthy_development
printf '%s  %s\n' "$helper_sha" "$helper_source" "$storage_sha" "$storage_source" "$defaults_sha" "$defaults_source" | sha256sum --check
sudo -v
run_verified_child scripts/repair-a7dev-shared-directory-defaults.sh "$default_launcher_sha" --check
run_verified_child scripts/install-a7dev-autodiscovery.sh "$discovery_installer_sha" --check
pause_discovery
sudo /usr/bin/install -d -o root -g root -m 0755 "$helper_dir"
/usr/bin/python3 -I -B -c '
import stat,sys
from pathlib import Path
path=Path(sys.argv[1])
for item in (path,*path.parents):
    info=item.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022, "Untrusted directory helper staging ancestor"
' "$helper_dir"
publish_pinned "$helper_source" "$helper" "$helper_sha"
publish_pinned "$defaults_source" "$defaults" "$defaults_sha"
publish_pinned "$storage_source" "$storage" "$storage_sha"
printf '%s  %s\n' "$helper_sha" "$helper" "$storage_sha" "$storage" "$defaults_sha" "$defaults" | sudo /usr/bin/sha256sum --check
before_hashes=$(configuration_hashes)
inventory=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --all-writable --list-workspaces)
printf '%s\n' "$inventory"
workspace_lines=$(printf '%s\n' "$inventory" | /usr/bin/python3 -I -B -c '
import json,re,sys
names=json.load(sys.stdin)["selected_workspaces"]
assert isinstance(names,list) and len(names)==33 and len(set(names))==33, "Expected the installed33-workspace scope; inspect changed grants before continuation"
assert all(isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",name) for name in names)
print("\n".join(names))')
mapfile -t workspaces <<< "$workspace_lines"
plan_shas=()
for workspace in "${workspaces[@]}"; do
  plan=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --workspace "$workspace")
  printf '%s\n' "$plan"
  plan_shas+=("$(printf '%s\n' "$plan" | plan_digest)")
done
quiet_jobs
config_matches_before
sudo /usr/bin/systemctl stop "$unit"
stopped_by_launcher=1
quiet_stopped
[[ $(readlink -f /opt/agentporter-development/current) == "$live" ]]
config_matches_before
# All roots must retain their exact plans before the first directory mutation.
for index in "${!workspaces[@]}"; do
  plan=$(sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --workspace "${workspaces[index]}")
  [[ $(printf '%s\n' "$plan" | plan_digest) == "${plan_shas[index]}" ]]
done
for index in "${!workspaces[@]}"; do
  apply_started=1
  sudo -u agentporter-dev /usr/bin/python3 -I -B "$helper" --workspace "${workspaces[index]}" \
    --apply --expected-plan-sha256 "${plan_shas[index]}"
done
sudo /usr/bin/systemctl start "$unit"
healthy_development
run_verified_child scripts/repair-a7dev-shared-directory-defaults.sh "$default_launcher_sha"
run_verified_child scripts/install-a7dev-autodiscovery.sh "$discovery_installer_sha"
restore_timer
echo 'Continuation applied service-owned directory access and defaults; validate live worker access. Production was not changed.'
