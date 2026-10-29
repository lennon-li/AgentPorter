#!/usr/bin/env bash
# Run as operator only after the final archive/runner independent review.
# Root executes only existing immutable installer and standard OS programs.
set -euo pipefail
set +x
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $(id -u) != 0 ]]
version=20261022T015212.581522Z
archive_sha=e0c709af0251d5725057c6d24f960ed1b58e262a2efa923b4b9bec9dd99126f5
fingerprint=3f5b472115d7ac1ee147c29279b532bf175bc63891846a8b17ec94429a3ed099
runtime_sha=9c9de5be87be8159e85c0b7dfd1165c8c17ae4045a8bfcfa371649d533798b3e
old=/opt/agentporter-development/versions/20261021T232414.837654Z
release=/opt/agentporter-development/versions/$version
artifact=/tmp/a7dev-acquisition-repair-final.tgz
config=/var/lib/agentporter-dev/config
backup=/var/backups/agentporter-dev-acquisition-repair-$version
installer=/usr/local/libexec/agentporter/install-development-artifact.py
installer_sha=84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58
old_runtime_sha=1ead69fa8d365fe9e1a062ce1906180a6b8caec1d124cf01282efc8253a96ae7
stopped=0
receipt=

quiet() {
  sudo -u agentporter-dev -- "$old/venv/bin/python" -I -c '
import sqlite3
with sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True) as c:
 assert c.execute("SELECT count(*) FROM jobs WHERE status IN (?,?,?,?)",("running","cancelling","queued","cleanup_failed")).fetchone()[0]==0,"Active/unresolved jobs; wait without interrupting work"
 tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=?",("table",))}
 assert "job_admissions" not in tables or c.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0,"Unresolved admissions; stop"
'
}

policies_unchanged() {
  local name
  for name in public-client-policy.yaml public-https.yaml workspaces.yaml; do
    sudo /usr/bin/cmp -s "$backup/$name" "$config/$name" || return
  done
}

runtime_is() {
  printf '%s  %s\n' "$1" "$config/development-runtime.yaml" | sudo /usr/bin/sha256sum --check --status
}

reviewed_policies() {
  printf '%s  %s\n' b7fe90d3872896f114944affbce5a4c84ddcadf82c32e37b7b0f9f07e6121c0b "$config/public-client-policy.yaml" | sudo /usr/bin/sha256sum --check --status || return
  printf '%s  %s\n' e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf "$config/public-https.yaml" | sudo /usr/bin/sha256sum --check --status || return
  printf '%s  %s\n' ffded407f4cd22dd8e30f1488cba12887158114617fd16b7f01c6560d4e0aacc "$config/workspaces.yaml" | sudo /usr/bin/sha256sum --check --status
}

recover() {
  local rc=$?
  [[ $rc != 0 ]] || rc=1
  trap - ERR INT TERM
  set +e
  if [[ $stopped == 1 ]]; then
    if ! sudo /usr/bin/systemctl stop agentporter-development.service || ! quiet ||
       ! sudo /usr/bin/test ! -e /sys/fs/cgroup/system.slice/agentporter-development.service; then
      echo "Cannot verify stopped/quiet service; preserve $backup and leave A7Dev stopped." >&2
      exit 1
    fi
    if ! policies_unchanged; then
      echo "Unexpected policy change; refuse overwrite. A7Dev remains stopped; evidence $backup." >&2
      exit 1
    fi
    current=$(readlink /opt/agentporter-development/current)
    if [[ $current == "$release" ]]; then
      if [[ ! $receipt =~ ^\.candidate-[0-9a-f]{32}$ ]] || ! runtime_is "$runtime_sha" ||
         ! sudo /usr/bin/python3 -I "$installer" --rollback "$receipt"; then
        echo "Exact rollback pair unavailable/changed; leave stopped and preserve $backup." >&2
        exit 1
      fi
    elif [[ $current == "$old" ]]; then
      if ! runtime_is "$old_runtime_sha"; then
        # Installer can stop between writing the known new runtime and swapping
        # current. Restore only the exact known relocation and root-private backup.
        if ! runtime_is "$runtime_sha" ||
           ! sudo /usr/bin/test ! -e "$config/.acquisition-repair-recovery" ||
           ! sudo /usr/bin/test ! -L "$config/.acquisition-repair-recovery" ||
           ! sudo /usr/bin/install -T -o agentporter-dev -g agentporter-dev -m 0600 \
             "$backup/development-runtime.yaml" "$config/.acquisition-repair-recovery" ||
           ! sudo /usr/bin/mv -T "$config/.acquisition-repair-recovery" "$config/development-runtime.yaml"; then
          echo "Unknown partial runtime state; leave stopped and preserve $backup." >&2
          exit 1
        fi
      fi
    else
      echo "Unexpected active release; leave stopped and preserve $backup." >&2
      exit 1
    fi
    if [[ $(readlink /opt/agentporter-development/current) != "$old" ]] ||
       ! runtime_is "$old_runtime_sha" || ! policies_unchanged; then
      echo "Rollback verification failed; A7Dev remains stopped. Evidence: $backup" >&2
      exit 1
    fi
    sudo /usr/bin/systemctl start agentporter-development.service || exit 1
    sudo /usr/bin/systemctl is-active --quiet agentporter-development.service || exit 1
    echo "Acceptance failed; exact previous A7Dev restored. Evidence: $backup" >&2
  fi
  exit "$rc"
}

[[ $version =~ ^[0-9]{8}T[0-9]{6}\.[0-9]{6}Z$ ]]
[[ $archive_sha =~ ^[0-9a-f]{64}$ && $fingerprint =~ ^[0-9a-f]{64}$ && $runtime_sha =~ ^[0-9a-f]{64}$ ]]
[[ $(readlink /opt/agentporter-development/current) == "$old" ]]
[[ $(systemctl is-active agentporter-development.service) == active ]]
[[ ! -L $artifact ]]
printf '%s  %s\n' "$archive_sha" "$artifact" | sha256sum --check --status
production_before=$(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts)
production_release=$(readlink /home/operator/.local/share/agentporter/current)
sudo -v
printf '%s  %s\n' "$installer_sha" "$installer" | sudo /usr/bin/sha256sum --check --status
runtime_is "$old_runtime_sha"
reviewed_policies
for path in "$backup" "$release" "$config/.acquisition-repair-recovery"; do
  sudo /usr/bin/test ! -e "$path"
  sudo /usr/bin/test ! -L "$path"
done
quiet
sudo /usr/bin/install -d -o root -g root -m 0700 "$backup"
for name in development-runtime.yaml public-client-policy.yaml public-https.yaml workspaces.yaml; do
  sudo /usr/bin/test -f "$config/$name"
  sudo /usr/bin/test ! -L "$config/$name"
  sudo /usr/bin/cp --archive --no-dereference "$config/$name" "$backup/$name"
done
printf '%s\n' "$production_before" | sudo /usr/bin/tee "$backup/production-before.txt" >/dev/null
trap recover ERR INT TERM
stopped=1
sudo /usr/bin/systemctl stop agentporter-development.service
quiet
sudo /usr/bin/test ! -e /sys/fs/cgroup/system.slice/agentporter-development.service
runtime_is "$old_runtime_sha"
reviewed_policies
policies_unchanged
sudo /usr/bin/cp --archive --no-dereference /var/lib/agentporter-dev/state/jobs.db "$backup/jobs.db"
for suffix in -wal -shm; do
  if sudo /usr/bin/test -e "/var/lib/agentporter-dev/state/jobs.db$suffix"; then
    sudo /usr/bin/cp --archive --no-dereference "/var/lib/agentporter-dev/state/jobs.db$suffix" "$backup/jobs.db$suffix"
  fi
done
sudo /usr/bin/python3 -I "$installer" --artifact "$artifact" --sha256 "$archive_sha" \
  | sudo /usr/bin/tee "$backup/installer-receipt.json"
receipt=$(sudo /usr/bin/cat "$backup/installer-receipt.json" | /usr/bin/python3 -I -c \
  'import json,pathlib,sys; print(pathlib.Path(json.load(sys.stdin)["rollback_evidence"]).name)')
[[ $receipt =~ ^\.candidate-[0-9a-f]{32}$ ]]
[[ $(readlink /opt/agentporter-development/current) == "$release" ]]
runtime_is "$runtime_sha"
policies_unchanged
sudo /usr/bin/systemctl start agentporter-development.service
ready=0
for attempt in {1..30}; do
  if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8876/health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ $ready == 1 ]]
sudo -u agentporter-dev -- "$release/venv/bin/python" -I -B \
  "$release/operator-plan/verify-a7dev-acquisition-repair.py" \
  --public-key-file "$config/secrets.env" --expected-fingerprint "$fingerprint" \
  | sudo /usr/bin/tee "$backup/public-acceptance.log"
policies_unchanged
runtime_is "$runtime_sha"
[[ $(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts) == "$production_before" ]]
[[ $(readlink /home/operator/.local/share/agentporter/current) == "$production_release" ]]
stopped=0
trap - ERR INT TERM
echo "Acquisition repair passed public/local acceptance; production A7 unchanged. Evidence: $backup"
echo 'Historical identity remains unverified; persisted receipts attest acquisition/file integrity only.'
