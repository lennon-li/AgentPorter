#!/usr/bin/env bash
# Run as operator. Only installed system programs cross sudo; no repository code
# executes as root. Owner approval: all ordinary registered project scopes.
set -euo pipefail
set +x
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ $(id -u) == 0 ]]; then
  echo 'Run this as operator; the immutable installer alone needs root.' >&2
  exit 2
fi
version=20261021T232414.837654Z
archive_sha=c2924acec4e2a5bb15b36c41891929179f614c211a79a5a57f5b53e258d28566
fingerprint=099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315
policy_helper_sha=e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0
artifact=/tmp/a7dev-project-access.tgz
old_release=/opt/agentporter-development/versions/20261021T212000.000019Z
release=/opt/agentporter-development/versions/$version
config=/var/lib/agentporter-dev/config
backup=/var/backups/agentporter-dev-project-access-$version
installer=/usr/local/libexec/agentporter/install-development-artifact.py
installer_sha=84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58
receipt=
plan_sha=
stopped=0
installed=0
policy_attempted=0

quiet() {
  sudo -u agentporter-dev -- "$1/venv/bin/python" -I -c '
import sqlite3
c=sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True)
assert c.execute("SELECT count(*) FROM jobs WHERE status IN (?,?,?,?)",("running","cancelling","queued","cleanup_failed")).fetchone()[0]==0,"Active/unresolved jobs: wait; do not stop work"
t={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=?",("table",))}
assert "job_admissions" not in t or c.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0,"Unresolved admissions: stop"
c.close()
'
}

policy() {
  sudo -u agentporter-dev -- "$release/venv/bin/python" -I \
    "$release/operator-plan/authorize-a7dev-project-delegation.py" "$@"
}

recover() {
  local rc=$?
  if [[ $rc == 0 ]]; then rc=1; fi
  trap - ERR INT TERM
  set +e
  if [[ $stopped == 1 ]]; then
    if [[ $installed == 1 ]]; then
      if ! sudo /usr/bin/systemctl stop agentporter-development.service; then
        echo "Cannot stop A7Dev; refuse rollback of a running service. Preserve $backup." >&2
        exit 1
      fi
      if [[ $policy_attempted == 1 ]] && sudo -u agentporter-dev -- /usr/bin/test -f \
          "$config/project-delegation-recovery-v1/receipt.json"; then
        policy --rollback --expected-plan-sha256 "$plan_sha"
        if [[ $? != 0 ]]; then
          echo "Guarded policy rollback failed. A7Dev remains stopped; preserve $backup." >&2
          exit 1
        fi
      fi
      sudo /usr/bin/python3 -I "$installer" --rollback "$receipt"
      if [[ $? != 0 ]]; then
        echo "Release rollback failed. A7Dev remains stopped; preserve $backup." >&2
        exit 1
      fi
    elif [[ $(readlink /opt/agentporter-development/current) != "$old_release" ]]; then
      echo "Interrupted immutable installation; A7Dev remains stopped. Preserve $backup; do not rerun blindly." >&2
      exit 1
    else
      # The immutable installer writes runtime before swapping current. An
      # interrupted install must not restart the old package with new config.
      for name in development-runtime.yaml workspaces.yaml public-client-policy.yaml public-https.yaml; do
        if ! sudo /usr/bin/cmp -s "$backup/$name" "$config/$name"; then
          echo "Interrupted installation changed $name; keep A7Dev stopped and preserve $backup." >&2
          exit 1
        fi
      done
    fi
    sudo /usr/bin/systemctl start agentporter-development.service
  fi
  echo "Installation did not pass acceptance. Evidence: $backup" >&2
  exit "${rc:-1}"
}

[[ $version =~ ^[0-9]{8}T[0-9]{6}\.[0-9]{6}Z$ ]]
[[ $archive_sha =~ ^[0-9a-f]{64}$ && $fingerprint =~ ^[0-9a-f]{64}$ ]]
[[ $(readlink /opt/agentporter-development/current) == "$old_release" ]]
[[ $(systemctl is-active agentporter-development.service) == active ]]
[[ ! -L $artifact ]]
printf '%s  %s\n' "$archive_sha" "$artifact" | sha256sum --check --status
sudo -v
printf '%s  %s\n' "$installer_sha" "$installer" | sudo /usr/bin/sha256sum --check --status
printf '%s  %s\n' 97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043 "$config/public-client-policy.yaml" | sudo /usr/bin/sha256sum --check --status
printf '%s  %s\n' e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf "$config/public-https.yaml" | sudo /usr/bin/sha256sum --check --status
sudo /usr/bin/test ! -e "$config/project-delegation-recovery-v1"
sudo /usr/bin/test ! -L "$config/project-delegation-recovery-v1"
sudo /usr/bin/test ! -e "$backup"
sudo /usr/bin/test ! -e "$release"
quiet "$old_release"
production_before=$(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts)
production_release=$(readlink /home/operator/.local/share/agentporter/current)
sudo /usr/bin/install -d -o root -g root -m 0700 "$backup"
for name in development-runtime.yaml workspaces.yaml public-client-policy.yaml public-https.yaml; do
  sudo /usr/bin/test -f "$config/$name"
  sudo /usr/bin/test ! -L "$config/$name"
  sudo /usr/bin/cp --archive --no-dereference "$config/$name" "$backup/$name"
done
printf '%s\n' "$production_before" | sudo /usr/bin/tee "$backup/production-before.txt" >/dev/null
trap recover ERR INT TERM
stopped=1
sudo /usr/bin/systemctl stop agentporter-development.service
quiet "$old_release"
sudo /usr/bin/python3 -I "$installer" --artifact "$artifact" --sha256 "$archive_sha" \
  | sudo /usr/bin/tee "$backup/installer-receipt.json"
receipt=$(sudo /usr/bin/cat "$backup/installer-receipt.json" | /usr/bin/python3 -I -c \
  'import json,sys,pathlib; r=json.load(sys.stdin); print(pathlib.Path(r["rollback_evidence"]).name)')
[[ $receipt =~ ^\.candidate-[0-9a-f]{32}$ ]]
installed=1
[[ $(readlink /opt/agentporter-development/current) == "$release" ]]
printf '%s  %s\n' "$policy_helper_sha" "$release/operator-plan/authorize-a7dev-project-delegation.py" | sudo /usr/bin/sha256sum --check --status
plan=$(policy --plan)
printf '%s\n' "$plan" | sudo /usr/bin/tee "$backup/project-access-plan.json"
plan_sha=$(printf '%s' "$plan" | /usr/bin/python3 -I -c 'import json,sys; print(json.load(sys.stdin)["plan_sha256"])')
[[ $plan_sha =~ ^[0-9a-f]{64}$ ]]
policy_attempted=1
policy --apply --expected-plan-sha256 "$plan_sha" \
  | sudo /usr/bin/tee "$backup/project-access-apply.json"
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
sudo -u agentporter-dev -- "$release/venv/bin/python" -I \
  "$release/operator-plan/verify-a7dev-project-access.py" \
  --after --public-key-file "$config/secrets.env" --expected-fingerprint "$fingerprint" \
  | sudo /usr/bin/tee "$backup/public-access-acceptance.log"
[[ $(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts) == "$production_before" ]]
[[ $(readlink /home/operator/.local/share/agentporter/current) == "$production_release" ]]
stopped=0
trap - ERR INT TERM
echo "A7Dev project scopes installed; public access and denial checks passed. Evidence: $backup"
echo 'Production A7 unchanged. Provider-backed acceptance follows; a quota failure will not undo working access.'
sudo -u agentporter-dev -- "$release/venv/bin/python" -I \
  "$release/operator-plan/verify-a7dev-project-access.py" \
  --after --execute-jax --public-key-file "$config/secrets.env" --expected-fingerprint "$fingerprint" \
  | sudo /usr/bin/tee "$backup/jax-project-acceptance.log"
