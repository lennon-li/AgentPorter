#!/usr/bin/env bash
# Reactivate the existing reviewed release after the acceptance-only rollback.
# Run as operator. No repository code executes as root; no ACLs or datasets change.
set -euo pipefail
set +x
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $(id -u) != 0 ]]
old=/opt/agentporter-development/versions/20261021T212000.000019Z
release=/opt/agentporter-development/versions/20261021T232414.837654Z
config=/var/lib/agentporter-dev/config
installer=/usr/local/libexec/agentporter/install-development-artifact.py
rollback=.candidate-482d30fb1a69a9aa75dc7f5ff88250fe
evidence=/opt/agentporter-development/$rollback
original_backup=/var/backups/agentporter-dev-project-access-20261021T232414.837654Z
backup=/var/backups/agentporter-dev-project-access-reactivation-20261021T232414.837654Z
runtime_template=docs/evidence/a7dev-project-access-20261021/retry-runtime-template.json
runtime_sha=fa33ac76062ce50e333a71d21310808bf6ea64658117da6224c6b4dab484a3fe
plan_sha=2c4b78429001d4a3f3e5acdfa074d2a0ea5987a3980b04e6d378177d5f9c196c
fingerprint=099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315
preflight_sha=f70f1f79987bc34edc2e56c718245fd852c42be43175c06d02355b9ce1449542
stopped=0
policy_attempted=0
runtime_temp=$config/.runtime-project-access-reactivation
link_temp=/opt/agentporter-development/.current-project-access-reactivation

quiet() {
  sudo -u agentporter-dev -- "$old/venv/bin/python" -I -c '
import sqlite3
c=sqlite3.connect("file:/var/lib/agentporter-dev/state/jobs.db?mode=ro",uri=True)
assert c.execute("SELECT count(*) FROM jobs WHERE status IN (?,?,?,?)",("running","cancelling","queued","cleanup_failed")).fetchone()[0]==0,"Active/unresolved jobs: wait without stopping work"
t={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=?",("table",))}
assert "job_admissions" not in t or c.execute("SELECT count(*) FROM job_admissions").fetchone()[0]==0,"Unresolved admissions"
c.close()
'
}

preflight() {
  sudo -u agentporter-dev -- "$release/venv/bin/python" -I -B -c '
import hashlib,pathlib,sys
p=pathlib.Path("/home/operator/agent-work/agentporter-dev/scripts/preflight-a7dev-project-access-retry.py")
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()==sys.argv.pop(1),"Retry preflight changed"
exec(compile(b,str(p),"exec"))
' "$preflight_sha" "$@"
}

policy() {
  sudo -u agentporter-dev -- "$release/venv/bin/python" -I -B \
    "$release/operator-plan/authorize-a7dev-project-delegation.py" "$@"
}

acceptance() {
  sudo -u agentporter-dev -- "$release/venv/bin/python" -I -B -c '
import hashlib,pathlib
p=pathlib.Path("/home/operator/agent-work/agentporter-dev/scripts/verify-a7dev-project-access.py")
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()=="08bcdd7413589045d40823cb652f2bb09c1b414445464c584c6fd48a42db674a","Corrected acceptance changed"
exec(compile(b,str(p),"exec"))
' --after --public-key-file "$config/secrets.env" --expected-fingerprint "$fingerprint" "$@"
}

restore_runtime() {
  sudo /usr/bin/test ! -e "$runtime_temp" || return
  sudo /usr/bin/test ! -L "$runtime_temp" || return
  sudo /usr/bin/install -T -o agentporter-dev -g agentporter-dev -m 0600 "$1" "$runtime_temp" || return
  sudo /usr/bin/mv -T "$runtime_temp" "$config/development-runtime.yaml"
}

recover() {
  local rc=$?
  if [[ $rc == 0 ]]; then rc=1; fi
  trap - ERR INT TERM
  set +e
  if [[ $stopped == 1 ]]; then
    if ! sudo /usr/bin/systemctl stop agentporter-development.service || ! quiet; then
      echo "Cannot establish stopped/quiet A7Dev; refuse rollback writes. Preserve $backup." >&2
      exit 1
    fi
    if ! sudo /usr/bin/test ! -e /sys/fs/cgroup/system.slice/agentporter-development.service; then
      echo "Service cgroup still exists; refuse rollback writes. Preserve $backup." >&2
      exit 1
    fi
    current=$(readlink /opt/agentporter-development/current)
    if [[ $current == "$release" ]]; then
      if [[ $policy_attempted == 1 ]] && sudo -u agentporter-dev -- /usr/bin/test -f "$config/project-delegation-recovery-v1/receipt.json"; then
        if ! policy --rollback --expected-plan-sha256 "$plan_sha"; then
          echo "Guarded policy rollback failed; A7Dev remains stopped. Preserve $backup." >&2
          exit 1
        fi
      else
        if ! sudo /usr/bin/cmp -s "$backup/reviewed-runtime.json" "$config/development-runtime.yaml"; then
          echo "Unexpected runtime before policy application; keep stopped. Preserve $backup." >&2
          exit 1
        fi
        for name in public-client-policy.yaml workspaces.yaml public-https.yaml; do
          if ! sudo /usr/bin/cmp -s "$backup/$name" "$config/$name"; then
            echo "Unexpected configuration before policy application; keep stopped. Preserve $backup." >&2
            exit 1
          fi
        done
      fi
      if ! sudo /usr/bin/python3 -I "$installer" --rollback "$rollback"; then
        echo "Exact release rollback failed; A7Dev remains stopped. Preserve $backup." >&2
        exit 1
      fi
    elif [[ $current == "$old" ]]; then
      for name in public-client-policy.yaml workspaces.yaml public-https.yaml; do
        if ! sudo /usr/bin/cmp -s "$backup/$name" "$config/$name"; then
          echo "Unexpected configuration drift before activation; keep stopped. Preserve $backup." >&2
          exit 1
        fi
      done
      if ! sudo /usr/bin/cmp -s "$backup/development-runtime.yaml" "$config/development-runtime.yaml"; then
        if ! sudo /usr/bin/cmp -s "$backup/reviewed-runtime.json" "$config/development-runtime.yaml"; then
          echo "Unknown partial runtime; keep stopped. Preserve $backup." >&2
          exit 1
        fi
        if ! restore_runtime "$backup/development-runtime.yaml"; then
          echo "Runtime restore failed; keep stopped. Preserve $backup." >&2
          exit 1
        fi
      fi
    else
      echo "Unexpected release pointer; keep stopped. Preserve $backup." >&2
      exit 1
    fi
    for name in development-runtime.yaml workspaces.yaml public-client-policy.yaml public-https.yaml; do
      if ! sudo /usr/bin/cmp -s "$backup/$name" "$config/$name"; then
        echo "Rollback byte mismatch: $name; keep stopped. Preserve $backup." >&2
        exit 1
      fi
    done
    sudo /usr/bin/systemctl start agentporter-development.service
  fi
  echo "Reactivation failed; retain evidence $backup. Do not rerun blindly." >&2
  exit "$rc"
}

[[ $preflight_sha =~ ^[0-9a-f]{64}$ ]]
[[ $(readlink /opt/agentporter-development/current) == "$old" ]]
[[ $(systemctl is-active agentporter-development.service) == active ]]
printf '%s  %s\n' c47044f4ca5bcd1558c8abe355dea949df7d571e370f162d51db1d118f619716 review-artifacts/a7dev-project-access-release-files.json | sha256sum --check --status
/usr/bin/python3 -I -B -c '
import hashlib,pathlib
p=pathlib.Path("/home/operator/agent-work/agentporter-dev/scripts/verify-existing-project-access-release.py")
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()=="0f71edb8aae7c5c3ffbd207f3ccfb44e3bab679dfda598ddad267e6b9071fbeb","Installed-payload checker changed"
exec(compile(b,str(p),"exec"),{"__name__":"__main__","__file__":str(p)})
'
printf '%s  %s\n' "$runtime_sha" "$runtime_template" | sha256sum --check --status
sudo -v
printf '%s  %s\n' 84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58 "$installer" | sudo /usr/bin/sha256sum --check --status
printf '%s  %s\n' e4bca398d91b8e0d95dec522d05c78ebe46081686376f109d12049929600c7d0 "$release/operator-plan/authorize-a7dev-project-delegation.py" | sudo /usr/bin/sha256sum --check --status
sudo /usr/bin/cat "$evidence/rollback.json" | /usr/bin/python3 -I -c '
import json,sys
assert json.load(sys.stdin)=={"release":"/opt/agentporter-development/versions/20261021T212000.000019Z","candidate":"20261021T232414.837654Z"},"Wrong installation rollback receipt"
'
sudo /usr/bin/cmp -s "$evidence/previous-runtime.yaml" "$config/development-runtime.yaml"
for name in development-runtime.yaml workspaces.yaml public-client-policy.yaml public-https.yaml; do
  sudo /usr/bin/cmp -s "$original_backup/$name" "$config/$name"
done
sudo /usr/bin/test ! -e "$backup"
sudo /usr/bin/test ! -L "$backup"
sudo /usr/bin/test ! -e "$runtime_temp"
sudo /usr/bin/test ! -L "$runtime_temp"
sudo /usr/bin/test ! -e "$link_temp"
sudo /usr/bin/test ! -L "$link_temp"
quiet
preflight --plan
production_before=$(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts)
production_release=$(readlink /home/operator/.local/share/agentporter/current)
sudo /usr/bin/install -d -o root -g root -m 0700 "$backup"
for name in development-runtime.yaml workspaces.yaml public-client-policy.yaml public-https.yaml; do
  sudo /usr/bin/cp --archive --no-dereference "$config/$name" "$backup/$name"
done
/usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
p="/home/operator/agent-work/agentporter-dev/docs/evidence/a7dev-project-access-20261021/retry-runtime-template.json"
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    s=os.fstat(fd)
    assert stat.S_ISREG(s.st_mode) and s.st_size<=1048576,"Unsafe inert runtime template"
    with os.fdopen(fd,"rb",closefd=False) as f: b=f.read(1048577)
finally: os.close(fd)
assert hashlib.sha256(b).hexdigest()=="fa33ac76062ce50e333a71d21310808bf6ea64658117da6224c6b4dab484a3fe","Runtime template changed"
sys.stdout.buffer.write(b)
' | sudo /usr/bin/tee "$backup/reviewed-runtime.json" >/dev/null
printf '%s  %s\n' "$runtime_sha" "$backup/reviewed-runtime.json" | sudo /usr/bin/sha256sum --check --status
printf '%s\n' "$production_before" | sudo /usr/bin/tee "$backup/production-before.txt" >/dev/null
trap recover ERR INT TERM
stopped=1
sudo /usr/bin/systemctl stop agentporter-development.service
quiet
sudo /usr/bin/cmp -s "$evidence/previous-runtime.yaml" "$config/development-runtime.yaml"
preflight --preserve-rolled-back-recovery | sudo /usr/bin/tee "$backup/preserved-policy-recovery.json"
restore_runtime "$backup/reviewed-runtime.json"
sudo /usr/bin/ln -s "$release" "$link_temp"
sudo /usr/bin/mv -T "$link_temp" /opt/agentporter-development/current
plan=$(policy --plan)
printf '%s\n' "$plan" | sudo /usr/bin/tee "$backup/project-access-plan.json"
[[ $(printf '%s' "$plan" | /usr/bin/python3 -I -c 'import json,sys; print(json.load(sys.stdin)["plan_sha256"])') == "$plan_sha" ]]
policy_attempted=1
policy --apply --expected-plan-sha256 "$plan_sha" | sudo /usr/bin/tee "$backup/project-access-apply.json"
sudo /usr/bin/systemctl start agentporter-development.service
ready=0
for attempt in {1..30}; do
  if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8876/health >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ $ready == 1 ]]
acceptance | sudo /usr/bin/tee "$backup/public-access-acceptance.log"
[[ $(systemctl --user show agentporter.service -p MainPID -p ActiveState -p NRestarts) == "$production_before" ]]
[[ $(readlink /home/operator/.local/share/agentporter/current) == "$production_release" ]]
stopped=0
trap - ERR INT TERM
echo "A7Dev project access/scope/negative checks passed. Evidence: $backup"
echo 'Existing protected traverse-only ACLs preserved; real Jax provider checks follow.'
acceptance --execute-jax | sudo /usr/bin/tee "$backup/jax-project-acceptance.log"
