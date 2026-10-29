#!/usr/bin/env bash
# User-run installer: root never executes mutable repository code.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly repo=/home/operator/agent-work/agentporter-dev
readonly target=/opt/agentporter-autodiscovery
[[ $(id -un) == operator && $(id -u) != 0 ]] || { echo 'Run as operator, not root.' >&2; exit 1; }
cd "$repo"
readonly helper_sha=451ce8829193fbf3e0ee3a223ae3593903aaf90479fa0a92bb1709874c5c668c
readonly service_sha=8995fb99ac8800005c2979d32588a3c3db51d6fdf887b8c71f53ea426af916f9
readonly timer_sha=0104f6620fd60e7dd4e74c3375473538a09cceb96fae146415952907dda4a9eb
readonly repair_sha=d44593917b8345da7a850df9ae86da6a8f61e5be46e9fc9d213a4dd6f743501b
check_user_file() {
  [[ -f $1 && ! -L $1 ]] || return 1
  printf '%s  %s\n' "$2" "$1" | sha256sum --check --status
}
check_user_file scripts/autodiscover-a7dev.py "$helper_sha"
check_user_file scripts/agentporter-dev-autodiscovery.service "$service_sha"
check_user_file scripts/agentporter-dev-autodiscovery.timer "$timer_sha"
sudo -v
# This runner pins the previous static registry, so it MUST precede discovery.
case $(readlink -f /opt/agentporter-development/current) in
  /opt/agentporter-development/versions/20261021T232414.837654Z)
    check_user_file scripts/install-a7dev-acquisition-repair.sh "$repair_sha"
    /bin/bash scripts/install-a7dev-acquisition-repair.sh
    ;;
  /opt/agentporter-development/versions/20261022T015212.581522Z|/opt/agentporter-development/versions/20261022T165047.488565Z|/opt/agentporter-development/versions/20261022T181133.685266Z) ;;
  *) echo 'Unreviewed A7Dev release; refuse installation.' >&2; exit 1 ;;
esac
case $(readlink -f /opt/agentporter-development/current) in
  /opt/agentporter-development/versions/20261022T015212.581522Z|/opt/agentporter-development/versions/20261022T165047.488565Z|/opt/agentporter-development/versions/20261022T181133.685266Z) ;;
  *) echo 'A7Dev release changed during preflight; refuse installation.' >&2; exit 1 ;;
esac
# Verify required system dependencies without importing user/project modules.
/usr/bin/python3 -I -c 'import yaml, sqlite3'
command -v setfacl >/dev/null
command -v getfacl >/dev/null
# Never replace helper code while its timer could launch a new process.
sudo /usr/bin/systemctl stop agentporter-dev-autodiscovery.timer 2>/dev/null || {
  sudo /usr/bin/systemctl is-enabled agentporter-dev-autodiscovery.timer >/dev/null 2>&1 && exit 1
  :
}
case $(sudo /usr/bin/systemctl show --value --property=ActiveState agentporter-dev-autodiscovery.service) in
  inactive|failed) ;;
  *) echo 'Discovery reconciliation active or changing; leave timer stopped and retry when quiet.' >&2; exit 1 ;;
esac
sudo /usr/bin/install -d -o root -g root -m 0755 "$target"
sudo /usr/bin/install -d -o root -g root -m 0700 /var/lib/agentporter-dev-autodiscovery
install_pinned() {
  local source=$1 destination=$2 expected=$3 private_stage
  check_user_file "$source" "$expected"
  private_stage=$(sudo /usr/bin/mktemp -d "$target/.verified-source.XXXXXXXX")
  # Read/hash bounded regular input as operator; root never opens a mutable source.
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
' "$source" "$expected" | sudo /usr/bin/install -T -o root -g root -m 0600 /dev/stdin "$private_stage/input"
  printf '%s  %s\n' "$expected" "$private_stage/input" | sudo /usr/bin/sha256sum --check --status
  sudo /usr/bin/install -T -o root -g root -m 0644 "$private_stage/input" "$destination"
  printf '%s  %s\n' "$expected" "$destination" | sudo /usr/bin/sha256sum --check --status
  sudo /usr/bin/unlink "$private_stage/input"
  sudo /usr/bin/rmdir "$private_stage"
}
install_pinned scripts/autodiscover-a7dev.py "$target/autodiscover-a7dev.py" "$helper_sha"
install_pinned scripts/agentporter-dev-autodiscovery.service /etc/systemd/system/agentporter-dev-autodiscovery.service "$service_sha"
install_pinned scripts/agentporter-dev-autodiscovery.timer /etc/systemd/system/agentporter-dev-autodiscovery.timer "$timer_sha"
sudo /usr/bin/python3 -I "$target/autodiscover-a7dev.py"
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl start agentporter-dev-autodiscovery.service
sudo /usr/bin/systemctl enable --now agentporter-dev-autodiscovery.timer
sudo /usr/bin/systemctl status --no-pager agentporter-dev-autodiscovery.timer
