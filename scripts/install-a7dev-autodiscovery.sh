#!/usr/bin/env bash
# User-run installer: root never executes mutable repository code.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly repo=/home/yeli/agent-work/agentporter-dev
readonly target=/opt/agentporter-autodiscovery
[[ $(id -un) == yeli && $(id -u) != 0 ]] || { echo 'Run as yeli, not root.' >&2; exit 1; }
cd "$repo"
readonly helper_sha=3992c76db55e32e6fc2a8b1614b8ff6a161ffde93672315d3230b83eb5e35050
readonly service_sha=44c809c3b10bdf93921b5f23b656098cfaab3f9eb1526e24c44e19a5045b2e1e
readonly timer_sha=0104f6620fd60e7dd4e74c3375473538a09cceb96fae146415952907dda4a9eb
readonly repair_sha=c877cfe7a3f3e82567c1fec5f4f8e395d12a3f936d978e38ef96f8171b4c6614
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
  /opt/agentporter-development/versions/20261022T015212.581522Z) ;;
  *) echo 'Unreviewed A7Dev release; refuse installation.' >&2; exit 1 ;;
esac
[[ $(readlink -f /opt/agentporter-development/current) == /opt/agentporter-development/versions/20261022T015212.581522Z ]]
# Verify required system dependencies without importing user/project modules.
/usr/bin/python3 -I -c 'import yaml, sqlite3'
command -v setfacl >/dev/null
command -v getfacl >/dev/null
# Never replace helper code while its timer could launch a new process.
sudo /usr/bin/systemctl stop agentporter-dev-autodiscovery.timer 2>/dev/null || {
  sudo /usr/bin/systemctl is-enabled agentporter-dev-autodiscovery.timer >/dev/null 2>&1 && exit 1
  :
}
sudo /usr/bin/systemctl is-active --quiet agentporter-dev-autodiscovery.service && {
  echo 'Discovery reconciliation currently running; wait and retry.' >&2; exit 1;
}
sudo /usr/bin/install -d -o root -g root -m 0755 "$target"
sudo /usr/bin/install -d -o root -g root -m 0700 /var/lib/agentporter-dev-autodiscovery
install_pinned() {
  local source=$1 destination=$2 expected=$3
  check_user_file "$source" "$expected"
  # Redirection is opened by yeli. Root reads this already-open input stream,
  # never a repository pathname that could be exchanged for a privileged file.
  sudo /usr/bin/install -T -o root -g root -m 0644 /dev/stdin "$destination" < "$source"
  printf '%s  %s\n' "$expected" "$destination" | sudo /usr/bin/sha256sum --check --status
}
install_pinned scripts/autodiscover-a7dev.py "$target/autodiscover-a7dev.py" "$helper_sha"
install_pinned scripts/agentporter-dev-autodiscovery.service /etc/systemd/system/agentporter-dev-autodiscovery.service "$service_sha"
install_pinned scripts/agentporter-dev-autodiscovery.timer /etc/systemd/system/agentporter-dev-autodiscovery.timer "$timer_sha"
sudo /usr/bin/python3 -I "$target/autodiscover-a7dev.py"
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl start agentporter-dev-autodiscovery.service
sudo /usr/bin/systemctl enable --now agentporter-dev-autodiscovery.timer
sudo /usr/bin/systemctl status --no-pager agentporter-dev-autodiscovery.timer
