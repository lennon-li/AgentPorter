#!/usr/bin/env bash
# Host-only, read-only verification gate for the AgentPorter development candidate.
# No sudo, network, commits, service changes, or production deployment.
set -euo pipefail
for acl_tool in getfacl setfacl; do
  command -v "$acl_tool" >/dev/null || { echo "ERROR: install distro acl package ($acl_tool missing)" >&2; exit 2; }
done
cd "$(dirname "$0")/.."
python_bin="$PWD/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  echo "ERROR: development Python 3.13 environment not installed" >&2
  exit 2
fi
"$python_bin" -I -c 'import sys; assert sys.version_info[:2] == (3, 13), sys.version'
export PYTHONDONTWRITEBYTECODE=1
"$python_bin" -m pytest -q tests/
"$python_bin" -B tests/verify_scoped_https_offline.py
"$python_bin" -B tests/verify_https_integration_offline.py
"$python_bin" -B tests/verify_https_audit_regressions.py
"$python_bin" -B tests/verify_production_relay_offline.py
"$python_bin" -B tests/verify_worker_credential_refresh_offline.py
"$python_bin" -B tests/verify_shared_agent_resources_offline.py
echo "PASS: complete development candidate verification"
