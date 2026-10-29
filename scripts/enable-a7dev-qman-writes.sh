#!/usr/bin/env bash
# Compatibility launcher for the explicitly authorized Qman-only grant.
set -euo pipefail
exec /bin/bash "$(dirname "${BASH_SOURCE[0]}")/enable-a7dev-workspace-writes.sh" --qman
