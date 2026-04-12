#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_agent_timeout.sh [package] [manager] [timeout_seconds]
#
# Examples:
#   ./run_agent_timeout.sh requests pip 120
#   ./run_agent_timeout.sh this-package-should-not-exist-xyz123 pip 60

PACKAGE_NAME="${1:-requests}"
MANAGER="${2:-pip}"
TIMEOUT_SECONDS="${3:-120}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

if ! command -v timeout >/dev/null 2>&1; then
  echo "ERROR: 'timeout' command not found. Install coreutils."
  exit 1
fi

if [[ ! -d "${ROOT}/.venv" ]]; then
  echo "ERROR: .venv not found in repo root."
  exit 1
fi

source "${ROOT}/.venv/bin/activate"

# Keep dependency-resolution failures fast/predictable during demos.
export PIP_DEFAULT_TIMEOUT="${PIP_DEFAULT_TIMEOUT:-10}"
export PIP_RETRIES="${PIP_RETRIES:-0}"
export HAZMAT_PACKAGE="${PACKAGE_NAME}"
export HAZMAT_MANAGER="${MANAGER}"

echo "Running Hazmat agent with timeout..."
echo "  package: ${HAZMAT_PACKAGE}"
echo "  manager: ${HAZMAT_MANAGER}"
echo "  timeout: ${TIMEOUT_SECONDS}s"
echo

# Exit code 124 indicates timeout.
timeout "${TIMEOUT_SECONDS}"s python3 -m hazmat_mcp.agent || {
  code=$?
  if [[ "${code}" -eq 124 ]]; then
    echo
    echo "Timed out after ${TIMEOUT_SECONDS}s."
    echo "Tip: increase timeout or use a smaller package test."
  fi
  exit "${code}"
}
