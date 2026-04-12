#!/usr/bin/env bash
set -euo pipefail

# Deterministic integration hardening checks for Step 7:
# 1) manager mismatch
# 2) nonexistent package (timeout-enforced path)
# 3) malicious local payload detection

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"
export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:$PYTHONPATH}"

if [[ ! -d ".venv" ]]; then
  echo "ERROR: .venv not found. Create and install dependencies first."
  exit 1
fi

source ".venv/bin/activate"

OUT_DIR="${ROOT_DIR}/.tmp_step7"
mkdir -p "${OUT_DIR}"

echo "== Step 7 hardening checks =="
echo

echo "[1/3] Manager mismatch test (npm package via pip)"
python3 -m hazmat_mcp.cli --manager pip --package lodash --raw-json > "${OUT_DIR}/manager_mismatch.json"
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path(".tmp_step7/manager_mismatch.json").read_text())
fv = data.get("final_verdict", {})
pre = data.get("precheck", {})
assert fv.get("verdict") == "suspicious", f"expected suspicious, got {fv.get('verdict')}"
assert fv.get("risk_level") == "medium", f"expected medium, got {fv.get('risk_level')}"
assert pre.get("suspected") is True, "expected manager mismatch precheck suspected=true"
print("PASS: manager mismatch classified as suspicious/medium with precheck signal.")
PY
echo

echo "[2/3] Nonexistent package test (timeout runner path)"
set +e
"${ROOT_DIR}/run_agent_timeout.sh" this-package-should-not-exist-xyz123 pip 75 > "${OUT_DIR}/nonexistent.log" 2>&1
status=$?
set -e
if [[ "${status}" -eq 124 ]]; then
  echo "FAIL: timeout hit unexpectedly for nonexistent package test."
  exit 1
fi
python3 - <<'PY'
import json
import re
from pathlib import Path

text = Path(".tmp_step7/nonexistent.log").read_text()
m = re.search(r"\{.*\}\s*$", text, flags=re.DOTALL)
assert m, "could not find JSON output from agent in timeout-runner log"
payload = json.loads(m.group(0))
install = payload.get("install_response", {})
assert install.get("ok") is False or (install.get("install") or {}).get("exit_code") != 0, "expected install failure signal"
print("PASS: nonexistent package failed gracefully through timeout runner.")
PY
echo

echo "[3/3] Malicious local payload detection (.tgz)"
python3 -m hazmat_mcp.cli \
  --manager npm \
  --package-source "${ROOT_DIR}/tests/demo_packages/react-helper-dom/react-helper-dom-1.0.0.tgz" \
  --raw-json > "${OUT_DIR}/malicious_tgz.json"
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path(".tmp_step7/malicious_tgz.json").read_text())
fv = data.get("final_verdict", {})
tele = (data.get("telemetry_response") or {}).get("telemetry", {})
risk = str(fv.get("risk_level", "")).lower()
alerts = tele.get("alerts") or []
assert risk in {"high", "critical", "medium"}, f"unexpected low risk for malicious payload: {risk}"
assert len(alerts) > 0, "expected telemetry alerts for malicious payload"
print(f"PASS: malicious payload flagged with risk={risk}, alerts={len(alerts)}.")
PY
echo

echo "All Step 7 hardening checks passed."
