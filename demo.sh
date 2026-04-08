#!/bin/bash
#
# Hazmat Live Demo Script
# Demonstrates malicious package detection in action
#
# Usage: chmod +x demo.sh && ./demo.sh
#

set -e

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAZMAT_CLI="${DEMO_DIR}/hazmat_cli.py"

echo "=================================="
echo "  HAZMAT LIVE DEMO"
echo "  Dynamic Package Security Scanner"
echo "=================================="
echo ""

# Ensure Python path is set
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "ERROR: npm not found. Please install Node.js"
    exit 1
fi

# Check if we need to start the mock server
MOCK_SERVER_PID=""
if lsof -Pi :9999 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "[INFO] Mock server already listening on port 9999"
else
    echo "[INFO] Starting mock server on localhost:9999..."
    python3 "${DEMO_DIR}/mock_server.py" >/dev/null 2>&1 &
    MOCK_SERVER_PID=$!
    sleep 1
    echo "[OK] Mock server started (PID: $MOCK_SERVER_PID)"
fi

echo ""
echo "---------------------------------------"
echo "TEST 1: BENIGN PACKAGE (Clean Result)"
echo "---------------------------------------"
echo ""
echo "Scanning: test_packages/benign_pkg (simple string utilities)"
echo "Expected: GREEN verdict, LOW risk"
echo ""
python3 "${HAZMAT_CLI}" \
    --manager npm \
    --package ./test_packages/benign_pkg \
    || true

echo ""
echo "---------------------------------------"
echo "TEST 2: MALICIOUS PACKAGE (Red Alert)"
echo "---------------------------------------"
echo ""
echo "Scanning: test_packages/malicious_pkg (simulates credential harvesting)"
echo "Expected: RED verdict, CRITICAL risk, multiple alerts"
echo ""
python3 "${HAZMAT_CLI}" \
    --manager npm \
    --package ./test_packages/malicious_pkg \
    --verbose \
    || true

echo ""
echo "---------------------------------------"
echo "Demo Complete"
echo "---------------------------------------"
echo ""

# Cleanup mock server if we started it
if [ -n "$MOCK_SERVER_PID" ]; then
    echo "[INFO] Cleaning up mock server..."
    kill $MOCK_SERVER_PID 2>/dev/null || true
fi

echo "Evidence files saved to /tmp/hazmat/ for inspection"
ls -la /tmp/hazmat/ 2>/dev/null || echo "(No evidence directory yet)"
