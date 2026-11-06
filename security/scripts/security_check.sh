#!/usr/bin/env bash
# FraudShield AI - Automated Security Verification Master Script (Bash)
# Usage: ./security/scripts/security_check.sh

set -e

echo "================================================================="
echo "    [FRAUDSHIELD AI] AUTOMATED SECURITY CHECK & HARDENING AUDIT   "
echo "================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="python3"
if [ -f "backend/venv/bin/python" ]; then
    PYTHON_BIN="backend/venv/bin/python"
elif [ -f "backend/venv/Scripts/python.exe" ]; then
    PYTHON_BIN="backend/venv/Scripts/python.exe"
fi

# 1. SECRET SCAN
echo -e "\n>>> [STEP 1/4] Running Repository Secret & Credential Scan..."
bash "$SCRIPT_DIR/secret_scan.sh"

# 2. DEPENDENCY AUDIT
echo -e "\n>>> [STEP 2/4] Running Dependency Security Audit..."
bash "$SCRIPT_DIR/dependency_audit.sh"

# 3. SECURITY REGRESSION TEST SUITE
echo -e "\n>>> [STEP 3/4] Executing Security Regression Test Suite (46 Tests)..."
$PYTHON_BIN -m pytest security/tests -v

# 4. BACKEND INTEGRATION TEST SUITE
echo -e "\n>>> [STEP 4/4] Executing Backend Core Test Suite (17 Tests)..."
$PYTHON_BIN -m pytest backend/tests -v

echo -e "\n================================================================="
echo " [V] ALL SECURITY CHECKS PASSED (63/63 Tests Verified Clean) "
echo "================================================================="

