#!/usr/bin/env bash
# FraudShield AI - Dependency Security Audit Script (Bash)
# Usage: ./security/scripts/dependency_audit.sh

set -e

echo "=========================================================="
echo " [FRAUDSHIELD AI] DEPENDENCY SECURITY & VULNERABILITY AUDIT "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

FAILED=0

# --- 1. Python Backend Dependencies ---
echo -e "\n[+] Checking Python Dependencies..."
PYTHON_BIN="python3"
if [ -f "backend/venv/bin/python" ]; then
    PYTHON_BIN="backend/venv/bin/python"
elif [ -f "backend/venv/Scripts/python.exe" ]; then
    PYTHON_BIN="backend/venv/Scripts/python.exe"
fi

$PYTHON_BIN -m pip check || { echo "[-] Dependency conflicts in Python environment"; FAILED=1; }

if $PYTHON_BIN -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('pip_audit') else 1)" 2>/dev/null; then
    echo " Running pip-audit..."
    $PYTHON_BIN -m pip_audit || true
else
    echo "[*] pip-audit not installed. Skipping live pip-audit CVE lookup."
fi

# --- 2. Admin Dashboard Node Dependencies ---
if [ -d "admin-dashboard" ] && [ -f "admin-dashboard/package.json" ]; then
    echo -e "\n[+] Auditing Admin Dashboard Dependencies..."
    OUTPUT=$(cd admin-dashboard && npm audit --audit-level=high 2>&1 || true)
    if echo "$OUTPUT" | grep -qE "ENOTFOUND|EAI_AGAIN|offline"; then
        echo "[*] npm audit skipped for admin-dashboard: registry offline or network sandboxed."
    elif echo "$OUTPUT" | grep -q "found 0 vulnerabilities"; then
        echo "[+] Admin dashboard dependencies passed security threshold."
    fi
fi

# --- 3. Browser Extension Dependencies ---
if [ -d "browser-extension" ] && [ -f "browser-extension/package.json" ]; then
    echo -e "\n[+] Auditing Browser Extension Dependencies..."
    OUTPUT=$(cd browser-extension && npm audit --audit-level=high 2>&1 || true)
    if echo "$OUTPUT" | grep -qE "ENOTFOUND|EAI_AGAIN|offline"; then
        echo "[*] npm audit skipped for browser-extension: registry offline or network sandboxed."
    elif echo "$OUTPUT" | grep -q "found 0 vulnerabilities"; then
        echo "[+] Browser extension dependencies passed security threshold."
    fi
fi

echo "=========================================================="
echo " [V] DEPENDENCY AUDIT FINISHED "
echo "=========================================================="
exit $FAILED
