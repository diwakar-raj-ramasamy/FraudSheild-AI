#!/usr/bin/env bash
# FraudShield AI - Secret and Credential Scanner (Bash)
# Usage: ./security/scripts/secret_scan.sh

set -e

echo "=========================================================="
echo " [FRAUDSHIELD AI] REPOSITORY SECRET & CREDENTIAL SCANNER "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python3"
if [ -f "$SCRIPT_DIR/../../backend/venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/../../backend/venv/bin/python"
elif [ -f "$SCRIPT_DIR/../../backend/venv/Scripts/python.exe" ]; then
    PYTHON_BIN="$SCRIPT_DIR/../../backend/venv/Scripts/python.exe"
fi

$PYTHON_BIN "$SCRIPT_DIR/scanner_core.py"

