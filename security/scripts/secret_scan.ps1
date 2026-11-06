# FraudShield AI - Secret and Credential Scanner (PowerShell)
# Usage: powershell -ExecutionPolicy Bypass -File security/scripts/secret_scan.ps1

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [FRAUDSHIELD AI] REPOSITORY SECRET & CREDENTIAL SCANNER " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$PYTHON_BIN = "backend\venv\Scripts\python.exe"
if (-Not (Test-Path $PYTHON_BIN)) {
    $PYTHON_BIN = "python"
}

$SCANNER_PY = "$PSScriptRoot\scanner_core.py"
& $PYTHON_BIN $SCANNER_PY
exit $LASTEXITCODE

