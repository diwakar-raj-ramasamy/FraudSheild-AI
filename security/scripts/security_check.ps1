# FraudShield AI - Automated Security Verification Master Script (PowerShell)
# Usage: powershell -ExecutionPolicy Bypass -File security/scripts/security_check.ps1

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "    [FRAUDSHIELD AI] AUTOMATED SECURITY CHECK & HARDENING AUDIT   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$ROOT_DIR = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $ROOT_DIR

$FAILED_STEPS = @()

# 1. SECRET SCAN
Write-Host "`n>>> [STEP 1/4] Running Repository Secret & Credential Scan..." -ForegroundColor Yellow
& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\secret_scan.ps1"
if ($LASTEXITCODE -ne 0) {
    $FAILED_STEPS += "Secret Scan"
    Write-Host "[-] STEP 1 FAILED: Hardcoded credentials or private keys detected." -ForegroundColor Red
} else {
    Write-Host "[+] STEP 1 PASSED: Repository clean of hardcoded secrets." -ForegroundColor Green
}

# 2. DEPENDENCY AUDIT
Write-Host "`n>>> [STEP 2/4] Running Dependency Security Audit..." -ForegroundColor Yellow
& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\dependency_audit.ps1"
if ($LASTEXITCODE -ne 0) {
    $FAILED_STEPS += "Dependency Audit"
    Write-Host "[-] STEP 2 FAILED: Dependency security conflicts or high-severity CVEs." -ForegroundColor Red
} else {
    Write-Host "[+] STEP 2 PASSED: Dependencies meet security baseline." -ForegroundColor Green
}

# 3. SECURITY REGRESSION TEST SUITE
Write-Host "`n>>> [STEP 3/4] Executing Security Regression Test Suite (46 Tests)..." -ForegroundColor Yellow
$PYTHON_BIN = "backend\venv\Scripts\python.exe"
if (-Not (Test-Path $PYTHON_BIN)) {
    $PYTHON_BIN = "python"
}

& $PYTHON_BIN -m pytest security\tests -v
if ($LASTEXITCODE -ne 0) {
    $FAILED_STEPS += "Security Regression Tests"
    Write-Host "[-] STEP 3 FAILED: Security regression tests failed!" -ForegroundColor Red
} else {
    Write-Host "[+] STEP 3 PASSED: All 46 security regression test cases passed." -ForegroundColor Green
}

# 4. BACKEND INTEGRATION TEST SUITE
Write-Host "`n>>> [STEP 4/4] Executing Backend Core Test Suite (17 Tests)..." -ForegroundColor Yellow
& $PYTHON_BIN -m pytest backend\tests -v
if ($LASTEXITCODE -ne 0) {
    $FAILED_STEPS += "Backend Core Tests"
    Write-Host "[-] STEP 4 FAILED: Backend core tests failed!" -ForegroundColor Red
} else {
    Write-Host "[+] STEP 4 PASSED: All 17 backend unit and integration test cases passed." -ForegroundColor Green
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
if ($FAILED_STEPS.Count -eq 0) {
    Write-Host " [V] ALL SECURITY CHECKS PASSED (63/63 Tests Verified Clean) " -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " [X] SECURITY VERIFICATION FAILED: $($FAILED_STEPS -join ', ') " -ForegroundColor Red
    Write-Host "=================================================================" -ForegroundColor Cyan
    exit 1
}

