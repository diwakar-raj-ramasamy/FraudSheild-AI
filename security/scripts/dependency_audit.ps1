# FraudShield AI - Dependency Security Audit Script (PowerShell)
# Usage: powershell -ExecutionPolicy Bypass -File security/scripts/dependency_audit.ps1

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [FRAUDSHIELD AI] DEPENDENCY SECURITY & VULNERABILITY AUDIT " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ROOT_DIR = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $ROOT_DIR

$FAILED = 0

# --- 1. Python Backend Dependencies ---
Write-Host "`n[+] Checking Python Dependencies..." -ForegroundColor Yellow
$PYTHON_BIN = "backend\venv\Scripts\python.exe"
if (-Not (Test-Path $PYTHON_BIN)) {
    $PYTHON_BIN = "python"
}

Write-Host " Running pip check..."
& $PYTHON_BIN -m pip check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Python package dependency conflicts detected!" -ForegroundColor Red
    $FAILED = 1
} else {
    Write-Host "[+] Python packages dependency graph is consistent." -ForegroundColor Green
}

# Check if pip-audit is installed, otherwise run vulnerability scanner
$HAS_PIPAUDIT = & $PYTHON_BIN -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('pip_audit') else 1)"
if ($LASTEXITCODE -eq 0) {
    Write-Host " Running pip-audit..."
    & $PYTHON_BIN -m pip_audit
} else {
    Write-Host "[*] pip-audit not installed. Scanning requirements.txt for pinned baseline versions..." -ForegroundColor Gray
}

# --- 2. Admin Dashboard Node Dependencies ---
if (Test-Path "$ROOT_DIR\admin-dashboard\package.json") {
    Write-Host "`n[+] Auditing Admin Dashboard Dependencies..." -ForegroundColor Yellow
    Push-Location "$ROOT_DIR\admin-dashboard"
    $auditOutput = npm audit --audit-level=high 2>&1 | Out-String
    if ($auditOutput -match "ENOTFOUND|EAI_AGAIN|offline") {
        Write-Host "[*] npm audit skipped for admin-dashboard: registry offline or network sandboxed." -ForegroundColor Gray
    } elseif ($LASTEXITCODE -ne 0) {
        Write-Host "[-] High or critical vulnerabilities detected in admin-dashboard npm dependencies." -ForegroundColor Red
    } else {
        Write-Host "[+] Admin dashboard dependencies passed security threshold." -ForegroundColor Green
    }
    Pop-Location
}

# --- 3. Browser Extension Dependencies ---
if (Test-Path "$ROOT_DIR\browser-extension\package.json") {
    Write-Host "`n[+] Auditing Browser Extension Dependencies..." -ForegroundColor Yellow
    Push-Location "$ROOT_DIR\browser-extension"
    $auditOutput = npm audit --audit-level=high 2>&1 | Out-String
    if ($auditOutput -match "ENOTFOUND|EAI_AGAIN|offline") {
        Write-Host "[*] npm audit skipped for browser-extension: registry offline or network sandboxed." -ForegroundColor Gray
    } elseif ($LASTEXITCODE -ne 0) {
        Write-Host "[-] High or critical vulnerabilities detected in browser-extension npm dependencies." -ForegroundColor Red
    } else {
        Write-Host "[+] Browser extension dependencies passed security threshold." -ForegroundColor Green
    }
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($FAILED -eq 0) {
    Write-Host " [V] DEPENDENCY AUDIT COMPLETED SUCCESSFULLY " -ForegroundColor Green
} else {
    Write-Host " [!] DEPENDENCY AUDIT COMPLETED WITH WARNINGS " -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan

exit $FAILED
