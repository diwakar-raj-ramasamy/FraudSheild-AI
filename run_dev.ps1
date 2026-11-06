# FraudShield AI - PowerShell Service Launcher & Control Center
# Usage: powershell -ExecutionPolicy Bypass -File .\run_dev.ps1

$ROOT = $PSScriptRoot
Set-Location $ROOT

function Show-Menu {
    Clear-Host
    Write-Host "=========================================================================" -ForegroundColor Cyan
    Write-Host "    [FRAUDSHIELD AI] PRODUCTION CONTROL CENTER & SERVICE LAUNCHER        " -ForegroundColor Cyan
    Write-Host "=========================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Start Backend API Server (FastAPI + Uvicorn on :8000)" -ForegroundColor White
    Write-Host "  [2] Start Admin SOC Dashboard (React + Vite on :5173)" -ForegroundColor White
    Write-Host "  [3] Run Complete Automated Test Suite (77 Tests)" -ForegroundColor White
    Write-Host "  [4] Run Concurrency Load & Stress Benchmark" -ForegroundColor White
    Write-Host "  [5] Apply Database Migrations (Alembic Upgrade Head)" -ForegroundColor White
    Write-Host "  [6] Start Full Stack via Docker Compose (PostgreSQL, Redis, API, UI)" -ForegroundColor White
    Write-Host "  [7] Stop Docker Compose Services" -ForegroundColor White
    Write-Host "  [8] Open Documentation & Health Probes in Browser" -ForegroundColor White
    Write-Host "  [9] Exit" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "=========================================================================" -ForegroundColor Cyan
}

do {
    Show-Menu
    $choice = Read-Host "Enter your selection [1-9]"
    switch ($choice) {
        "1" {
            Clear-Host
            Write-Host "Starting Backend API on http://localhost:8000 ..." -ForegroundColor Green
            Set-Location "$ROOT\backend"
            & ".\venv\Scripts\Activate.ps1"
            python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
            Pause
        }
        "2" {
            Clear-Host
            Write-Host "Starting Admin SOC Dashboard on http://localhost:5173 ..." -ForegroundColor Green
            Set-Location "$ROOT\admin-dashboard"
            npm run dev
            Pause
        }
        "3" {
            Clear-Host
            Write-Host "Executing Full Automated Test Suite (77 Tests)..." -ForegroundColor Green
            Set-Location $ROOT
            & "backend\venv\Scripts\python.exe" -m pytest security\tests backend\tests -v
            Pause
        }
        "4" {
            Clear-Host
            Write-Host "Running Concurrency Load & Stress Benchmark..." -ForegroundColor Green
            Set-Location $ROOT
            & "backend\venv\Scripts\python.exe" backend\load_tests\async_load_runner.py
            Pause
        }
        "5" {
            Clear-Host
            Write-Host "Applying Database Migrations to Head..." -ForegroundColor Green
            Set-Location "$ROOT\backend"
            & ".\venv\Scripts\Activate.ps1"
            alembic upgrade head
            Write-Host "`nDatabase schema is at HEAD." -ForegroundColor Green
            Pause
        }
        "6" {
            Clear-Host
            Write-Host "Launching Production Stack via Docker Compose..." -ForegroundColor Green
            Set-Location $ROOT
            if (-Not (Test-Path ".env")) {
                Copy-Item ".env.example" ".env"
                Write-Host "Generated .env from .env.example." -ForegroundColor Yellow
            }
            docker compose up -d --build
            docker compose ps
            Pause
        }
        "7" {
            Clear-Host
            Write-Host "Stopping Docker Compose Services..." -ForegroundColor Yellow
            Set-Location $ROOT
            docker compose down
            Pause
        }
        "8" {
            Start-Process "http://localhost:8000/docs"
            Start-Process "http://localhost:8000/health/ready"
            Start-Process "http://localhost:5173"
        }
        "9" {
            break
        }
        Default {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne "9")

