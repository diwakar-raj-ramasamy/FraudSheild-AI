@echo off
title FraudShield AI - Service Launcher & Control Center
color 0B

:MENU
cls
echo =========================================================================
echo    [FRAUDSHIELD AI] PRODUCTION CONTROL CENTER & SERVICE LAUNCHER
echo =========================================================================
echo.
echo   [1] Start Backend API Server (FastAPI + Uvicorn on :8000)
echo   [2] Start Admin SOC Dashboard (React + Vite on :5173)
echo   [3] Run Complete Automated Test Suite (77 Tests)
echo   [4] Run Concurrency Load & Stress Benchmark
echo   [5] Apply Database Migrations (Alembic Upgrade Head)
echo   [6] Start Full Stack via Docker Compose (PostgreSQL, Redis, API, UI)
echo   [7] Stop Docker Compose Services
echo   [8] Open Documentation & Health Probes in Browser
echo   [9] Exit
echo.
echo =========================================================================
set /p choice="Enter your selection [1-9]: "

if "%choice%"=="1" goto START_BACKEND
if "%choice%"=="2" goto START_DASHBOARD
if "%choice%"=="3" goto RUN_TESTS
if "%choice%"=="4" goto RUN_LOAD_TEST
if "%choice%"=="5" goto RUN_MIGRATIONS
if "%choice%"=="6" goto START_DOCKER
if "%choice%"=="7" goto STOP_DOCKER
if "%choice%"=="8" goto OPEN_BROWSER
if "%choice%"=="9" goto EXIT

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto MENU

:START_BACKEND
cls
echo Starting FraudShield AI Backend API on http://localhost:8000 ...
cd /d "%~dp0backend"
call venv\Scripts\activate.bat
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
pause
goto MENU

:START_DASHBOARD
cls
echo Starting FraudShield AI Admin SOC Dashboard on http://localhost:5173 ...
cd /d "%~dp0admin-dashboard"
npm run dev
pause
goto MENU

:RUN_TESTS
cls
echo Executing Full Automated Test Suite (77 Tests)...
cd /d "%~dp0"
backend\venv\Scripts\python.exe -m pytest security\tests backend\tests -v
echo.
pause
goto MENU

:RUN_LOAD_TEST
cls
echo Running Concurrency Load and Stress Benchmark...
cd /d "%~dp0"
backend\venv\Scripts\python.exe backend\load_tests\async_load_runner.py
echo.
pause
goto MENU

:RUN_MIGRATIONS
cls
echo Applying Database Migrations to Head...
cd /d "%~dp0backend"
call venv\Scripts\activate.bat
alembic upgrade head
echo.
echo Database schema is at HEAD.
pause
goto MENU

:START_DOCKER
cls
echo Launching Production Stack via Docker Compose...
cd /d "%~dp0"
if not exist .env (
    echo Generating .env from .env.example...
    copy .env.example .env
)
docker compose up -d --build
echo.
docker compose ps
pause
goto MENU

:STOP_DOCKER
cls
echo Stopping Docker Compose Services...
cd /d "%~dp0"
docker compose down
pause
goto MENU

:OPEN_BROWSER
cls
echo Opening Swagger UI & Admin Dashboard...
start http://localhost:8000/docs
start http://localhost:8000/health/ready
start http://localhost:5173
goto MENU

:EXIT
exit /b 0

