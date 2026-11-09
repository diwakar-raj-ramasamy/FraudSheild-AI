@echo off
title FraudShield AI - Platform Launcher
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_dev.ps1"

