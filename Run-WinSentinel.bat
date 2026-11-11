@echo off
:: ==============================================================================
:: WinSentinel - Self-Elevating Windows Hardening Launcher
:: ==============================================================================
title WinSentinel Launcher

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrative Privileges for WinSentinel...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k `"%~f0`"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinSentinel.ps1"
echo.
pause
