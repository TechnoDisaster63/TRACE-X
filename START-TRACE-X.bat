@echo off
setlocal
cd /d "%~dp0"
title TRACE-X

echo ========================================
echo   TRACE-X - Email Threat Analysis
echo ========================================
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] TRACE-X is not set up in this folder.
    echo Run setup.bat first, then double-click this file again.
    echo.
    pause
    exit /b 1
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Could not activate the TRACE-X environment.
    echo.
    pause
    exit /b 1
)

echo Starting TRACE-X. Your browser will open automatically.
echo In the page: choose a .eml file, then click RUN ANALYSIS.
echo Keep this window open while using TRACE-X.
echo Press Ctrl+C here when you want to stop.
echo.
python demo.py

if errorlevel 1 (
    echo.
    echo [ERROR] TRACE-X stopped with an error.
    pause
)
