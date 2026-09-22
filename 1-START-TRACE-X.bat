@echo off
setlocal
cd /d "%~dp0"
title TRACE-X Offline Demo

echo ========================================
echo   TRACE-X - Starting Offline Demo
echo ========================================
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] TRACE-X is not set up in this folder.
    echo Run setup.bat first, then try again.
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

echo Opening the local demo at http://127.0.0.1:8765/
echo Keep this window open while using TRACE-X.
echo Press Ctrl+C here when you want to stop it.
echo.
python demo.py

if errorlevel 1 (
    echo.
    echo [ERROR] TRACE-X stopped with an error.
    pause
)
