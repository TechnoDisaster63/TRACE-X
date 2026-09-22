@echo off
setlocal
cd /d "%~dp0"
title TRACE-X

echo ========================================
echo   TRACE-X - Email Threat Analysis
echo ========================================
echo.

REM ---- 1. One-click bootstrap: find Python ----
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    echo Install Python 3.11+ from https://www.python.org/downloads/
    echo and check "Add python.exe to PATH" during install.
    echo.
    pause
    exit /b 1
)

REM ---- 2. Create the virtual environment on first run ----
if not exist ".venv\Scripts\python.exe" (
    echo First run: creating the TRACE-X environment ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create the virtual environment.
        echo.
        pause
        exit /b 1
    )
    set "TRACE_X_FRESH=1"
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Could not activate the TRACE-X environment.
    echo.
    pause
    exit /b 1
)

REM ---- 3. Install dependencies on first run (offline afterwards) ----
if "%TRACE_X_FRESH%"=="1" (
    echo Installing dependencies (one-time, needs internet) ...
    python -m pip install --upgrade pip >nul 2>nul
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo Installing optional offline ML runtime (best effort) ...
    python -m pip install -r requirements-ml.txt >nul 2>nul
    if errorlevel 1 (
        echo [NOTE] Optional ML runtime not installed. TRACE-X still runs;
        echo        the M18 advisory signal will report itself unavailable.
    )
    if not exist "output" mkdir output
    if not exist "reports" mkdir reports
    python -c "import sys; sys.path.insert(0, '.'); from core.pipeline import analyze_email; print('[OK] TRACE-X is ready')"
    if errorlevel 1 (
        echo [ERROR] Installation check failed.
        echo.
        pause
        exit /b 1
    )
    echo.
)

REM ---- 4. No arguments: launch the demo console ----
if "%~1"=="" goto :demo
if /i "%~1"=="demo" goto :demo
if /i "%~1"=="test" goto :test
goto :cli

:demo
echo Starting TRACE-X. Your browser will open automatically.
echo In the page: choose a bundled scenario or a .eml file, then click RUN ANALYSIS.
echo Keep this window open while using TRACE-X.
echo Press Ctrl+C here when you want to stop.
echo.
python demo.py
if errorlevel 1 (
    echo.
    echo [ERROR] TRACE-X stopped with an error.
    pause
)
exit /b %errorlevel%

:test
python -m pytest tests\ -v
pause
exit /b %errorlevel%

:cli
python cli.py %*
pause
exit /b %errorlevel%
