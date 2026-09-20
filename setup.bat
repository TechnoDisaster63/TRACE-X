@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo TRACE-X - Setup (M01-M08 Prototype)
echo ============================================================
echo.

REM ---- 1. Check Python exists ----
where python >nul 2>nul
if errorlevel 1 (
    echo [FAILURE] Python was not found on PATH.
    echo Please install Python 3.11+ from https://www.python.org/downloads/
    echo and ensure "Add python.exe to PATH" is checked during install.
    goto :fail
)

echo [OK] Python found. Version:
python --version
echo.

REM ---- 2. Create virtual environment if missing ----
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment in .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [FAILURE] Failed to create virtual environment.
        goto :fail
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)
echo.

REM ---- 3. Activate virtual environment ----
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [FAILURE] Failed to activate virtual environment.
    goto :fail
)
echo [OK] Virtual environment activated.
echo.

REM ---- 4. Upgrade pip ----
echo Upgrading pip ...
python -m pip install --upgrade pip >nul
if errorlevel 1 (
    echo [WARNING] pip upgrade failed, continuing anyway.
) else (
    echo [OK] pip upgraded.
)
echo.

REM ---- 5. Install requirements ----
echo Installing requirements.txt ...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [FAILURE] Failed to install requirements.
    goto :fail
)
echo [OK] Requirements installed.
echo.

REM ---- 6. Create required directories ----
if not exist "output" mkdir output
if not exist "reports" mkdir reports
echo [OK] Required directories present (output\, reports\).
echo.

REM ---- 7. Basic import / installation check ----
echo Running basic import check ...
python -c "import sys; sys.path.insert(0, '.'); from core.pipeline import analyze_email; import pytest; print('[OK] Core imports succeeded')"
if errorlevel 1 (
    echo [FAILURE] Basic import check failed.
    goto :fail
)
echo.

echo ============================================================
echo SETUP RESULT: SUCCESS
echo ============================================================
echo You can now run:  run.bat analyze test_data\phishing\phishing_paypal_lookalike.eml
echo.
pause
exit /b 0

:fail
echo ============================================================
echo SETUP RESULT: FAILURE
echo ============================================================
pause
exit /b 1
