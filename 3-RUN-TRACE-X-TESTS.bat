@echo off
setlocal
cd /d "%~dp0"
title TRACE-X Test Suite

echo ========================================
echo   TRACE-X - Running All Tests
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

echo This can take a few minutes. Please wait...
echo.
python -m pytest tests\ -v
set "TRACE_X_EXIT=%ERRORLEVEL%"

echo.
if not "%TRACE_X_EXIT%"=="0" (
    echo [ERROR] One or more tests failed.
) else (
    echo [DONE] All TRACE-X tests passed.
)
echo.
pause
exit /b %TRACE_X_EXIT%
