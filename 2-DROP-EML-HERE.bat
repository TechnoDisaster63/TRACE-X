@echo off
setlocal
cd /d "%~dp0"
title TRACE-X Email Analyzer

echo ========================================
echo   TRACE-X - Email File Analyzer
echo ========================================
echo.

if "%~1"=="" (
    echo Drag one .eml email file onto this BAT file.
    echo.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] TRACE-X is not set up in this folder.
    echo Run setup.bat first, then try again.
    echo.
    pause
    exit /b 1
)

if not exist "%~1" (
    echo [ERROR] File not found:
    echo "%~1"
    echo.
    pause
    exit /b 1
)

if /I not "%~x1"==".eml" (
    echo [ERROR] TRACE-X accepts .eml email files only.
    echo Dropped file: "%~nx1"
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

echo Analyzing:
echo "%~f1"
echo.
python cli.py analyze "%~f1"
set "TRACE_X_EXIT=%ERRORLEVEL%"

echo.
if not "%TRACE_X_EXIT%"=="0" (
    echo [ERROR] Analysis did not finish successfully.
) else (
    echo [DONE] Analysis complete.
    echo Full results were saved inside the output and reports folders.
)
echo.
pause
exit /b %TRACE_X_EXIT%
