@echo off
setlocal

if not exist ".venv\Scripts\python.exe" (
    echo [FAILURE] Virtual environment not found.
    echo Please run setup.bat first.
    pause
    exit /b 1
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [FAILURE] Failed to activate virtual environment.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo TRACE-X
    echo.
    echo Usage:
    echo   run.bat analyze ^<path\to\email.eml^>
    echo   run.bat analyze-folder ^<path\to\folder^>
    echo   run.bat campaign ^<path\to\folder^>
    echo   run.bat test
    echo.
    echo Example:
    echo   run.bat analyze test_data\phishing\phishing_paypal_lookalike.eml
    echo   run.bat campaign test_data\campaign
    echo.
    exit /b 0
)

if "%~1"=="test" (
    python -m pytest tests\ -v
    exit /b %errorlevel%
)

python cli.py %*
exit /b %errorlevel%
