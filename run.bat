@echo off
REM Network Baseline Monitor — Windows launcher.
REM Double-click this file or run from Command Prompt.

setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    echo [setup] creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo.
        echo ERROR: Python wasn't found. Install Python 3 from
        echo        https://www.python.org/downloads/windows/
        echo        and tick "Add python.exe to PATH" during install.
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"

echo [setup] installing dependencies...
pip install --quiet --disable-pip-version-check -r requirements.txt

echo.
echo [run] launching Network Baseline Monitor...
echo [run] dashboard: http://127.0.0.1:5050/
echo [run] press Ctrl+C in this window to stop.
echo.
python main.py %*

endlocal
