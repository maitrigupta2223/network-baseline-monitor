# Network Baseline Monitor — PowerShell launcher (Windows).
# Run with:  .\run.ps1
# If PowerShell blocks the script, run once:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "[setup] creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Python wasn't found." -ForegroundColor Red
        Write-Host "Install Python 3 from https://www.python.org/downloads/windows/"
        Write-Host "and tick 'Add python.exe to PATH' during install."
        Read-Host "Press Enter to exit"
        exit 1
    }
}

. .\.venv\Scripts\Activate.ps1

Write-Host "[setup] installing dependencies..." -ForegroundColor Cyan
pip install --quiet --disable-pip-version-check -r requirements.txt

Write-Host ""
Write-Host "[run] launching Network Baseline Monitor..." -ForegroundColor Green
Write-Host "[run] dashboard: http://127.0.0.1:5050/"  -ForegroundColor Green
Write-Host "[run] press Ctrl+C in this window to stop."
Write-Host ""

python main.py @args
