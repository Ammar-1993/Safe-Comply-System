# run-dev.ps1 - development helper for SafeComply
# Usage: Open PowerShell in the project root and run: .\run-dev.ps1

# Allow script execution for this session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Create and activate virtual environment if missing
if (-Not (Test-Path -Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}

Write-Host "Activating virtual environment..."
. .\.venv\Scripts\Activate.ps1

# Ensure pip is up-to-date
python -m pip install --upgrade pip

# Install requirements if not already installed
if (-Not (Test-Path -Path ".venv\Lib\site-packages\flask")) {
    Write-Host "Installing requirements..."
    python -m pip install -r .\requirements.txt
}

# Set default environment variables if not set
if (-not $env:SAFE_COMPLY_SECRET) {
    $env:SAFE_COMPLY_SECRET = 'Comply_ChangeMe!'
    Write-Host "SAFE_COMPLY_SECRET not set, using default (change for production)."
}
if (-not $env:SAFE_COMPLY_CORS) {
    $env:SAFE_COMPLY_CORS = 'http://localhost:5500'
}
if (-not $env:SAFE_COMPLY_PORT) {
    $env:SAFE_COMPLY_PORT = '5001'
}

Write-Host "Starting SafeComply backend on port $env:SAFE_COMPLY_PORT (CORS: $env:SAFE_COMPLY_CORS)"
python .\app.py
