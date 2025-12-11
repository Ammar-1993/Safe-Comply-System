# SafeComply (Development)

SafeComply is a small Flask-based compliance analysis app. This README shows how to set up and run the project locally for development.

## Prerequisites
- Python 3.8+ (3.10 recommended)
- PowerShell (Windows)

## Quick start (recommended)
1. Open PowerShell in the project root `d:\projects\Safecomply`.
2. Run the development helper script which creates/activates the venv, installs requirements, sets defaults, and starts the backend:

```powershell
.\run-dev.ps1
```

This script will:
- Create a `.venv` if missing and activate it.
- Upgrade `pip` and install packages from `requirements.txt` (Flask, pandas, pyjwt, etc.).
- Set default environment variables when missing:
  - `SAFE_COMPLY_SECRET` (default `Comply_ChangeMe!`)
  - `SAFE_COMPLY_CORS` (default `http://localhost:5500`)
  - `SAFE_COMPLY_PORT` (default `5001`)
- Start the Flask backend.

Note: change the defaults before exposing the app to any network. The default secret is for development only.

## Manual setup (alternative)
1. Create and activate venv:
```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\.venv\Scripts\Activate.ps1
```
2. Install dependencies:
```powershell
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```
3. Set environment variables (current session):
```powershell
$env:SAFE_COMPLY_SECRET = 'your-strong-secret'
$env:SAFE_COMPLY_CORS = 'http://localhost:5500'
$env:SAFE_COMPLY_PORT = '5001'
```
4. Run the app:
```powershell
python .\app.py
```

## Default seeded account (development)
- An admin account is seeded when the app runs first (only if not present):
  - username: `admin`
  - password: `Admin123!`

Change this password immediately with the `/auth/change-password` endpoint or create a new admin account via `/auth/register`.

## Notes & security
- The built-in Flask server runs in debug mode inside `app.py` for development only. Use a production WSGI server (e.g., Gunicorn, Waitress) for deployment.
- Do not keep the default `SAFE_COMPLY_SECRET` in production. Export a secure secret before running.
- Lock down `SAFE_COMPLY_CORS` to your front-end origin(s) in production.

## Useful tips
- Change port quickly without editing code:
```powershell
$env:SAFE_COMPLY_PORT = '5010'; python .\app.py
```
- If you see socket binding errors, check which process uses the port:
```powershell
netstat -aon | findstr ":5000"
netsh interface ipv4 show excludedportrange protocol=tcp
```

If you'd like, I can add an automated `run-prod.ps1` or instructions for running behind a WSGI server and reverse proxy.