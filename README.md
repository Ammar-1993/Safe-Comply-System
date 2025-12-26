# 🛡️ SafeComply - AI-Powered Compliance Analysis System

Flask application for password and backup compliance analysis with AI-generated insights, Excel ingestion, and JWT-protected user workflows.

---

## 📑 Contents
- [About](#about)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Setup](#setup)
- [Configuration](#configuration)
- [Database](#database)
- [Run](#run)
- [Application Pages](#application-pages)
- [API](#api)
- [Data Model](#data-model)
- [Testing](#testing)
- [Utilities & Scripts](#utilities--scripts)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## ℹ️ About
SafeComply ingests user credential/backups data (Excel), evaluates password and backup policies, produces compliance scores, and generates AI-driven alerts and recommendations. Users authenticate with JWTs, manage profiles, and track notifications. Reports can be exported to PDF/Excel (ReportLab optional for PDFs).

## 🏗️ Architecture
- Flask app factory with blueprints for pages, auth, reports, and APIs ([app/__init__.py](app/__init__.py), [app/routes](app/routes)).
- SQLAlchemy ORM + Flask-Migrate; default SQLite database stored beside the code ([config.py](config.py)).
- JWT auth utilities in [app/auth_utils.py](app/auth_utils.py) with role-based guards.
- Services for policy checks and AI analysis ([app/services/policy_service.py](app/services/policy_service.py), [app/services/analysis_service.py](app/services/analysis_service.py)).
- Notifications persisted in DB via [app/services/notification_service.py](app/services/notification_service.py).
- HTML/CSS/JS frontend served from [app/templates](app/templates) and [app/static](app/static).

## 🧰 Requirements
- Python 3.10+
- pip
- (Optional) ReportLab for PDF export: `pip install reportlab`

## ⚙️ Setup
```powershell
# from repo root
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 🔧 Configuration
Environment variables (defaults shown from [config.py](config.py)):

| Variable | Default | Purpose |
|----------|---------|---------|
| SAFE_COMPLY_SECRET | dev-secret-key | Flask/JWT secret key (must change in prod) |
| SAFE_COMPLY_DEBUG | true | Enable debug mode when truthy |
| SAFE_COMPLY_PORT | 5002 | HTTP port used by `run.py` |
| SAFE_COMPLY_CORS | * | Allowed CORS origins (comma-separated or `*`) |
| DATABASE_URL | sqlite:///.../safecomply.db | Override default SQLite path |

Set for current session (PowerShell):
```powershell
$env:SAFE_COMPLY_SECRET = 'change-me'
$env:SAFE_COMPLY_CORS = 'http://localhost:5500'
$env:SAFE_COMPLY_PORT = '5002'
```

## 🗄️ Database
Flask-Migrate is wired in the app factory. To create/upgrade the schema:
```powershell
$env:FLASK_APP = 'run.py'
$env:FLASK_CONFIG = 'development'   # default if unset
flask db upgrade
```
The default SQLite file lives at `app/safecomply.db`. Legacy script `scripts/migrate_db.py` only adds an `uploaded_by` column and is not sufficient for a fresh setup.

## ▶️ Run
```powershell
python run.py
```
Runs on `0.0.0.0:${SAFE_COMPLY_PORT}` (default 5002). The helper script `run-dev.ps1` currently points to a non-existent `app.py` and sets port 5001; prefer `python run.py` or update the script locally to call `run.py` if you use it.

## 🖥️ Application Pages
Served without auth guard at the route level (frontend enforces auth):
- `/` landing
- `/signin.html`, `/signup.html`
- `/dashboard.html`
- `/password-policies.html`, `/backup-policies.html`, `/policies.html`
- `/reports.html`, `/compliance-report-view.html`
- `/recommendations.html`, `/settings.html`

## 🔌 API
JWT: `Authorization: Bearer <token>` for protected endpoints.

**Auth** (prefix `/auth`):
- POST `/auth/register` (public; accepts optional `role`, default `user`)
- POST `/auth/login`
- POST `/auth/change-password`
- GET/PUT `/auth/profile`
- POST `/auth/profile/picture` (base64 data URL, ~500KB max)
- GET `/auth/history` (last 10 logins)
- GET `/auth/export` (JSON download of profile + reports)
- DELETE `/auth/delete-account` (blocks deleting `admin` account)

**Public policy checks**:
- POST `/check-password`
- POST `/check-passwords-bulk`
- POST `/check-backup-policy`

**Reports** (JWT):
- POST `/upload-excel` (Excel ingest, stores report and users, triggers AI alerts/recs)
- GET `/reports` (admin/auditor see all; users see own)
- GET `/reports/<id>` (owner or role `admin|auditor`)
- DELETE `/reports/<id>` (admin or owner)
- GET `/api/reports/<id>/pdf` (requires ReportLab)
- GET `/api/reports/<id>/excel`

**Notifications & dashboard** (JWT):
- GET `/api/notifications`, POST `/api/notifications/mark-read`
- GET `/dashboard-stats`
- GET `/api/recommendations` (latest report-based)

**Admin** (JWT, role `admin`):
- GET `/admin/users`
- DELETE `/admin/users/<username>`

## 🗂️ Data Model
- `accounts`: username, password_hash, role, email, profile_picture
- `login_history`: username, login_at, ip_address, status
- `reports`: filename, uploaded_at, uploaded_by, total/valid/invalid, overall_score
- `users`: per-report user rows (row_index, username, masked_password, checks JSON, strength, backup_checks JSON)
- `notifications`: username, title, message, type, is_read, created_at

## ✅ Testing
Pytest uses the testing config with an in-memory SQLite DB.
```powershell
pytest
# or
pytest tests/test_reports.py -vv
```
Key coverage: auth/profile flows, report upload and export, dashboard stats, policy service checks, settings features.

## 🛠️ Utilities & Scripts
- `scripts/create_admin.py` is legacy and does not match the current models; manual role updates or registration with `role="admin"` are required for an admin user.
- `scripts/migrate_db.py` is a narrow one-off migration; rely on Flask-Migrate instead.
- Other scripts in `scripts/` may predate the current schema—review before use.

## 🔒 Security Notes
- Change `SAFE_COMPLY_SECRET` for any non-local use.
- Lock down `SAFE_COMPLY_CORS` to the actual frontend origins.
- Use a production WSGI server (e.g., waitress/gunicorn) and move SQLite out of the web root or switch to a managed DB via `DATABASE_URL`.
- No default admin is created; create an admin intentionally and protect the `register` flow if exposed publicly.

## 🩺 Troubleshooting
- **Module not found**: ensure `.venv` is activated and dependencies installed.
- **Port in use**: change `SAFE_COMPLY_PORT` or stop the other process.
- **CORS blocked**: set `SAFE_COMPLY_CORS` to your frontend origin or `*` during development.
- Comment complex logic

### 🚀 Submitting Changes
1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit with clear description of changes

### 🤝 Areas for Contribution
- Additional compliance policy checks
- Enhanced AI recommendations
- UI/UX improvements
- Performance optimizations
- Documentation updates

---

## 📝 License

This project is proprietary software. All rights reserved.

---

## 👨‍💻 Developer Notes

### 📦 Current Version
- **Status**: Development
- **Python**: 3.10+
- **Flask**: 3.1.2
- **Database**: SQLite 3 with SQLAlchemy ORM
- **Testing**: Pytest with 14 test cases

### ⚠️ Known Limitations
- SQLite may have concurrency limitations under high load
- PDF export requires optional `reportlab` package
- Debug mode enabled by default (disable in production)

---

<div align="center">

<p align="center">Developed by ❤️ Engineer Ammar Al-Najjar</p>

[⬆ Back to Top](#️-safecomply---ai-powered-compliance-analysis-system)

</div>