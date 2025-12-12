# 🛡️ SafeComply - AI-Powered Compliance Analysis System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Latest-green.svg)
![License](https://img.shields.io/badge/License-Proprietary-red.svg)
![Status](https://img.shields.io/badge/Status-Development-yellow.svg)

**An intelligent compliance analysis platform for password and backup policy evaluation**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [API Documentation](#-api-documentation) • [Troubleshooting](#-troubleshooting)

</div>

---

## 📋 Table of Contents

- [About the Project](#-about-the-project)
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Development](#-development)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🎯 About the Project

**SafeComply** is a Flask-based compliance analysis platform that leverages AI to evaluate organizational security policies. The system analyzes password strength, backup compliance, and generates intelligent recommendations to improve security posture.

### Key Capabilities

- 🔐 **Password Policy Analysis** - Evaluate passwords against security standards
- 💾 **Backup Policy Compliance** - Monitor backup schedules and retention
- 📊 **Excel Report Processing** - Bulk analysis from spreadsheet uploads
- 🤖 **AI-Powered Insights** - Generate alerts and recommendations
- 📈 **Trend Analysis** - Track compliance changes over time
- 👥 **Role-Based Access Control** - Admin, Auditor, and User roles
- 📄 **PDF/Excel Export** - Generate professional compliance reports

---

## ✨ Features

### Core Functionality

| Feature | Description |
|---------|-------------|
| **Single Password Check** | Validate individual passwords against policy requirements |
| **Bulk Analysis** | Process hundreds of passwords from Excel files |
| **Backup Monitoring** | Evaluate backup frequency, type, and retention policies |
| **Compliance Scoring** | Calculate overall compliance rates with detailed metrics |
| **Historical Trends** | Compare current vs. previous reports to detect regressions |
| **Smart Alerts** | AI-generated warnings for critical compliance issues |
| **Multi-format Export** | Download reports as PDF or Excel |

### User Roles

- **Admin** - Full system access, user management, all reports
- **Auditor** - View all reports, generate compliance documentation
- **User** - Upload reports, view own submissions

---

## 🛠️ Technology Stack

### Backend
- **Flask** - Lightweight WSGI web framework
- **Flask-CORS** - Cross-Origin Resource Sharing support
- **SQLite** - Embedded database for data persistence
- **JWT** - Secure token-based authentication

### Data Processing
- **Pandas** - Excel file processing and data manipulation
- **OpenPyXL** - Excel file reading/writing engine
- **ReportLab** *(optional)* - PDF generation for reports

### Security
- **Werkzeug** - Password hashing and security utilities
- **PyJWT** - JSON Web Token implementation

---

## 📦 Prerequisites

Before setting up SafeComply, ensure you have the following installed:

### Required Software

| Software | Minimum Version | Recommended | Download |
|----------|----------------|-------------|----------|
| **Python** | 3.8+ | 3.10+ | [python.org](https://www.python.org/downloads/) |
| **PowerShell** | 5.1+ | 7.0+ | Built-in (Windows) |
| **Git** | 2.0+ | Latest | [git-scm.com](https://git-scm.com/) |

### Environment Setup

- **Operating System**: Windows (PowerShell scripts included)
- **Internet Connection**: Required for dependency installation
- **Disk Space**: ~500MB for virtual environment and dependencies

> [!TIP]
> For best results, use Python 3.10 or newer. Verify your installation:
> ```powershell
> python --version
> ```

---

## 🚀 Installation

### Step 1: Clone the Repository

```powershell
# Navigate to your projects directory
cd d:\projects

# Clone the repository (or download as ZIP)
git clone <repository-url> Safecomply
cd Safecomply
```

### Step 2: Create Virtual Environment

```powershell
# Create a new virtual environment
python -m venv .venv

# Set execution policy for current session (if needed)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

> [!NOTE]
> After activation, your terminal prompt should show `(.venv)` at the beginning.

### Step 3: Install Dependencies

```powershell
# Upgrade pip to latest version
python -m pip install --upgrade pip

# Install all required packages
python -m pip install -r .\requirements.txt
```

#### Required Libraries

The following packages will be installed from `requirements.txt`:

| Package | Purpose |
|---------|---------|
| **flask** | Web framework core |
| **flask-cors** | Enable cross-origin requests |
| **pandas** | Data manipulation and Excel processing |
| **openpyxl** | Excel file format support |
| **pyjwt** | JWT token authentication |
| **werkzeug** | Password hashing and security |

**Optional**: For PDF export functionality:
```powershell
python -m pip install reportlab
```

### Step 4: Initialize Database

The database will be automatically initialized on first run with:
- SQLite database file: `safecomply.db`
- Tables: `reports`, `users`, `accounts`
- Default admin account (see [Default Credentials](#default-credentials))

---

## ⚙️ Configuration

### Environment Variables

SafeComply uses environment variables for configuration. Set these before running the application:

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `SAFE_COMPLY_SECRET` | `change-this-secret` | JWT signing secret ⚠️ |
| `SAFE_COMPLY_CORS` | `http://localhost:5500` | Allowed CORS origins |
| `SAFE_COMPLY_PORT` | `5001` | Application port |

#### Setting Environment Variables (PowerShell)

```powershell
# For current session only
$env:SAFE_COMPLY_SECRET = 'your-strong-random-secret-here'
$env:SAFE_COMPLY_CORS = 'http://localhost:5500'
$env:SAFE_COMPLY_PORT = '5001'
```

#### Setting Environment Variables (Persistent)

```powershell
# For current user (persists across sessions)
[System.Environment]::SetEnvironmentVariable('SAFE_COMPLY_SECRET', 'your-secret', 'User')
```

> [!WARNING]
> **Never use the default secret in production!** Generate a secure random string:
> ```powershell
> # Generate a secure random secret (PowerShell 7+)
> -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
> ```

---

## ⚡ Quick Start

### Option 1: Automated Setup (Recommended)

Use the included PowerShell script for one-command setup:

```powershell
.\run-dev.ps1
```

**This script automatically:**
- ✅ Creates/activates virtual environment
- ✅ Upgrades pip
- ✅ Installs all dependencies
- ✅ Sets default environment variables
- ✅ Starts the Flask development server

### Option 2: Manual Setup

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Set environment variables (optional)
$env:SAFE_COMPLY_SECRET = 'dev-secret-key'
$env:SAFE_COMPLY_PORT = '5001'

# 3. Run the application
python .\app.py
```

### Verify Installation

Once the server starts, you should see:

```
 * Running on http://127.0.0.1:5001
 * Debug mode: on
```

Test the API health endpoint:

```powershell
curl http://localhost:5001/health
```

Expected response:
```json
{
  "status": "ok",
  "message": "Backend is running"
}
```

---

## 🎮 Usage

### Default Credentials

A default admin account is automatically created on first run:

| Field | Value |
|-------|-------|
| **Username** | `admin` |
| **Password** | `Admin123!` |

> [!CAUTION]
> **Change the default password immediately after first login!** Use the `/auth/change-password` endpoint or create a new admin account.

### Accessing the Application

1. **Open your browser** and navigate to:
   ```
   http://localhost:5001
   ```

2. **Sign in** with the default credentials

3. **Upload a compliance report**:
   - Navigate to the Reports page
   - Upload an Excel file with user data
   - View analysis results and AI recommendations

### Sample Excel Format

Your Excel file should contain columns such as:

| Username | Password | last_backup_date | backup_frequency | backup_type | retention_days |
|----------|----------|------------------|------------------|-------------|----------------|
| john.doe | SecurePass123! | 2025-12-10 | daily | full | 60 |

> [!TIP]
> A sample Excel file `sample_compliance.xlsx` is included in the project directory.

---

## 📡 API Documentation

### Authentication

All protected endpoints require a JWT token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Core Endpoints

#### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/auth/register` | Create new user account | ❌ |
| `POST` | `/auth/login` | Login and receive JWT token | ❌ |

**Login Example:**
```bash
curl -X POST http://localhost:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin123!"}'
```

#### Password Checking

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/check-password` | Validate single password | ❌ |
| `POST` | `/check-passwords-bulk` | Validate multiple passwords | ❌ |
| `POST` | `/upload-excel` | Upload and analyze Excel file | ✅ |

#### Reports

| Method | Endpoint | Description | Auth Required | Roles |
|--------|----------|-------------|---------------|-------|
| `GET` | `/reports` | List all reports | ✅ | All |
| `GET` | `/reports/<id>` | Get report details | ✅ | Admin, Auditor |
| `GET` | `/api/reports/<id>/pdf` | Download PDF report | ✅ | All |
| `GET` | `/api/reports/<id>/excel` | Download Excel report | ✅ | All |

#### Admin

| Method | Endpoint | Description | Auth Required | Roles |
|--------|----------|-------------|---------------|-------|
| `GET` | `/admin/users` | List all users | ✅ | Admin |
| `DELETE` | `/admin/users/<username>` | Delete user | ✅ | Admin |

#### Dashboard

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/dashboard-stats` | Get dashboard statistics | ✅ |

### API Response Examples

#### Password Check Response
```json
{
  "isValid": true,
  "checks": {
    "length": true,
    "uppercase": true,
    "lowercase": true,
    "digit": true,
    "special": true
  },
  "message": "كلمة المرور صحيحة ✓"
}
```

#### Upload Excel Response
```json
{
  "total": 150,
  "valid": 120,
  "invalid": 30,
  "overall_score": 78,
  "policies_analyzed": 2,
  "alerts_detected": 3,
  "alerts": [...],
  "recommendations": [...],
  "report_id": 42
}
```

---

## 📁 Project Structure

```
Safecomply/
├── 📄 app.py                          # Main Flask application
├── 📄 README.md                       # This file
├── 📄 requirements.txt                # Python dependencies
├── 📄 requirements-lock.txt           # Locked dependency versions
├── 📄 run-dev.ps1                     # Development startup script
├── 📄 safecomply.db                   # SQLite database (auto-generated)
├── 📄 sample_compliance.xlsx          # Sample data file
│
├── 🎨 Frontend Files
│   ├── index.html                     # Landing page
│   ├── signin.html                    # Login page
│   ├── Signup.html                    # Registration page
│   ├── dashboard.html                 # Main dashboard
│   ├── reports.html                   # Reports listing
│   ├── compliance-report-view.html    # Report details view
│   ├── policies.html                  # Policy management
│   ├── password-policies.html         # Password policy view
│   ├── backup-policies.html           # Backup policy view
│   ├── recommendations.html           # AI recommendations
│   ├── settings.html                  # User settings
│   └── style.css                      # Global styles
│
├── 🛠️ Utility Scripts
│   ├── create_auditor.py              # Create auditor accounts
│   ├── create_sample.py               # Generate sample data
│   ├── migrate_db.py                  # Database migrations
│   ├── test_reqs.py                   # Test requirements
│   └── verify_rbac.py                 # Verify role-based access
│
└── 📁 .venv/                          # Virtual environment (auto-generated)
```

---

## 🔧 Development

### Helper Scripts

The project includes several utility scripts for development:

#### Create Auditor Account
```powershell
python .\create_auditor.py
```

#### Generate Sample Data
```powershell
python .\create_sample.py
```

#### Database Migration
```powershell
python .\migrate_db.py
```

#### Verify RBAC
```powershell
python .\verify_rbac.py
```

### Development Best Practices

1. **Always use the virtual environment**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. **Update dependencies after adding new packages**
   ```powershell
   python -m pip freeze > requirements-lock.txt
   ```

3. **Test after changes**
   ```powershell
   python .\test_reqs.py
   ```

### Running on Different Ports

```powershell
# Temporarily change port
$env:SAFE_COMPLY_PORT = '5010'
python .\app.py

# Or inline
$env:SAFE_COMPLY_PORT = '8080'; python .\app.py
```

---

## 🔒 Security

### Production Deployment

> [!WARNING]
> **The current configuration is for DEVELOPMENT ONLY!**

Before deploying to production:

#### 1. Change the Secret Key
```powershell
# Generate a cryptographically secure secret
$env:SAFE_COMPLY_SECRET = '<strong-random-secret-32-chars-minimum>'
```

#### 2. Configure CORS Properly
```powershell
# Lock down to specific frontend origin(s)
$env:SAFE_COMPLY_CORS = 'https://yourdomain.com'

# Multiple origins (comma-separated)
$env:SAFE_COMPLY_CORS = 'https://app.yourdomain.com,https://admin.yourdomain.com'
```

#### 3. Use a Production WSGI Server

**Don't use Flask's built-in server in production!** Use Waitress (Windows) or Gunicorn (Linux):

```powershell
# Install Waitress
python -m pip install waitress

# Run with Waitress
waitress-serve --port=5001 --call app:app
```

#### 4. Database Security
- Move `safecomply.db` to a secure location outside the web root
- Regular backups of the database
- Implement database encryption if handling sensitive data

#### 5. Change Default Credentials
- Delete or disable the default admin account
- Create new admin accounts with strong passwords
- Enforce password rotation policies

---

## 🐛 Troubleshooting

### Common Issues

#### 1. PowerShell Execution Policy Error

**Error:**
```
cannot be loaded because running scripts is disabled on this system
```

**Solution:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

#### 2. Port Already in Use

**Error:**
```
OSError: [WinError 10048] Only one usage of each socket address is normally permitted
```

**Solution:**
```powershell
# Find process using the port
netstat -aon | findstr ":5001"

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F

# Or use a different port
$env:SAFE_COMPLY_PORT = '5002'
```

#### 3. Port Range Excluded by Windows

**Solution:**
```powershell
# Check excluded port ranges
netsh interface ipv4 show excludedportrange protocol=tcp

# Use a port outside the excluded ranges
```

#### 4. Module Not Found Error

**Error:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```powershell
# Ensure virtual environment is activated
.\.venv\Scripts\Activate.ps1

# Reinstall dependencies
python -m pip install -r .\requirements.txt
```

#### 5. Database Locked Error

**Error:**
```
sqlite3.OperationalError: database is locked
```

**Solution:**
- Close any other applications accessing `safecomply.db`
- Restart the Flask application
- Check file permissions

#### 6. CORS Errors in Browser

**Error:**
```
Access to XMLHttpRequest has been blocked by CORS policy
```

**Solution:**
```powershell
# Allow your frontend origin
$env:SAFE_COMPLY_CORS = 'http://localhost:5500'

# Or allow all origins (development only!)
$env:SAFE_COMPLY_CORS = '*'
```

### Getting Help

If you encounter issues not covered here:

1. Check Flask logs in the terminal for error messages
2. Verify all environment variables are set correctly
3. Ensure Python version is 3.8 or higher
4. Try with a fresh virtual environment

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings to functions
- Comment complex logic

### Submitting Changes
1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit with clear description of changes

### Areas for Contribution
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

### Current Version
- **Status**: Development
- **Python**: 3.8+
- **Flask**: Latest stable
- **Database**: SQLite 3

### Known Limitations
- SQLite may have concurrency limitations under high load
- PDF export requires optional `reportlab` package
- Debug mode enabled by default (disable in production)

---

<div align="center">

**Built with ❤️ using Flask and Python**

[⬆ Back to Top](#️-safecomply---ai-powered-compliance-analysis-system)

</div>