from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
import pandas as pd
from io import BytesIO
import sqlite3
import json
from datetime import datetime, timedelta
import os
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# JWT secret (use env var in production)
SECRET_KEY = os.environ.get('SAFE_COMPLY_SECRET', 'change-this-secret')


DB_PATH = 'safecomply.db'

app = Flask(__name__)
# Configure CORS: use SAFE_COMPLY_CORS env var (comma-separated origins) or allow all for dev
cors_origins = os.environ.get('SAFE_COMPLY_CORS', '*')
if cors_origins == '*' or cors_origins.strip() == '':
    CORS(app)
else:
    CORS(app, origins=[o.strip() for o in cors_origins.split(',')])


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        uploaded_at TEXT,
        total INTEGER,
        valid INTEGER,
        invalid INTEGER,
        overall_score INTEGER
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER,
        row_index INTEGER,
        username TEXT,
        masked_password TEXT,
        is_valid INTEGER,
        checks TEXT,
        strength INTEGER,
        backup_checks TEXT,
        FOREIGN KEY(report_id) REFERENCES reports(id)
    )
    ''')
    # accounts table for authentication (separate from report 'users' table)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT
    )
    ''')
    # seed a default admin account if not exists
    cur.execute("SELECT COUNT(1) FROM accounts WHERE username = 'admin'")
    if cur.fetchone()[0] == 0:
        pw = generate_password_hash('Admin123!')
        cur.execute('INSERT INTO accounts (username, password_hash, role) VALUES (?,?,?)', ('admin', pw, 'admin'))
    conn.commit()
    conn.close()


init_db()

def check_password_policy(password):
    """فحص كلمة المرور حسب السياسة الأمنية"""
    if not isinstance(password, str):
        return False
    # Align with policy: minimum length 12, require uppercase/lowercase/digit/special
    length_ok = len(password) >= 12
    upper_ok = any(c.isupper() for c in password)
    lower_ok = any(c.islower() for c in password)
    digit_ok = any(c.isdigit() for c in password)
    special_ok = any(c in "!@#$%^&*()-_=+[]{};:,.<>?" for c in password)
    return length_ok and upper_ok and lower_ok and digit_ok and special_ok

def get_password_checks(password):
    """الحصول على تفاصيل فحص كلمة المرور"""
    if not isinstance(password, str):
        return {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'digit': False,
            'special': False
        }
    
    return {
        'length': len(password) >= 12,
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'digit': any(c.isdigit() for c in password),
        'special': any(c in "!@#$%^&*()-_=+[]{};:,.<>?" for c in password)
    }

def calculate_strength(password, checks):
    """حساب قوة كلمة المرور"""
    score = 0
    if checks.get('length'): score += 25
    if checks.get('uppercase'): score += 20
    if checks.get('lowercase'): score += 15
    if checks.get('digit'): score += 20
    if checks.get('special'): score += 20

    if len(password) >= 16: score += 5

    return min(score, 100)


def mask_password(pw: str) -> str:
    if not pw:
        return ''
    if len(pw) <= 2:
        return '*' * len(pw)
    return pw[0] + '*' * (len(pw) - 2) + pw[-1]


def _get_value_from_row(row, candidates):
    # row may be dict or pandas Series
    for c in candidates:
        if isinstance(row, dict):
            if c in row and pd.notna(row[c]):
                return row[c]
        else:
            if c in row.index and pd.notna(row[c]):
                return row[c]
    return None


def evaluate_backup_policy(row):
    """Evaluate backup-related columns and return a small dict of checks."""
    # candidate column names
    last_backup = _get_value_from_row(row, ['last_backup_date', 'LastBackup', 'last_backup', 'last_backup_dt'])
    freq = _get_value_from_row(row, ['backup_frequency', 'BackupFrequency', 'backup_freq']) or ''
    btype = _get_value_from_row(row, ['backup_type', 'BackupType', 'type_of_backup']) or ''
    status = _get_value_from_row(row, ['backup_status', 'BackupStatus', 'status']) or ''
    retention = _get_value_from_row(row, ['retention_days', 'retention', 'retention_period'])

    # normalize last backup date
    last_ok = False
    try:
        if last_backup is not None and (not (isinstance(last_backup, float) and pd.isna(last_backup))):
            last_dt = pd.to_datetime(last_backup)
            last_ok = (datetime.utcnow() - last_dt.to_pydatetime()) <= timedelta(days=7)
    except Exception:
        last_ok = False

    freq_ok = any(k in str(freq).lower() for k in ['daily', 'weekly', 'monthly'])
    type_ok = any(k in str(btype).lower() for k in ['full', 'differential', 'incremental'])
    retention_ok = False
    try:
        if retention is not None and pd.notna(retention):
            retention_ok = int(retention) >= 30
    except Exception:
        retention_ok = False

    return {
        'last_backup_ok': bool(last_ok),
        'freq_ok': bool(freq_ok),
        'type_ok': bool(type_ok),
        'retention_ok': bool(retention_ok)
    }


def _generate_token(username, role):
    exp = datetime.utcnow() + timedelta(hours=8)
    payload = {
        'sub': username,
        'role': role,
        'exp': int(exp.timestamp())
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth or not auth.startswith('Bearer '):
                return jsonify({'error': 'Unauthorized'}), 401
            token = auth.split(None, 1)[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            except Exception as e:
                return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
            role = payload.get('role')
            if roles:
                allowed = roles if isinstance(roles, (list, tuple)) else [roles]
                if role not in allowed:
                    return jsonify({'error': 'Forbidden', 'message': 'insufficient role'}), 403
            # attach user to request for handlers
            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/check-password', methods=['POST'])
def check_password():
    """فحص كلمة مرور واحدة"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        is_valid = check_password_policy(password)
        checks = get_password_checks(password)
        # do not return the raw password
        return jsonify({
            'isValid': is_valid,
            'checks': checks,
            'message': 'كلمة المرور صحيحة ✓' if is_valid else 'كلمة المرور لا تطابق المتطلبات'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'حدث خطأ في المعالجة'
        }), 500



@app.route('/auth/register', methods=['POST'])
def auth_register():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user') # Default role
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute('SELECT id FROM accounts WHERE username = ?', (username,))
        if cur.fetchone():
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400
            
        password_hash = generate_password_hash(password)
        cur.execute('INSERT INTO accounts (username, password_hash, role) VALUES (?,?,?)', (username, password_hash, role))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Account created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def auth_login():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id, username, password_hash, role FROM accounts WHERE username = ?', (username,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Invalid credentials'}), 401

        stored_hash = row[2]
        if not check_password_hash(stored_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = _generate_token(row[1], row[3])
        return jsonify({'access_token': token, 'role': row[3], 'username': row[1]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/check-passwords-bulk', methods=['POST'])
def check_passwords_bulk():
    """فحص مجموعة من كلمات المرور من JSON"""
    try:
        data = request.get_json()
        passwords_data = data.get('passwords', [])
        
        results = []
        for idx, row in enumerate(passwords_data):
            # البحث عن عمود كلمة المرور بأسماء مختلفة
            password = (row.get('password') or 
                       row.get('Password') or 
                       row.get('كلمة_المرور') or 
                       row.get('كلمة المرور') or '')
            
            # البحث عن اسم المستخدم
            username = (row.get('username') or 
                       row.get('Username') or 
                       row.get('المستخدم') or 
                       row.get('اسم المستخدم') or 
                       f'مستخدم {idx + 1}')
            
            checks = get_password_checks(password)
            is_valid = check_password_policy(password)
            strength = calculate_strength(password, checks)
            masked = mask_password(password)

            results.append({
                'row': idx + 1,
                'username': username,
                'password': masked,
                'isValid': is_valid,
                'checks': checks,
                'strength': strength
            })
        
        valid_count = sum(1 for r in results if r['isValid'])
        

        if valid_count < len(results):
            # Example bulk check recommendation
            pass

        return jsonify({
            'results': results,
            'total': len(results),
            'valid': valid_count,
            'invalid': len(results) - valid_count
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'حدث خطأ في المعالجة'
        }), 500

def generate_ai_analysis(results, total, current_score=0, previous_score=None):
    """Generate alerts and recommendations based on analysis results and historical trends."""
    
    pwd_weak_count = sum(1 for r in results if r.get('strength', 0) < 60)
    backup_ok_count = sum(1 for r in results if all(r.get('backup_checks', {}).values()))
    backup_fail_count = total - backup_ok_count
    
    alerts = []
    recommendations = []
    
    # Trend Analysis
    if previous_score is not None:
        diff = current_score - previous_score
        if diff < -10:
            alerts.append({
                'severity': 'high',
                'title': f'CRITICAL: Compliance Score Dropped by {abs(diff)}%',
                'desc': f'Significant regression detected. Score fell from {previous_score}% to {current_score}%.'
            })
            recommendations.append({
                'title': 'Immediate Audit Required',
                'desc': 'Review recent changes or user onboarding processes that caused this drop.'
            })
        elif diff < -5:
             alerts.append({
                'severity': 'medium',
                'title': f'Warning: Compliance Score Dropped by {abs(diff)}%',
                'desc': f'Score fell from {previous_score}% to {current_score}%.'
            })
        elif diff > 5:
            # We can use 'low' severity for positive news or add a new type if UI supports it
            alerts.append({
                'severity': 'low',
                'title': f'Positive Trend: Score Improved by {diff}%',
                'desc': f'Compliance rose from {previous_score}% to {current_score}%.'
            })

    # Analyze Password Policy
    if total > 0 and (pwd_weak_count / total) >= 0.05:
        alerts.append({
            'severity': 'high',
            'title': f'High Risk: Weak Passwords for {pwd_weak_count} users',
            'desc': 'Password strength below recommended standards for a significant portion of users.'
        })
    elif pwd_weak_count > 0:
        alerts.append({
            'severity': 'medium',
            'title': f'Medium: Weak Passwords for {pwd_weak_count} users',
            'desc': 'Some users have weak passwords.'
        })
        
    if pwd_weak_count > 0:
        recommendations.append({
            'title': f'Enforce stronger passwords for {pwd_weak_count} users',
            'desc': 'Require minimum length of 14 and enforce complexity; prompt users to change weak passwords.'
        })

    # Analyze Backup Policy
    if backup_fail_count > 0 and (backup_fail_count / max(1, total)) >= 0.1:
        alerts.append({
            'severity': 'high',
            'title': f'High Risk: Backup Failures affecting {backup_fail_count} users',
            'desc': 'Multiple backup failures detected — data loss risk is high.'
        })
    elif backup_fail_count > 0:
        alerts.append({
            'severity': 'medium',
            'title': f'Medium: {backup_fail_count} Backup Failures',
            'desc': 'Some users have missing or outdated backups.'
        })
        
    if backup_fail_count > 0:
        recommendations.append({
            'title': 'Investigate backup failures',
            'desc': 'Run recovery readiness checks and repair failing backup jobs.'
        })

    # General recommendations
    if not alerts:
        alerts.append({'severity': 'low', 'title': 'No critical alerts detected', 'desc': 'All checks are within acceptable thresholds.'})
        recommendations.append({'title': 'Maintain current settings', 'desc': 'No immediate recommendations.'})
        
    return alerts, recommendations

@app.route('/upload-excel', methods=['POST'])
@require_auth(roles=['admin','auditor','user'])
def upload_excel():
    """رفع وفحص ملف Excel مباشرة"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'لم يتم رفع ملف'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'اسم الملف فارغ'}), 400
        
        # قراءة ملف Excel
        df = pd.read_excel(file)

        results = []
        for idx, row in df.iterrows():
            # البحث عن عمود كلمة المرور
            password = ''
            for col in ['password', 'Password', 'كلمة_المرور', 'كلمة المرور']:
                if col in df.columns:
                    password = str(row[col]) if pd.notna(row[col]) else ''
                    break

            # البحث عن اسم المستخدم
            username = ''
            for col in ['username', 'Username', 'المستخدم', 'اسم المستخدم']:
                if col in df.columns:
                    username = str(row[col]) if pd.notna(row[col]) else ''
                    break

            if not username:
                username = f'مستخدم {idx + 1}'

            checks = get_password_checks(password)
            is_valid = check_password_policy(password)
            strength = calculate_strength(password, checks)
            masked = mask_password(password)

            # evaluate backup policy if any backup columns exist
            backup_checks = evaluate_backup_policy(row)

            results.append({
                'row': idx + 1,
                'username': username,
                'password': masked,
                'isValid': is_valid,
                'checks': checks,
                'strength': strength,
                'backup_checks': backup_checks
            })

        valid_count = sum(1 for r in results if r['isValid'])
        invalid_count = len(results) - valid_count
        # compute a simple overall score as average of strengths
        overall_score = int(sum(r['strength'] for r in results) / len(results)) if results else 0

        # count backup issues (any false in backup checks)
        backup_issues = sum(1 for r in results if any(not v for v in r.get('backup_checks', {}).values()))

        # Get Previous Score for Trend Analysis
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT overall_score FROM reports ORDER BY uploaded_at DESC LIMIT 1')
        prev_row = cur.fetchone()
        previous_score = prev_row[0] if prev_row else None
        
        # Generate AI Analysis with Trend
        alerts, recommendations = generate_ai_analysis(results, len(results), current_score=overall_score, previous_score=previous_score)

        uploaded_at = datetime.utcnow().isoformat()
        cur.execute('INSERT INTO reports (filename, uploaded_at, total, valid, invalid, overall_score) VALUES (?,?,?,?,?,?)',
                    (file.filename, uploaded_at, len(results), valid_count, invalid_count, overall_score))
        report_id = cur.lastrowid

        for r in results:
            cur.execute('INSERT INTO users (report_id, row_index, username, masked_password, is_valid, checks, strength, backup_checks) VALUES (?,?,?,?,?,?,?,?)',
                        (report_id, r['row'], r['username'], r['password'], int(r['isValid']), json.dumps(r['checks']), int(r['strength']), json.dumps(r.get('backup_checks', {}))))

        conn.commit()
        conn.close()

        return jsonify({
            'results': results,
            'total': len(results),
            'valid': valid_count,
            'invalid': invalid_count,
            'overall_score': overall_score,
            'policies_analyzed': 2,
            'alerts_detected': len(alerts),
            'non_compliant_users': invalid_count,
            'alerts': alerts,
            'recommendations': recommendations
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'حدث خطأ في قراءة الملف'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """فحص صحة الخادم"""
    return jsonify({
        'status': 'ok', 
        'message': 'Backend is running',
        'endpoints': [
            '/check-password',
            '/check-passwords-bulk',
            '/upload-excel',
            '/auth/login',
            '/reports',
            '/reports/<id>'
        ]
    }), 200


@app.route('/reports', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def list_reports():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score FROM reports ORDER BY uploaded_at DESC')
    rows = cur.fetchall()
    conn.close()
    reports = []
    for r in rows:
        reports.append({
            'id': r[0], 'filename': r[1], 'uploaded_at': r[2], 'total': r[3], 'valid': r[4], 'invalid': r[5], 'overall_score': r[6]
        })
    return jsonify({'reports': reports}), 200


@app.route('/dashboard-stats', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def dashboard_stats():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Get latest report
    cur.execute('SELECT id, overall_score, total, valid, invalid FROM reports ORDER BY uploaded_at DESC LIMIT 1')
    latest = cur.fetchone()
    
    compliance_rate = 0
    active_alerts = 0
    
    if latest:
        compliance_rate = latest[1] # overall_score
        # Approximation: active alerts = invalid count + some backup logic logic
        # For simplicity, let's say alerts = invalid users / 2 roughly, or store alerts in DB
        active_alerts = latest[4] # invalid count
        
    # Pending reports
    cur.execute("SELECT COUNT(1) FROM reports WHERE uploaded_at > date('now', '-7 days')")
    recent_count = cur.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'compliance_rate': compliance_rate,
        'active_alerts': active_alerts,
        'pending_reports': recent_count,
        # Mocking the pie chart data for now, ideally calc from latest report
        'policy_breakdown': {
            'password': 70, 
            'backup': 30
        }
    }), 200


@app.route('/reports/<int:report_id>', methods=['GET'])
@require_auth(roles=['admin','auditor'])
def get_report(report_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score FROM reports WHERE id = ?', (report_id,))
    rep = cur.fetchone()
    if not rep:
        conn.close()
        return jsonify({'error': 'Report not found'}), 404
    cur.execute('SELECT row_index, username, masked_password, is_valid, checks, strength, backup_checks FROM users WHERE report_id = ?', (report_id,))
    users = cur.fetchall()
    conn.close()
    user_list = []
    for u in users:
        user_list.append({
            'row': u[0], 'username': u[1], 'password': u[2], 'isValid': bool(u[3]), 'checks': json.loads(u[4] or '{}'), 'strength': u[5], 'backup_checks': json.loads(u[6] or '{}')
        })
    report_obj = {'id': rep[0], 'filename': rep[1], 'uploaded_at': rep[2], 'total': rep[3], 'valid': rep[4], 'invalid': rep[5], 'overall_score': rep[6], 'results': user_list}
    return jsonify(report_obj), 200


# Serve a simple frontend root and static files from project root for development
@app.route('/')
def index():
    # Prefer the signin page if present
    if os.path.exists('signin.html'):
        return send_from_directory('.', 'signin.html')
    return redirect('/health')


@app.route('/<path:filename>')
def serve_static_file(filename):
    # Only serve common static asset types from the project root in development
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Not allowed'}), 403
    allowed_ext = ('html', 'css', 'js', 'png', 'jpg', 'jpeg', 'svg', 'ico')
    ext = filename.rsplit('.', 1)[-1] if '.' in filename else ''
    if ext.lower() in allowed_ext and os.path.exists(filename):
        return send_from_directory('.', filename)
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    # Use environment variable for port so user can avoid reserved ports (default 5001)
    port = int(os.environ.get('SAFE_COMPLY_PORT', '5002'))
    print("=" * 50)
    print(f"🚀 Backend running on http://localhost:{port}")
    print("=" * 50)
    print("المسارات المتاحة:")
    # Print registered rules (skip the Flask static endpoint)
    seen = set()
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: (str(r.rule), str(list(r.methods)))):
        if rule.endpoint == 'static':
            continue
        methods = ','.join(sorted(m for m in rule.methods if m not in ('HEAD', 'OPTIONS')))
        entry = f"  - {methods} {rule.rule}"
        if entry not in seen:
            print(entry)
            seen.add(entry)
    print("=" * 50)
    try:
        app.run(debug=True, port=port, host='0.0.0.0')
    except OSError as e:
        print('Failed to start server:', e)
        print('If you see a socket/permission error, pick a different port and set SAFE_COMPLY_PORT or free the port.')