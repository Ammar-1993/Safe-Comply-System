from flask import Flask, request, jsonify, send_from_directory, redirect, send_file
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
        uploaded_by TEXT,
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
        role TEXT,
        email TEXT
    )
    ''')
    
    # Add email column if it doesn't exist (migration for existing databases)
    try:
        cur.execute('ALTER TABLE accounts ADD COLUMN email TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add profile_picture column if it doesn't exist (stores base64 image data)
    try:
        cur.execute('ALTER TABLE accounts ADD COLUMN profile_picture TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Login history table for tracking login attempts
    cur.execute('''
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_at TEXT,
        ip_address TEXT,
        status TEXT
    )
    ''')
    
    # Create notifications table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        is_read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # seed a default admin account if not exists
    cur.execute("SELECT COUNT(1) FROM accounts WHERE username = 'admin'")
    if cur.fetchone()[0] == 0:
        pw = generate_password_hash('Admin123!')
        cur.execute('INSERT INTO accounts (username, password_hash, role) VALUES (?,?,?)', ('admin', pw, 'admin'))
    conn.commit()
    conn.close()
    print("Database initialized.")


init_db()

def create_notification(username, title, message, n_type='info'):
    """Helper to create a notification"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO notifications (username, title, message, type) VALUES (?,?,?,?)',
                    (username, title, message, n_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error creating notification: {e}")

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

@app.route('/api/notifications', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def get_notifications():
    try:
        # Get username from token (require_auth wrapper puts decoded payload in request.user)
        # Assuming require_auth sets request.user = payload
        # If not, we re-parse. Let's look at require_auth again or play safe.
        # But wait, looking at my `auth_delete_account` above, it uses `request.user.get('sub')`.
        # So I should use that pattern.
        
        username = request.user.get('sub')
        if not username:
             # Fallback if request.user isn't set properly in some context
             token = request.headers.get('Authorization').split(" ")[1]
             username = jwt.decode(token, SECRET_KEY, algorithms=["HS256"]).get('sub')

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get unread or recent 10 events
        cur.execute('SELECT * FROM notifications WHERE username = ? ORDER BY created_at DESC LIMIT 10', (username,))
        rows = cur.fetchall()
        
        notifs = []
        unread_count = 0
        for r in rows:
            notifs.append({
                'id': r['id'],
                'title': r['title'],
                'message': r['message'],
                'type': r['type'],
                'is_read': bool(r['is_read']),
                'created_at': r['created_at']
            })
            if not r['is_read']:
                unread_count += 1
                
        conn.close()
        return jsonify({'notifications': notifs, 'unread_count': unread_count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/mark-read', methods=['POST'])
@require_auth(roles=['admin','auditor','user'])
def mark_notifications_read():
    try:
        username = request.user.get('sub')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('UPDATE notifications SET is_read = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Marked as read'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def auth_login():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        ip_address = request.remote_addr or 'unknown'
        login_at = datetime.utcnow().isoformat()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id, username, password_hash, role FROM accounts WHERE username = ?', (username,))
        row = cur.fetchone()

        if not row:
            # Log failed login attempt
            cur.execute('INSERT INTO login_history (username, login_at, ip_address, status) VALUES (?,?,?,?)',
                       (username, login_at, ip_address, 'failed_user_not_found'))
            conn.commit()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

        stored_hash = row[2]
        if not check_password_hash(stored_hash, password):
            # Log failed login attempt
            cur.execute('INSERT INTO login_history (username, login_at, ip_address, status) VALUES (?,?,?,?)',
                       (username, login_at, ip_address, 'failed_wrong_password'))
            conn.commit()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

        # Log successful login
        cur.execute('INSERT INTO login_history (username, login_at, ip_address, status) VALUES (?,?,?,?)',
                   (username, login_at, ip_address, 'success'))
        conn.commit()
        conn.close()
        
        token = _generate_token(row[1], row[3])
        return jsonify({'access_token': token, 'role': row[3], 'username': row[1]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/auth/change-password', methods=['POST'])
@require_auth()
def auth_change_password():
    """Change user password"""
    try:
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400
        
        username = request.user.get('sub')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT password_hash FROM accounts WHERE username = ?', (username,))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        if not check_password_hash(row[0], current_password):
            conn.close()
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password against policy
        if not check_password_policy(new_password):
            conn.close()
            checks = get_password_checks(new_password)
            return jsonify({
                'error': 'New password does not meet security requirements',
                'checks': checks
            }), 400
        
        new_hash = generate_password_hash(new_password)
        cur.execute('UPDATE accounts SET password_hash = ? WHERE username = ?', (new_hash, username))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/profile', methods=['GET'])
@require_auth()
def auth_get_profile():
    """Get current user profile"""
    try:
        username = request.user.get('sub')
        role = request.user.get('role')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id, username, role, email, profile_picture FROM accounts WHERE username = ?', (username,))
        row = cur.fetchone()
        conn.close()
        
        if not row:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': row[0],
            'username': row[1],
            'role': row[2],
            'email': row[3] or f'{row[1]}@company.com',
            'profile_picture': row[4]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/profile', methods=['PUT'])
@require_auth()
def auth_update_profile():
    """Update user profile"""
    try:
        data = request.get_json() or {}
        new_email = data.get('email')
        
        username = request.user.get('sub')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Update email if provided
        if new_email:
            cur.execute('UPDATE accounts SET email = ? WHERE username = ?', (new_email, username))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/profile/picture', methods=['POST'])
@require_auth()
def auth_update_picture():
    """Update profile picture (base64 encoded)"""
    try:
        data = request.get_json() or {}
        picture_data = data.get('picture')  # Base64 encoded image
        
        if not picture_data:
            return jsonify({'error': 'No picture data provided'}), 400
        
        # Validate it looks like base64 image data
        if not picture_data.startswith('data:image/'):
            return jsonify({'error': 'Invalid image format. Must be base64 data URL'}), 400
        
        # Limit size (max ~500KB base64)
        if len(picture_data) > 700000:
            return jsonify({'error': 'Image too large. Maximum size is 500KB'}), 400
        
        username = request.user.get('sub')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('UPDATE accounts SET profile_picture = ? WHERE username = ?', (picture_data, username))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile picture updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/history', methods=['GET'])
@require_auth()
def auth_get_history():
    """Get login history for current user"""
    try:
        username = request.user.get('sub')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT login_at, ip_address, status FROM login_history WHERE username = ? ORDER BY login_at DESC LIMIT 10', (username,))
        rows = cur.fetchall()
        conn.close()
        
        history = []
        for r in rows:
            history.append({
                'login_at': r[0],
                'ip_address': r[1],
                'status': r[2]
            })
        
        return jsonify({'history': history}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/export', methods=['GET'])
@require_auth()
def auth_export_data():
    """Export user data as JSON"""
    try:
        username = request.user.get('sub')
        role = request.user.get('role')
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get user profile
        cur.execute('SELECT id, username, role, email FROM accounts WHERE username = ?', (username,))
        profile_row = cur.fetchone()
        
        # Get user's reports
        cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score FROM reports WHERE uploaded_by = ?', (username,))
        report_rows = cur.fetchall()
        
        conn.close()
        
        reports = []
        for r in report_rows:
            reports.append({
                'id': r[0],
                'filename': r[1],
                'uploaded_at': r[2],
                'total': r[3],
                'valid': r[4],
                'invalid': r[5],
                'overall_score': r[6]
            })
        
        export_data = {
            'exported_at': datetime.utcnow().isoformat(),
            'profile': {
                'id': profile_row[0],
                'username': profile_row[1],
                'role': profile_row[2],
                'email': profile_row[3] or f'{profile_row[1]}@company.com'
            },
            'reports': reports,
            'report_count': len(reports)
        }
        
        # Create downloadable JSON file
        buffer = BytesIO()
        buffer.write(json.dumps(export_data, indent=2).encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'safecomply_export_{username}.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/delete-account', methods=['DELETE'])
@require_auth()
def auth_delete_account():
    """Delete current user account"""
    try:
        data = request.get_json() or {}
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password confirmation required'}), 400
        
        username = request.user.get('sub')
        
        # Prevent deletion of main admin
        if username == 'admin':
            return jsonify({'error': 'Cannot delete the main admin account'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Verify password
        cur.execute('SELECT password_hash FROM accounts WHERE username = ?', (username,))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        if not check_password_hash(row[0], password):
            conn.close()
            return jsonify({'error': 'Incorrect password'}), 401
        
        # Delete user's reports and associated users data
        cur.execute('SELECT id FROM reports WHERE uploaded_by = ?', (username,))
        report_ids = [r[0] for r in cur.fetchall()]
        
        for rid in report_ids:
            cur.execute('DELETE FROM users WHERE report_id = ?', (rid,))
        
        cur.execute('DELETE FROM reports WHERE uploaded_by = ?', (username,))
        cur.execute('DELETE FROM login_history WHERE username = ?', (username,))
        cur.execute('DELETE FROM accounts WHERE username = ?', (username,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Account deleted successfully'}), 200
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

def generate_ai_analysis(results, total, current_score=0, previous_score=None, username=None):
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
            title = f'CRITICAL: Compliance Score Dropped by {abs(diff)}%'
            msg = f'Significant regression detected. Score fell from {previous_score}% to {current_score}%.'
            alerts.append({'severity': 'high', 'title': title, 'desc': msg})
            recommendations.append({'title': 'Immediate Audit Required', 'desc': 'Review recent changes or user onboarding processes that caused this drop.'})
            
            if username:
                create_notification(username, title, msg, 'error')
                
        elif diff < -5:
             title = f'Warning: Compliance Score Dropped by {abs(diff)}%'
             msg = f'Score fell from {previous_score}% to {current_score}%.'
             alerts.append({'severity': 'medium', 'title': title, 'desc': msg})
             
             if username:
                create_notification(username, title, msg, 'warning')
                
        elif diff > 5:
            title = f'Positive Trend: Score Improved by {diff}%'
            msg = f'Compliance rose from {previous_score}% to {current_score}%.'
            alerts.append({'severity': 'low', 'title': title, 'desc': msg})
            
            if username:
                create_notification(username, title, msg, 'success')

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

        # Get username for notification
        username = request.user.get('sub')
        if not username:
             token = request.headers.get('Authorization').split(" ")[1]
             username = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"]).get('sub')

        # Get Previous Score for Trend Analysis
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT overall_score FROM reports ORDER BY uploaded_at DESC LIMIT 1')
        prev_row = cur.fetchone()
        previous_score = prev_row[0] if prev_row else None
        
        # Generate AI Analysis with Trend using USERNAME for auth
        alerts, recommendations = generate_ai_analysis(results, len(results), current_score=overall_score, previous_score=previous_score, username=username)

        uploaded_at = datetime.utcnow().isoformat()
        cur.execute('INSERT INTO reports (filename, uploaded_at, total, valid, invalid, overall_score) VALUES (?,?,?,?,?,?)',
                    (file.filename, uploaded_at, len(results), valid_count, invalid_count, overall_score))
        report_id = cur.lastrowid

        for r in results:
            cur.execute('INSERT INTO users (report_id, row_index, username, masked_password, is_valid, checks, strength, backup_checks) VALUES (?,?,?,?,?,?,?,?)',
                        (report_id, r['row'], r['username'], r['password'], int(r['isValid']), json.dumps(r['checks']), int(r['strength']), json.dumps(r.get('backup_checks', {}))))

        conn.commit()
        conn.close()
        
        # Notify user that report is ready
        create_notification(username, "Analysis Complete", f"Your report for {file.filename} is ready.", "success")

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
            'recommendations': recommendations,
            'report_id': report_id
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
    role = request.user.get('role')
    username = request.user.get('sub')
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    if role in ['admin', 'auditor']:
        cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score, uploaded_by FROM reports ORDER BY uploaded_at DESC')
    else:
        # Standard user sees only their own reports
        cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score, uploaded_by FROM reports WHERE uploaded_by = ? ORDER BY uploaded_at DESC', (username,))
        
    rows = cur.fetchall()
    conn.close()
    reports = []
    for r in rows:
        reports.append({
            'id': r[0], 'filename': r[1], 'uploaded_at': r[2], 'total': r[3], 'valid': r[4], 'invalid': r[5], 'overall_score': r[6], 'uploaded_by': r[7] if len(r) > 7 else ''
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



@app.route('/admin/users', methods=['GET'])
@require_auth(roles=['admin'])
def admin_list_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, username, role FROM accounts')
    rows = cur.fetchall()
    conn.close()
    users = [{'id': r[0], 'username': r[1], 'role': r[2]} for r in rows]
    return jsonify({'users': users}), 200

@app.route('/admin/users/<username>', methods=['DELETE'])
@require_auth(roles=['admin'])
def admin_delete_user(username):
    if username == 'admin':
        return jsonify({'error': 'Cannot delete the main admin account'}), 400
        
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('DELETE FROM accounts WHERE username = ?', (username,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    
    if deleted == 0:
        return jsonify({'error': 'User not found'}), 404
        
    return jsonify({'message': f'User {username} deleted successfully'}), 200

@app.route('/api/reports/<int:report_id>/pdf', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def export_report_pdf(report_id):
    """Export report as PDF"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get report details
        cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score FROM reports WHERE id = ?', (report_id,))
        rep = cur.fetchone()
        if not rep:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404
            
        # Get users data
        cur.execute('SELECT row_index, username, masked_password, is_valid, checks, strength, backup_checks FROM users WHERE report_id = ?', (report_id,))
        users = cur.fetchall()
        conn.close()
        
        # Try to use reportlab if available
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            # Container for elements
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#051338'), spaceAfter=30, alignment=TA_CENTER)
            elements.append(Paragraph('AI Compliance Report', title_style))
            elements.append(Spacer(1, 12))
            
            # Report Info
            info_style = styles['Normal']
            elements.append(Paragraph(f'<b>Report ID:</b> {rep[0]}', info_style))
            elements.append(Paragraph(f'<b>Filename:</b> {rep[1]}', info_style))
            elements.append(Paragraph(f'<b>Generated:</b> {rep[2]}', info_style))
            elements.append(Spacer(1, 20))
            
            # Summary Section
            summary_style = ParagraphStyle('SummaryTitle', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#051338'), spaceAfter=12)
            elements.append(Paragraph('Summary', summary_style))
            
            summary_data = [
                ['Metric', 'Value'],
                ['Overall Compliance Score', f"{rep[6]}%"],
                ['Total Users', str(rep[3])],
                ['Valid Passwords', str(rep[4])],
                ['Invalid Passwords', str(rep[5])]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 20))
            
            # User Details Section
            elements.append(Paragraph('User Details', summary_style))
            
            user_data = [['#', 'Username', 'Password', 'Valid', 'Strength']]
            for u in users[:50]:  # Limit to first 50 users to avoid huge PDFs
                user_data.append([
                    str(u[0]),
                    u[1],
                    u[2],
                    'Yes' if u[3] else 'No',
                    f"{u[5]}%"
                ])
            
            user_table = Table(user_data, colWidths=[0.5*inch, 1.5*inch, 1.5*inch, 0.8*inch, 0.8*inch])
            user_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(user_table)
            
            if len(users) > 50:
                elements.append(Spacer(1, 12))
                elements.append(Paragraph(f'<i>Note: Showing first 50 of {len(users)} users</i>', info_style))
            
            # Build PDF
            doc.build(elements)
            buffer.seek(0)
            
            return send_file(
                buffer,
                as_attachment=True,
                download_name=f'compliance_report_{report_id}.pdf',
                mimetype='application/pdf'
            )
            
        except ImportError:
            # Fallback: return error message asking to install reportlab
            return jsonify({
                'error': 'PDF generation requires reportlab library',
                'message': 'Please install reportlab: pip install reportlab'
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<int:report_id>/excel', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def export_report_excel(report_id):
    """Export report raw data as Excel"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get report details
        cur.execute('SELECT id, filename, uploaded_at, total, valid, invalid, overall_score FROM reports WHERE id = ?', (report_id,))
        rep = cur.fetchone()
        if not rep:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404
            
        # Get users data
        cur.execute('SELECT row_index, username, masked_password, is_valid, checks, strength, backup_checks FROM users WHERE report_id = ?', (report_id,))
        users = cur.fetchall()
        conn.close()
        
        # Create DataFrame
        data = []
        for u in users:
            checks_dict = json.loads(u[4] or '{}')
            backup_dict = json.loads(u[6] or '{}')
            data.append({
                'Row': u[0],
                'Username': u[1],
                'Password': u[2],
                'Is Valid': 'Yes' if u[3] else 'No',
                'Strength': u[5],
                'Length Check': 'Pass' if checks_dict.get('length') else 'Fail',
                'Uppercase Check': 'Pass' if checks_dict.get('uppercase') else 'Fail',
                'Lowercase Check': 'Pass' if checks_dict.get('lowercase') else 'Fail',
                'Digit Check': 'Pass' if checks_dict.get('digit') else 'Fail',
                'Special Char Check': 'Pass' if checks_dict.get('special') else 'Fail',
                'Last Backup OK': 'Yes' if backup_dict.get('last_backup_ok') else 'No',
                'Backup Frequency OK': 'Yes' if backup_dict.get('freq_ok') else 'No',
                'Backup Type OK': 'Yes' if backup_dict.get('type_ok') else 'No',
                'Retention OK': 'Yes' if backup_dict.get('retention_ok') else 'No'
            })
        
        df = pd.DataFrame(data)
        
        # Create Excel file in memory
        buffer = BytesIO()
        with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
            # Write main data
            df.to_excel(writer, sheet_name='User Data', index=False)
            
            # Write summary on a separate sheet
            summary_df = pd.DataFrame([
                {'Metric': 'Report ID', 'Value': rep[0]},
                {'Metric': 'Filename', 'Value': rep[1]},
                {'Metric': 'Generated At', 'Value': rep[2]},
                {'Metric': 'Total Users', 'Value': rep[3]},
                {'Metric': 'Valid Passwords', 'Value': rep[4]},
                {'Metric': 'Invalid Passwords', 'Value': rep[5]},
                {'Metric': 'Overall Score', 'Value': f"{rep[6]}%"}
            ])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'compliance_data_{report_id}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def home():
    return send_file('index.html')

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