from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from io import BytesIO
import sqlite3
import json
from datetime import datetime, timedelta

DB_PATH = 'safecomply.db'

app = Flask(__name__)
# For local development allow all origins; lock this down in production
CORS(app)


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
    conn.commit()
    conn.close()


init_db()

def check_password_policy(password):
    """فحص كلمة المرور حسب السياسة الأمنية"""
    if not isinstance(password, str):
        return False
    length_ok = len(password) >= 8
    upper_ok = any(c.isupper() for c in password)
    digit_ok = any(c.isdigit() for c in password)
    special_ok = any(c in "!@#$%^&*()-_=+[]{};:,.<>?" for c in password)
    return length_ok and upper_ok and digit_ok and special_ok

def get_password_checks(password):
    """الحصول على تفاصيل فحص كلمة المرور"""
    if not isinstance(password, str):
        return {
            'length': False,
            'uppercase': False,
            'digit': False,
            'special': False
        }
    
    return {
        'length': len(password) >= 8,
        'uppercase': any(c.isupper() for c in password),
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

@app.route('/upload-excel', methods=['POST'])
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

        # persist report and rows into SQLite
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
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
            'alerts_detected': invalid_count + backup_issues,
            'non_compliant_users': invalid_count
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
            '/upload-excel'
        ]
    }), 200

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Backend يعمل على http://localhost:5000")
    print("=" * 50)
    print("المسارات المتاحة:")
    print("  - POST /check-password")
    print("  - POST /check-passwords-bulk")
    print("  - POST /upload-excel")
    print("  - GET  /health")
    print("=" * 50)
    app.run(debug=True, port=5000, host='0.0.0.0')