import pandas as pd
from datetime import timedelta
from app.utils import get_riyadh_time, get_value_from_row

def check_password_policy(password):
    """Check password against security policy"""
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
    """Get detailed password checks"""
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
    """Calculate password strength score"""
    score = 0
    if checks.get('length'): score += 25
    if checks.get('uppercase'): score += 20
    if checks.get('lowercase'): score += 15
    if checks.get('digit'): score += 20
    if checks.get('special'): score += 20

    if len(password) >= 16: score += 5

    return min(score, 100)

def evaluate_backup_policy(row):
    """Evaluate backup-related columns and return a small dict of checks."""
    # candidate column names
    last_backup = get_value_from_row(row, ['last_backup_date', 'LastBackup', 'last_backup', 'last_backup_dt'])
    freq = get_value_from_row(row, ['backup_frequency', 'BackupFrequency', 'backup_freq']) or ''
    btype = get_value_from_row(row, ['backup_type', 'BackupType', 'type_of_backup']) or ''
    status = get_value_from_row(row, ['backup_status', 'BackupStatus', 'status']) or ''
    retention = get_value_from_row(row, ['retention_days', 'retention', 'retention_period'])

    # normalize last backup date
    last_ok = False
    try:
        if last_backup is not None and (not (isinstance(last_backup, float) and pd.isna(last_backup))):
            last_dt = pd.to_datetime(last_backup)
            # Use Riyadh time for comparison
            last_ok = (get_riyadh_time() - last_dt.to_pydatetime()) <= timedelta(days=7)
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
