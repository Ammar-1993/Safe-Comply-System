from app.services.policy_service import check_password_policy, get_password_checks, calculate_strength, evaluate_backup_policy
from datetime import datetime, timedelta

def test_check_password_policy():
    assert check_password_policy("StrongP@ssw0rd123") is True
    assert check_password_policy("weak") is False
    assert check_password_policy("NoSpecialChar123") is False
    assert check_password_policy("NoNumbers!") is False
    assert check_password_policy("nocaps123!") is False
    assert check_password_policy("NOLOWER123!") is False

def test_get_password_checks():
    checks = get_password_checks("StrongP@ssw0rd123")
    assert checks['length'] is True
    assert checks['uppercase'] is True
    assert checks['lowercase'] is True
    assert checks['digit'] is True
    assert checks['special'] is True

    checks = get_password_checks("weak")
    assert checks['length'] is False

def test_calculate_strength():
    checks = {
        'length': True,
        'uppercase': True,
        'lowercase': True,
        'digit': True,
        'special': True
    }
    # Base score 100 + 5 bonus for length >= 16
    assert calculate_strength("StrongP@ssw0rd123", checks) == 100
    
    checks['length'] = False
    assert calculate_strength("Short1!", checks) < 100

def test_evaluate_backup_policy():
    # Mock row data
    row = {
        'last_backup': (datetime.utcnow() + timedelta(hours=3)).isoformat(), # Today
        'backup_freq': 'Daily',
        'backup_type': 'Full',
        'retention': 30
    }
    
    result = evaluate_backup_policy(row)
    assert result['last_backup_ok'] is True
    assert result['freq_ok'] is True
    assert result['type_ok'] is True
    assert result['retention_ok'] is True

    # Test failure case
    row_fail = {
        'last_backup': (datetime.utcnow() - timedelta(days=10)).isoformat(), # Old
        'backup_freq': 'Never',
        'backup_type': 'None',
        'retention': 5
    }
    result_fail = evaluate_backup_policy(row_fail)
    assert result_fail['last_backup_ok'] is False
    assert result_fail['freq_ok'] is False
    assert result_fail['type_ok'] is False
    assert result_fail['retention_ok'] is False
