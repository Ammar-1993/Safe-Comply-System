import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.policy_service import check_password_policy, evaluate_backup_policy


def main() -> None:
    file_path = (REPO_ROOT / 'test_40_records.xlsx')
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        candidate = Path(sys.argv[1])
        file_path = candidate if candidate.is_absolute() else (REPO_ROOT / candidate)
    df = pd.read_excel(file_path)

    password_valid = 0
    backup_compliant = 0

    # We always compute backup checks, because upload-excel does.
    # This reflects *current* app behavior.
    for _, row in df.iterrows():
        password = ''
        for col in ['password', 'Password', 'كلمة_المرور', 'كلمة المرور']:
            if col in df.columns:
                value = row[col]
                password = str(value) if pd.notna(value) else ''
                break

        if check_password_policy(password):
            password_valid += 1

        checks = evaluate_backup_policy(row)
        if isinstance(checks, dict) and bool(checks) and all(bool(v) for v in checks.values()):
            backup_compliant += 1

    total = len(df)
    password_invalid = total - password_valid
    backup_violations = total - backup_compliant

    # Policies Overview donuts (per-policy compliance rates)
    password_compliance_rate = round((password_valid / total) * 100, 2) if total else 0
    backup_compliance_rate = round((backup_compliant / total) * 100, 2) if total else 0

    # Dashboard donut (share of violations by policy type)
    violations_total = password_invalid + backup_violations
    password_share = round((password_invalid / violations_total) * 100, 2) if violations_total else 0
    backup_share = round((backup_violations / violations_total) * 100, 2) if violations_total else 0

    print('File:', str(file_path))
    print('Rows:', total)
    print('\nPolicies Overview (compliance rates)')
    print('  Password compliant:', password_valid, '/', total, '=', password_compliance_rate)
    print('  Backup compliant:', backup_compliant, '/', total, '=', backup_compliance_rate)

    print('\nDashboard Policies & Compliance Status (violation share donut)')
    print('  Password violations:', password_invalid)
    print('  Backup violations:', backup_violations)
    print('  Password share %:', password_share)
    print('  Backup share %:', backup_share)


if __name__ == '__main__':
    main()
