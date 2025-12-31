import json
import os
import sqlite3


def parse_checks(raw: str | None) -> dict:
    if raw is None:
        return {}
    text = str(raw).strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def is_backup_compliant_app(checks: dict) -> bool:
    # Matches current /dashboard-stats logic: requires non-empty checks
    return bool(checks) and all(bool(v) for v in checks.values())


def main() -> None:
    db_path = os.path.join(os.getcwd(), "safecomply.db")
    print("DB:", db_path)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    report = cur.execute(
        "SELECT * FROM reports ORDER BY uploaded_at DESC, id DESC LIMIT 1"
    ).fetchone()
    if not report:
        print("No reports in DB")
        return

    report_id = report["id"]
    print(
        "Latest report:",
        {
            "id": report_id,
            "filename": report["filename"],
            "uploaded_at": report["uploaded_at"],
            "total": report["total"],
            "valid": report["valid"],
            "invalid": report["invalid"],
            "overall_score": report["overall_score"],
        },
    )

    users = cur.execute(
        "SELECT is_valid, backup_checks FROM users WHERE report_id = ?",
        (report_id,),
    ).fetchall()

    total = len(users)
    pwd_valid = sum(1 for u in users if int(u["is_valid"] or 0) == 1)
    pwd_invalid = total - pwd_valid
    pwd_rate = (pwd_valid / total * 100) if total else 0

    # Backup
    backup_checks_list = [parse_checks(u["backup_checks"]) for u in users]
    backup_has_any = sum(1 for c in backup_checks_list if bool(c))
    backup_compliant = sum(1 for c in backup_checks_list if is_backup_compliant_app(c))
    backup_violations = total - backup_compliant
    backup_rate = (backup_compliant / total * 100) if total else 0

    # Violation-share donut
    violations_total = pwd_invalid + backup_violations
    pwd_share = (pwd_invalid / violations_total * 100) if violations_total else 0
    backup_share = (backup_violations / violations_total * 100) if violations_total else 0

    print("\nComputed from DB (current app logic)")
    print(f"Password compliance: {pwd_valid}/{total} = {pwd_rate:.2f}%")
    print(f"Backup compliance: {backup_compliant}/{total} = {backup_rate:.2f}%")
    print(f"Backup checks present (non-empty JSON): {backup_has_any}/{total}")
    print("\nDashboard donut (share of violations)")
    print(f"Password violations: {pwd_invalid}")
    print(f"Backup violations: {backup_violations}")
    print(f"Password share: {pwd_share:.2f}%")
    print(f"Backup share: {backup_share:.2f}%")

    # If backup checks exist, show which checks fail most
    if backup_has_any:
        fail_counts = {
            "last_backup_ok": 0,
            "freq_ok": 0,
            "type_ok": 0,
            "retention_ok": 0,
        }
        for c in backup_checks_list:
            if not c:
                continue
            for k in list(fail_counts.keys()):
                if c.get(k) is False:
                    fail_counts[k] += 1
        print("\nBackup check failures (counts)")
        for k, v in fail_counts.items():
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()
