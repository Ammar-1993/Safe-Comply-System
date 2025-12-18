from datetime import datetime, timedelta
import pandas as pd

def get_riyadh_time():
    """Returns current time in Riyadh (UTC+3)"""
    return datetime.utcnow() + timedelta(hours=3)

def mask_password(pw: str) -> str:
    if not pw:
        return ''
    if len(pw) <= 2:
        return '*' * len(pw)
    return pw[0] + '*' * (len(pw) - 2) + pw[-1]

def get_value_from_row(row, candidates):
    # row may be dict or pandas Series
    for c in candidates:
        if isinstance(row, dict):
            if c in row and pd.notna(row[c]):
                return row[c]
        else:
            if c in row.index and pd.notna(row[c]):
                return row[c]
    return None
