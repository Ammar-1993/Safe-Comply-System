
import requests
import sys

BASE_URL = 'http://localhost:5002'

def login(username, password):
    resp = requests.post(f'{BASE_URL}/auth/login', json={'username': username, 'password': password})
    if resp.status_code == 200:
        return resp.json()['access_token']
    return None

def upload_file(token, username):
    try:
        files = {'file': ('sample_compliance.xlsx', open('sample_compliance.xlsx', 'rb'), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
    except FileNotFoundError:
        print("sample_compliance.xlsx not found! Run create_sample.py first.")
        return None
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.post(f'{BASE_URL}/upload-excel', headers=headers, files=files)
    if resp.status_code == 200:
        rid = resp.json().get('report_id')
        print(f"[{username}] Upload Success -> Report ID: {rid}")
        return rid
    else:
        print(f"[{username}] Upload Failed: {resp.status_code} - {resp.text}")
        return None

def list_reports(token, username):
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.get(f'{BASE_URL}/reports', headers=headers)
    if resp.status_code == 200:
        reports = resp.json()['reports']
        count = len(reports)
        owners = set(r.get('uploaded_by') for r in reports)
        print(f"[{username}] List Reports -> Count: {count}, Owners: {owners}")
        return reports
    return []

def check_admin_users(token, username):
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.get(f'{BASE_URL}/admin/users', headers=headers)
    if resp.status_code == 200:
        print(f"[{username}] Admin List Users -> Success (Count: {len(resp.json()['users'])})")
    else:
        print(f"[{username}] Admin List Users -> Failed ({resp.status_code})")

# 1. Admin Actions
print("\n--- ADMIN ACTIONS ---")
admin_token = login('admin', 'Admin123!')
if admin_token:
    admin_rid = upload_file(admin_token, 'admin')
    check_admin_users(admin_token, 'admin')
else:
    print("Admin Login Failed")
    sys.exit(1)

# 2. User Actions (Register new user to ensure clean state)
print("\n--- USER ACTIONS ---")
reg_resp = requests.post(f'{BASE_URL}/auth/register', json={'username': 'rbac_user', 'password': 'User123!'})
user_token = login('rbac_user', 'User123!')

if user_token:
    # Upload user file
    user_rid = upload_file(user_token, 'rbac_user')
    
    # List reports (Should see ONLY their own)
    user_reports = list_reports(user_token, 'rbac_user')
    
    # Verify isolation
    can_see_admin_report = any(r['id'] == admin_rid for r in user_reports)
    print(f"[{'rbac_user'}] Can see Admin report? {'YES (FAIL)' if can_see_admin_report else 'NO (PASS)'}")
    
    # Try Admin Action
    check_admin_users(user_token, 'rbac_user') # Should fail
else:
    print("User Login Failed")

# 3. Auditor Actions
print("\n--- AUDITOR ACTIONS ---")
auditor_token = login('auditor', 'Auditor123!')
if auditor_token:
    aud_reports = list_reports(auditor_token, 'auditor')
    # Use IDs for checking
    has_admin_rep = any(r['id'] == admin_rid for r in aud_reports)
    has_user_rep = any(r['id'] == user_rid for r in aud_reports)
    print(f"[{'auditor'}] Can see Admin report? {'YES (PASS)' if has_admin_rep else 'NO (FAIL)'}")
    print(f"[{'auditor'}] Can see User report? {'YES (PASS)' if has_user_rep else 'NO (FAIL)'}")
    
    check_admin_users(auditor_token, 'auditor') # Should fail (Admin only)

print("\n--- VERIFICATION COMPLETE ---")
