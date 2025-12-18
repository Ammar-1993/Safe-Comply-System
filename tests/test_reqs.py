
import requests
import json

# 1. Login as Admin
url = 'http://localhost:5002/auth/login'
payload = {'username': 'admin', 'password': 'Admin123!'}
headers = {'Content-Type': 'application/json'}

try:
    resp = requests.post(url, json=payload)
    if resp.status_code == 200:
        data = resp.json()
        token = data['access_token']
        print(f"Login Success. Token: {token[:10]}...")
        
        # 2. Upload File as Admin
        upload_url = 'http://localhost:5002/upload-excel'
        files = {'file': ('sample_compliance.xlsx', open('sample_compliance.xlsx', 'rb'), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        auth_header = {'Authorization': f'Bearer {token}'}
        
        up_resp = requests.post(upload_url, headers=auth_header, files=files)
        
        if up_resp.status_code == 200:
            up_data = up_resp.json()
            report_id = up_data.get('report_id')
            print(f"Upload Success. Report ID: {report_id}")
            print(f"Overall Score: {up_data.get('overall_score')}")
            
            # 3. View Detailed Report as Admin (Should succeed)
            detail_url = f'http://localhost:5002/reports/{report_id}'
            det_resp = requests.get(detail_url, headers=auth_header)
            
            if det_resp.status_code == 200:
                det_data = det_resp.json()
                print(f"Detailed Report Access: SUCCESS")
                print(f"First User: {det_data['results'][0]['username']}")
            else:
                print(f"Detailed Report Access: FAILED ({det_resp.status_code})")
                
        else:
            print(f"Upload Failed: {up_resp.text}")

    else:
        print(f"Login Failed: {resp.text}")

    # 4. Create Standard User
    reg_url = 'http://localhost:5002/auth/register'
    reg_payload = {'username': 'testuser', 'password': 'UserPass123!'}
    reg_resp = requests.post(reg_url, json=reg_payload)
    print(f"User Register: {reg_resp.status_code}")
    
    # 5. Login as Standard User
    user_resp = requests.post(url, json=reg_payload)
    if user_resp.status_code == 200:
        user_token = user_resp.json()['access_token']
        user_auth = {'Authorization': f'Bearer {user_token}'}
        print("User Login Success")
        
        # 6. Attempt to View Detailed Report as User (Should Fail)
        # We use the SAME report_id from the admin upload to see if user can view it
        if 'report_id' in locals():
            user_det_url = f'http://localhost:5002/reports/{report_id}'
            user_det_resp = requests.get(user_det_url, headers=user_auth)
            
            if user_det_resp.status_code == 403:
                print("User Access Restriction: VERIFIED (403 Forbidden)")
            else:
                print(f"User Access Restriction: FAILED (Got {user_det_resp.status_code})")

except Exception as e:
    print(f"Error: {e}")
