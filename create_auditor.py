
import requests

url = 'http://localhost:5002/auth/register'
payload = {'username': 'auditor', 'password': 'Auditor123!', 'role': 'auditor'}

try:
    resp = requests.post(url, json=payload)
    if resp.status_code == 201:
        print("Success: Auditor account created.")
        print("Username: auditor")
        print("Password: Auditor123!")
    elif resp.status_code == 400 and 'already exists' in resp.text:
         print("Auditor account already exists.")
         print("Username: auditor")
         print("Password: Auditor123! (If you haven't changed it)")
    else:
        print(f"Failed: {resp.status_code} - {resp.text}")
except Exception as e:
    print(f"Error: {e}")
