import requests
try:
    r = requests.get('http://localhost:5002/', allow_redirects=False)
    print(f"Status Code: {r.status_code}")
    print("Headers:", r.headers)
    print("Body Start:", r.text[:200])
except Exception as e:
    print(e)
