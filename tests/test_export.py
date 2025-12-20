import pytest
from io import BytesIO
import pandas as pd
import json

@pytest.fixture
def auth_token(client):
    # Register and login to get token
    client.post('/auth/register', json={
        'username': 'exportuser',
        'password': 'Password123!',
        'role': 'user'
    })
    response = client.post('/auth/login', json={
        'username': 'exportuser',
        'password': 'Password123!'
    })
    return response.json['access_token']

def test_export_failure_reproduction(client, auth_token):
    # 1. Upload a report to ensure we have data with datetime fields
    df = pd.DataFrame({
        'username': ['user1'],
        'password': ['StrongP@ssw0rd1'],
        'last_backup': ['2023-01-01']
    })
    
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    buffer.seek(0)
    
    client.post(
        '/upload-excel', 
        data={'file': (buffer, 'test_export.xlsx')},
        headers={'Authorization': f'Bearer {auth_token}'},
        content_type='multipart/form-data'
    )

    # 2. Try to export data
    response = client.get('/auth/export', headers={'Authorization': f'Bearer {auth_token}'})
    
    # 3. Assert success (bug fixed)
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    
    # Verify content
    content = json.loads(response.data)
    assert 'reports' in content
    assert len(content['reports']) == 1
    assert content['reports'][0]['filename'] == 'test_export.xlsx'
    assert 'uploaded_at' in content['reports'][0]
    assert isinstance(content['reports'][0]['uploaded_at'], str)
