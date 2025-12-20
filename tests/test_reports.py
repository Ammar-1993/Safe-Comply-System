import pytest
from io import BytesIO
import pandas as pd

@pytest.fixture
def auth_token(client):
    # Register and login to get token
    client.post('/auth/register', json={
        'username': 'testadmin',
        'password': 'Password123!',
        'role': 'admin'
    })
    response = client.post('/auth/login', json={
        'username': 'testadmin',
        'password': 'Password123!'
    })
    return response.json['access_token']

def test_upload_excel(client, auth_token):
    # Create a dummy Excel file
    df = pd.DataFrame({
        'username': ['user1', 'user2'],
        'password': ['StrongP@ssw0rd1', 'weak'],
        'last_backup': ['2023-01-01', '2023-01-01']
    })
    
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    buffer.seek(0)
    
    data = {
        'file': (buffer, 'test_report.xlsx')
    }
    
    response = client.post(
        '/upload-excel', 
        data=data,
        headers={'Authorization': f'Bearer {auth_token}'},
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 200
    assert response.json['total'] == 2
    assert response.json['valid'] == 1
    assert response.json['invalid'] == 1

def test_list_reports(client, auth_token):
    response = client.get(
        '/reports',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 200
    assert 'reports' in response.json

def test_get_recommendations(client, auth_token):
    # Ensure a report exists
    df = pd.DataFrame({
        'username': ['user1'],
        'password': ['weak'],
        'last_backup': ['2020-01-01']
    })
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    buffer.seek(0)
    
    client.post(
        '/upload-excel', 
        data={'file': (buffer, 'test_rec.xlsx')},
        headers={'Authorization': f'Bearer {auth_token}'},
        content_type='multipart/form-data'
    )
    
    response = client.get(
        '/api/recommendations',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    
    assert response.status_code == 200
    assert response.json['has_report'] is True
    assert len(response.json['alerts']) > 0
