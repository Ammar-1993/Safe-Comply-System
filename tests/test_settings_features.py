import pytest
from app.models import Account, LoginHistory
from app.extensions import db
from werkzeug.security import check_password_hash

@pytest.fixture
def user_token(client):
    client.post('/auth/register', json={
        'username': 'settingsuser',
        'password': 'Password123!',
        'role': 'user'
    })
    response = client.post('/auth/login', json={
        'username': 'settingsuser',
        'password': 'Password123!'
    })
    return response.json['access_token']

def test_get_login_history(client, user_token):
    response = client.get('/auth/history', headers={'Authorization': f'Bearer {user_token}'})
    assert response.status_code == 200
    assert 'history' in response.json
    # Should have at least one entry from the login in the fixture
    assert len(response.json['history']) >= 1
    assert response.json['history'][0]['status'] == 'success'

def test_update_profile_email(client, user_token):
    response = client.put('/auth/profile', 
        json={'email': 'newemail@example.com'},
        headers={'Authorization': f'Bearer {user_token}'}
    )
    assert response.status_code == 200
    
    # Verify update
    response = client.get('/auth/profile', headers={'Authorization': f'Bearer {user_token}'})
    assert response.json['email'] == 'newemail@example.com'

def test_change_password(client, user_token):
    response = client.post('/auth/change-password',
        json={
            'current_password': 'Password123!',
            'new_password': 'NewPassword123!'
        },
        headers={'Authorization': f'Bearer {user_token}'}
    )
    assert response.status_code == 200
    
    # Verify login with new password
    response = client.post('/auth/login', json={
        'username': 'settingsuser',
        'password': 'NewPassword123!'
    })
    assert response.status_code == 200

def test_delete_account(client):
    # Create a separate user for deletion
    client.post('/auth/register', json={
        'username': 'todelete_user',
        'password': 'Password123!',
        'role': 'user'
    })
    login_resp = client.post('/auth/login', json={
        'username': 'todelete_user',
        'password': 'Password123!'
    })
    token = login_resp.json['access_token']
    
    response = client.delete('/auth/delete-account',
        json={'password': 'Password123!'},
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 200
    
    # Verify account is gone
    with client.application.app_context():
        account = db.session.execute(db.select(Account).filter_by(username='todelete_user')).scalar_one_or_none()
        assert account is None
