import pytest
from app.models import Account
from app.extensions import db

@pytest.fixture
def admin_token(client):
    # Ensure admin exists
    with client.application.app_context():
        if not db.session.execute(db.select(Account).filter_by(username='admin')).scalar_one_or_none():
            from werkzeug.security import generate_password_hash
            admin = Account(username='admin', password_hash=generate_password_hash('Admin123!'), role='admin')
            db.session.add(admin)
            db.session.commit()

    response = client.post('/auth/login', json={
        'username': 'admin',
        'password': 'Admin123!'
    })
    return response.json['access_token']

def test_admin_list_users(client, admin_token):
    response = client.get('/admin/users', headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 200
    assert 'users' in response.json
    assert len(response.json['users']) > 0

def test_admin_delete_user(client, admin_token):
    # Create a dummy user to delete
    with client.application.app_context():
        from werkzeug.security import generate_password_hash
        user = Account(username='todelete', password_hash=generate_password_hash('User123!'), role='user')
        db.session.add(user)
        db.session.commit()

    response = client.delete('/admin/users/todelete', headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'User todelete deleted successfully'

def test_admin_delete_self_fail(client, admin_token):
    response = client.delete('/admin/users/admin', headers={'Authorization': f'Bearer {admin_token}'})
    assert response.status_code == 400
    assert response.json['error'] == 'Cannot delete the main admin account'
