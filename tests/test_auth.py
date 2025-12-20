def test_register(client):
    response = client.post('/auth/register', json={
        'username': 'testuser',
        'password': 'Password123!',
        'role': 'user'
    })
    assert response.status_code == 201
    assert b'Account created successfully' in response.data

def test_login(client):
    # Register first
    client.post('/auth/register', json={
        'username': 'testuser',
        'password': 'Password123!',
        'role': 'user'
    })
    
    # Login
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'Password123!'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_login_invalid(client):
    response = client.post('/auth/login', json={
        'username': 'wrong',
        'password': 'wrong'
    })
    assert response.status_code == 401
    assert response.json['error'] == 'Invalid credentials'
