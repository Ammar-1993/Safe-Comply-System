import pytest

def test_routes_exist(client):
    routes = [
        '/',
        '/signin.html',
        '/signup.html',
        '/dashboard.html',
        '/password-policies.html',
        '/backup-policies.html',
        '/reports.html',
        '/compliance-report-view.html',
        '/recommendations.html',
        '/settings.html',
        '/policies.html'
    ]
    
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, f"Route {route} failed with {response.status_code}"
