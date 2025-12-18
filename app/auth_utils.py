from functools import wraps
from flask import request, jsonify, current_app
import jwt

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth or not auth.startswith('Bearer '):
                return jsonify({'error': 'Unauthorized'}), 401
            token = auth.split(None, 1)[1]
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            except Exception as e:
                return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
            role = payload.get('role')
            if roles:
                allowed = roles if isinstance(roles, (list, tuple)) else [roles]
                if role not in allowed:
                    return jsonify({'error': 'Forbidden', 'message': 'insufficient role'}), 403
            # attach user to request for handlers
            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

def generate_token(username, role):
    from datetime import datetime, timedelta
    exp = datetime.utcnow() + timedelta(hours=8)
    payload = {
        'sub': username,
        'role': role,
        'exp': int(exp.timestamp())
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
