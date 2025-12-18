from flask import Blueprint, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.models import Account, LoginHistory, Report, User
from app.auth_utils import require_auth, generate_token
from app.services.policy_service import check_password_policy, get_password_checks
from app.utils import get_riyadh_time
import json
from io import BytesIO

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        ip_address = request.remote_addr or 'unknown'
        login_at = get_riyadh_time().isoformat()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()

        if not account:
            log = LoginHistory(username=username, login_at=login_at, ip_address=ip_address, status='failed_user_not_found')
            db.session.add(log)
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401

        if not check_password_hash(account.password_hash, password):
            log = LoginHistory(username=username, login_at=login_at, ip_address=ip_address, status='failed_wrong_password')
            db.session.add(log)
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401

        log = LoginHistory(username=username, login_at=login_at, ip_address=ip_address, status='success')
        db.session.add(log)
        db.session.commit()
        
        token = generate_token(account.username, account.role)
        return jsonify({'access_token': token, 'role': account.role, 'username': account.username}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        if not check_password_policy(password):
            checks = get_password_checks(password)
            errors = []
            if not checks['length']: errors.append("at least 12 characters")
            if not checks['uppercase']: errors.append("an uppercase letter")
            if not checks['lowercase']: errors.append("a lowercase letter")
            if not checks['digit']: errors.append("a number")
            if not checks['special']: errors.append("a special character")
            
            error_msg = "Password is too weak. It must contain: " + ", ".join(errors)
            return jsonify({'error': error_msg}), 400

        existing = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        if existing:
            return jsonify({'error': 'Username already exists'}), 400
            
        password_hash = generate_password_hash(password)
        new_account = Account(username=username, password_hash=password_hash, role=role)
        db.session.add(new_account)
        db.session.commit()

        return jsonify({'message': 'Account created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/change-password', methods=['POST'])
@require_auth()
def change_password():
    try:
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400
        
        username = request.user.get('sub')
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        
        if not account:
            return jsonify({'error': 'User not found'}), 404
        
        if not check_password_hash(account.password_hash, current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        if not check_password_policy(new_password):
            checks = get_password_checks(new_password)
            return jsonify({
                'error': 'New password does not meet security requirements',
                'checks': checks
            }), 400
        
        account.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/profile', methods=['GET'])
@require_auth()
def get_profile():
    try:
        username = request.user.get('sub')
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        
        if not account:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': account.id,
            'username': account.username,
            'role': account.role,
            'email': account.email or f'{account.username}@company.com',
            'profile_picture': account.profile_picture
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/profile', methods=['PUT'])
@require_auth()
def update_profile():
    try:
        data = request.get_json() or {}
        new_email = data.get('email')
        username = request.user.get('sub')
        
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        if new_email:
            account.email = new_email
            db.session.commit()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/profile/picture', methods=['POST'])
@require_auth()
def update_picture():
    try:
        data = request.get_json() or {}
        picture_data = data.get('picture')
        
        if not picture_data:
            return jsonify({'error': 'No picture data provided'}), 400
        
        if not picture_data.startswith('data:image/'):
            return jsonify({'error': 'Invalid image format. Must be base64 data URL'}), 400
        
        if len(picture_data) > 700000:
            return jsonify({'error': 'Image too large. Maximum size is 500KB'}), 400
        
        username = request.user.get('sub')
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        account.profile_picture = picture_data
        db.session.commit()
        
        return jsonify({'message': 'Profile picture updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/history', methods=['GET'])
@require_auth()
def get_history():
    try:
        username = request.user.get('sub')
        history = db.session.execute(
            db.select(LoginHistory)
            .filter_by(username=username)
            .order_by(LoginHistory.login_at.desc())
            .limit(10)
        ).scalars().all()
        
        return jsonify({'history': [{
            'login_at': h.login_at,
            'ip_address': h.ip_address,
            'status': h.status
        } for h in history]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/export', methods=['GET'])
@require_auth()
def export_data():
    try:
        username = request.user.get('sub')
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        reports = db.session.execute(db.select(Report).filter_by(uploaded_by=username)).scalars().all()
        
        export_data = {
            'exported_at': get_riyadh_time().isoformat(),
            'profile': {
                'id': account.id,
                'username': account.username,
                'role': account.role,
                'email': account.email or f'{account.username}@company.com'
            },
            'reports': [{
                'id': r.id,
                'filename': r.filename,
                'uploaded_at': r.uploaded_at,
                'total': r.total,
                'valid': r.valid,
                'invalid': r.invalid,
                'overall_score': r.overall_score
            } for r in reports],
            'report_count': len(reports)
        }
        
        buffer = BytesIO()
        buffer.write(json.dumps(export_data, indent=2).encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'safecomply_export_{username}.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/delete-account', methods=['DELETE'])
@require_auth()
def delete_account():
    try:
        data = request.get_json() or {}
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password confirmation required'}), 400
        
        username = request.user.get('sub')
        
        if username == 'admin':
            return jsonify({'error': 'Cannot delete the main admin account'}), 400
        
        account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
        
        if not account:
            return jsonify({'error': 'User not found'}), 404
        
        if not check_password_hash(account.password_hash, password):
            return jsonify({'error': 'Incorrect password'}), 401
        
        reports = db.session.execute(db.select(Report).filter_by(uploaded_by=username)).scalars().all()
        for r in reports:
            db.session.delete(r)
            
        db.session.execute(db.delete(LoginHistory).filter_by(username=username))
        db.session.delete(account)
        db.session.commit()
        
        return jsonify({'message': 'Account deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
