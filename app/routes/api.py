from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import Notification, Report, Account
from app.auth_utils import require_auth
from app.services.policy_service import check_password_policy, get_password_checks, calculate_strength, mask_password, evaluate_backup_policy
from app.utils import get_riyadh_time
from sqlalchemy import select, func
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/notifications', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def get_notifications():
    try:
        username = request.user.get('sub')
        
        notifs = db.session.execute(
            select(Notification)
            .filter_by(username=username, is_read=False)
            .order_by(Notification.created_at.desc())
        ).scalars().all()
        
        return jsonify({
            'notifications': [{
                'id': n.id,
                'title': n.title,
                'message': n.message,
                'type': n.type,
                'is_read': n.is_read,
                'created_at': n.created_at
            } for n in notifs],
            'unread_count': len(notifs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/api/notifications/mark-read', methods=['POST'])
@require_auth(roles=['admin','auditor','user'])
def mark_notifications_read():
    try:
        username = request.user.get('sub')
        db.session.execute(
            db.update(Notification)
            .where(Notification.username == username)
            .values(is_read=True)
        )
        db.session.commit()
        return jsonify({'message': 'Marked as read'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/dashboard-stats', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def dashboard_stats():
    try:
        latest = db.session.execute(
            select(Report).order_by(Report.uploaded_at.desc()).limit(1)
        ).scalar_one_or_none()
        
        compliance_rate = latest.overall_score if latest else 0
        active_alerts = latest.invalid if latest else 0
        
        # Pending reports (last 7 days)
        # Note: uploaded_at is stored as string ISO format, so string comparison works for ISO dates
        seven_days_ago = (get_riyadh_time() - datetime.timedelta(days=7)).isoformat()
        # But wait, we need datetime import
        import datetime
        seven_days_ago = (get_riyadh_time() - datetime.timedelta(days=7)).isoformat()
        
        recent_count = db.session.execute(
            select(func.count(Report.id)).where(Report.uploaded_at > seven_days_ago)
        ).scalar()
        
        return jsonify({
            'compliance_rate': compliance_rate,
            'active_alerts': active_alerts,
            'pending_reports': recent_count,
            'policy_breakdown': {
                'password': 70, 
                'backup': 30
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/api/recommendations', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def get_recommendations_api():
    """Get AI-generated recommendations based on latest report"""
    try:
        username = request.user.get('sub')
        
        report = db.session.execute(
            select(Report).filter_by(uploaded_by=username).order_by(Report.uploaded_at.desc()).limit(1)
        ).scalar_one_or_none()
        
        if not report:
            return jsonify({'recommendations': [], 'has_report': False}), 200
            
        # We need to reconstruct the analysis. 
        # Ideally we should store alerts/recommendations in DB, but for now we regenerate them.
        # This requires importing generate_ai_analysis from reports.py or moving it to a service.
        # Let's move generate_ai_analysis to policy_service.py to avoid circular imports or duplication.
        # For now, I will import it from reports (if possible) or duplicate it.
        # Duplication is safer to avoid circular dependency if reports imports api.
        # Better: Move to policy_service.
        
        # Let's assume we moved it or duplicate it for now.
        # I'll duplicate the logic briefly or just return empty if not critical, 
        # but the user expects it.
        # Let's use the one in reports via import inside function to avoid top-level circular dependency
        from app.routes.reports import generate_ai_analysis
        
        users = report.users
        results = []
        for u in users:
            results.append({
                'strength': u.strength,
                'backup_checks': json.loads(u.backup_checks or '{}')
            })

        prev_report = db.session.execute(
            select(Report)
            .filter(Report.uploaded_by == username, Report.id != report.id)
            .order_by(Report.uploaded_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        previous_score = prev_report.overall_score if prev_report else None
        
        alerts, recommendations = generate_ai_analysis(results, len(results), report.overall_score, previous_score)
        
        return jsonify({
            'recommendations': recommendations,
            'alerts': alerts,
            'has_report': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/check-password', methods=['POST'])
def check_password():
    """Check single password"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        is_valid = check_password_policy(password)
        checks = get_password_checks(password)
        
        return jsonify({
            'isValid': is_valid,
            'checks': checks,
            'message': 'كلمة المرور صحيحة ✓' if is_valid else 'كلمة المرور لا تطابق المتطلبات'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e), 'message': 'Error processing request'}), 500

@api_bp.route('/check-passwords-bulk', methods=['POST'])
def check_passwords_bulk():
    """Check bulk passwords"""
    try:
        data = request.get_json()
        passwords_data = data.get('passwords', [])
        
        results = []
        for idx, row in enumerate(passwords_data):
            password = (row.get('password') or row.get('Password') or row.get('كلمة_المرور') or row.get('كلمة المرور') or '')
            username = (row.get('username') or row.get('Username') or row.get('المستخدم') or row.get('اسم المستخدم') or f'User {idx + 1}')
            
            checks = get_password_checks(password)
            is_valid = check_password_policy(password)
            strength = calculate_strength(password, checks)
            masked = mask_password(password)

            results.append({
                'row': idx + 1,
                'username': username,
                'password': masked,
                'isValid': is_valid,
                'checks': checks,
                'strength': strength
            })
        
        valid_count = sum(1 for r in results if r['isValid'])
        
        return jsonify({
            'results': results,
            'total': len(results),
            'valid': valid_count,
            'invalid': len(results) - valid_count
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e), 'message': 'Error processing request'}), 500

@api_bp.route('/check-backup-policy', methods=['POST'])
def check_backup_policy_endpoint():
    """Evaluate backup policy"""
    try:
        data = request.get_json() or {}
        row = {
            'last_backup_date': data.get('last_backup_date'),
            'backup_frequency': data.get('frequency'),
            'retention_days': data.get('retention')
        }
        
        checks = evaluate_backup_policy(row)
        is_compliant = checks['last_backup_ok'] and checks['freq_ok'] and checks['retention_ok']
        
        return jsonify({
            'compliant': is_compliant,
            'checks': checks
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/admin/users', methods=['GET'])
@require_auth(roles=['admin'])
def admin_list_users():
    accounts = db.session.execute(select(Account)).scalars().all()
    return jsonify({'users': [{'id': a.id, 'username': a.username, 'role': a.role} for a in accounts]}), 200

@api_bp.route('/admin/users/<username>', methods=['DELETE'])
@require_auth(roles=['admin'])
def admin_delete_user(username):
    if username == 'admin':
        return jsonify({'error': 'Cannot delete the main admin account'}), 400
        
    account = db.session.execute(select(Account).filter_by(username=username)).scalar_one_or_none()
    if not account:
        return jsonify({'error': 'User not found'}), 404
        
    db.session.delete(account)
    db.session.commit()
    
    return jsonify({'message': f'User {username} deleted successfully'}), 200
