from flask import Blueprint, request, jsonify, send_file
from app.extensions import db
from app.models import Report, User, Notification
from app.auth_utils import require_auth
from app.services.policy_service import check_password_policy, get_password_checks, calculate_strength, evaluate_backup_policy
from app.utils import get_riyadh_time, mask_password
import pandas as pd
import json
from io import BytesIO
from sqlalchemy import select

reports_bp = Blueprint('reports', __name__)

def generate_ai_analysis(results, total, current_score=0, previous_score=None, username=None):
    """Generate alerts and recommendations based on analysis results and historical trends."""
    
    pwd_weak_count = sum(1 for r in results if r.get('strength', 0) < 60)
    # backup_checks is a dict in the results list here
    backup_ok_count = sum(1 for r in results if all(r.get('backup_checks', {}).values()))
    backup_fail_count = total - backup_ok_count
    
    alerts = []
    recommendations = []
    
    # Trend Analysis
    if previous_score is not None:
        diff = current_score - previous_score
        if diff < -10:
            title = f'CRITICAL: Compliance Score Dropped by {abs(diff)}%'
            msg = f'Significant regression detected. Score fell from {previous_score}% to {current_score}%.'
            alerts.append({'severity': 'high', 'title': title, 'desc': msg})
            recommendations.append({'title': 'Immediate Audit Required', 'desc': 'Review recent changes or user onboarding processes that caused this drop.'})
            
            if username:
                create_notification(username, title, msg, 'error')
                
        elif diff < -5:
             title = f'Warning: Compliance Score Dropped by {abs(diff)}%'
             msg = f'Score fell from {previous_score}% to {current_score}%.'
             alerts.append({'severity': 'medium', 'title': title, 'desc': msg})
             
             if username:
                create_notification(username, title, msg, 'warning')
                
        elif diff > 5:
            title = f'Positive Trend: Score Improved by {diff}%'
            msg = f'Compliance rose from {previous_score}% to {current_score}%.'
            alerts.append({'severity': 'low', 'title': title, 'desc': msg})
            
            if username:
                create_notification(username, title, msg, 'success')

    # Analyze Password Policy
    if total > 0 and (pwd_weak_count / total) >= 0.05:
        alerts.append({
            'severity': 'high',
            'title': f'High Risk: Weak Passwords for {pwd_weak_count} users',
            'desc': 'Password strength below recommended standards for a significant portion of users.'
        })
    elif pwd_weak_count > 0:
        alerts.append({
            'severity': 'medium',
            'title': f'Medium: Weak Passwords for {pwd_weak_count} users',
            'desc': 'Some users have weak passwords.'
        })
        
    if pwd_weak_count > 0:
        recommendations.append({
            'title': f'Enforce stronger passwords for {pwd_weak_count} users',
            'desc': 'Require minimum length of 14 and enforce complexity; prompt users to change weak passwords.'
        })

    # Analyze Backup Policy
    if backup_fail_count > 0 and (backup_fail_count / max(1, total)) >= 0.1:
        alerts.append({
            'severity': 'high',
            'title': f'High Risk: Backup Failures affecting {backup_fail_count} users',
            'desc': 'Multiple backup failures detected — data loss risk is high.'
        })
    elif backup_fail_count > 0:
        alerts.append({
            'severity': 'medium',
            'title': f'Medium: {backup_fail_count} Backup Failures',
            'desc': 'Some users have missing or outdated backups.'
        })
        
    if backup_fail_count > 0:
        recommendations.append({
            'title': 'Investigate backup failures',
            'desc': 'Run recovery readiness checks and repair failing backup jobs.'
        })

    # General recommendations
    if not alerts:
        alerts.append({'severity': 'low', 'title': 'No critical alerts detected', 'desc': 'All checks are within acceptable thresholds.'})
        recommendations.append({'title': 'Maintain current settings', 'desc': 'No immediate recommendations.'})
        
    return alerts, recommendations

def create_notification(username, title, message, n_type='info'):
    """Helper to create a notification"""
    try:
        created_at = get_riyadh_time().isoformat()
        notif = Notification(username=username, title=title, message=message, type=n_type, created_at=created_at)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        print(f"Error creating notification: {e}")

@reports_bp.route('/upload-excel', methods=['POST'])
@require_auth(roles=['admin','auditor','user'])
def upload_excel():
    """Upload and analyze Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Read Excel file
        df = pd.read_excel(file)

        results = []
        for idx, row in df.iterrows():
            # Find password column
            password = ''
            for col in ['password', 'Password', 'كلمة_المرور', 'كلمة المرور']:
                if col in df.columns:
                    password = str(row[col]) if pd.notna(row[col]) else ''
                    break

            # Find username column
            username = ''
            for col in ['username', 'Username', 'المستخدم', 'اسم المستخدم']:
                if col in df.columns:
                    username = str(row[col]) if pd.notna(row[col]) else ''
                    break

            if not username:
                username = f'User {idx + 1}'

            checks = get_password_checks(password)
            is_valid = check_password_policy(password)
            strength = calculate_strength(password, checks)
            masked = mask_password(password)

            # evaluate backup policy
            backup_checks = evaluate_backup_policy(row)

            results.append({
                'row': idx + 1,
                'username': username,
                'password': masked,
                'isValid': is_valid,
                'checks': checks,
                'strength': strength,
                'backup_checks': backup_checks
            })

        valid_count = sum(1 for r in results if r['isValid'])
        invalid_count = len(results) - valid_count
        overall_score = int(sum(r['strength'] for r in results) / len(results)) if results else 0

        # Get username from token
        username = request.user.get('sub')

        # Get Previous Score for Trend Analysis
        prev_report = db.session.execute(
            select(Report).order_by(Report.uploaded_at.desc()).limit(1)
        ).scalar_one_or_none()
        previous_score = prev_report.overall_score if prev_report else None
        
        # Generate AI Analysis
        alerts, recommendations = generate_ai_analysis(results, len(results), current_score=overall_score, previous_score=previous_score, username=username)

        uploaded_at = get_riyadh_time().isoformat()
        
        new_report = Report(
            filename=file.filename,
            uploaded_at=uploaded_at,
            total=len(results),
            valid=valid_count,
            invalid=invalid_count,
            overall_score=overall_score,
            uploaded_by=username
        )
        db.session.add(new_report)
        db.session.flush() # Get ID

        for r in results:
            new_user = User(
                report_id=new_report.id,
                row_index=r['row'],
                username=r['username'],
                masked_password=r['password'],
                is_valid=int(r['isValid']),
                checks=json.dumps(r['checks']),
                strength=int(r['strength']),
                backup_checks=json.dumps(r.get('backup_checks', {}))
            )
            db.session.add(new_user)

        db.session.commit()
        
        create_notification(username, "Analysis Complete", f"Your report for {file.filename} is ready.", "success")

        return jsonify({
            'results': results,
            'total': len(results),
            'valid': valid_count,
            'invalid': invalid_count,
            'overall_score': overall_score,
            'policies_analyzed': 2,
            'alerts_detected': len(alerts),
            'non_compliant_users': invalid_count,
            'alerts': alerts,
            'recommendations': recommendations,
            'report_id': new_report.id
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error processing file'
        }), 500

@reports_bp.route('/reports', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def list_reports():
    role = request.user.get('role')
    username = request.user.get('sub')
    
    query = select(Report).order_by(Report.uploaded_at.desc())
    
    if role not in ['admin', 'auditor']:
        query = query.filter_by(uploaded_by=username)
        
    reports = db.session.execute(query).scalars().all()
    
    return jsonify({'reports': [{
        'id': r.id, 
        'filename': r.filename, 
        'uploaded_at': r.uploaded_at, 
        'total': r.total, 
        'valid': r.valid, 
        'invalid': r.invalid, 
        'overall_score': r.overall_score, 
        'uploaded_by': r.uploaded_by
    } for r in reports]}), 200

@reports_bp.route('/reports/<int:report_id>', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def get_report(report_id):
    report = db.session.get(Report, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    current_user = request.user.get('sub')
    current_role = request.user.get('role')
    if current_role not in ['admin', 'auditor'] and report.uploaded_by != current_user:
        return jsonify({'error': 'Forbidden'}), 403

    users = report.users
    user_list = []
    for u in users:
        user_list.append({
            'row': u.row_index, 
            'username': u.username, 
            'password': u.masked_password, 
            'isValid': bool(u.is_valid), 
            'checks': json.loads(u.checks or '{}'), 
            'strength': u.strength, 
            'backup_checks': json.loads(u.backup_checks or '{}')
        })
    
    report_obj = {
        'id': report.id, 
        'filename': report.filename, 
        'uploaded_at': report.uploaded_at, 
        'total': report.total, 
        'valid': report.valid, 
        'invalid': report.invalid, 
        'overall_score': report.overall_score, 
        'results': user_list
    }
    return jsonify(report_obj), 200

@reports_bp.route('/reports/<int:report_id>', methods=['DELETE'])
@require_auth(roles=['admin','auditor','user'])
def delete_report(report_id):
    report = db.session.get(Report, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
        
    current_user = request.user.get('sub')
    current_role = request.user.get('role')
    
    if current_role != 'admin' and report.uploaded_by != current_user:
        return jsonify({'error': 'Forbidden'}), 403

    db.session.delete(report)
    db.session.commit()
    
    return jsonify({'message': 'Report deleted successfully'}), 200

@reports_bp.route('/api/reports/<int:report_id>/pdf', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def export_report_pdf(report_id):
    """Export report as PDF"""
    try:
        report = db.session.get(Report, report_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
            
        users = report.users
        
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            elements = []
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#051338'), spaceAfter=30, alignment=TA_CENTER)
            elements.append(Paragraph('AI Compliance Report', title_style))
            elements.append(Spacer(1, 12))
            
            info_style = styles['Normal']
            elements.append(Paragraph(f'<b>Report ID:</b> {report.id}', info_style))
            elements.append(Paragraph(f'<b>Filename:</b> {report.filename}', info_style))
            elements.append(Paragraph(f'<b>Generated:</b> {report.uploaded_at}', info_style))
            elements.append(Spacer(1, 20))
            
            summary_style = ParagraphStyle('SummaryTitle', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#051338'), spaceAfter=12)
            elements.append(Paragraph('Summary', summary_style))
            
            summary_data = [
                ['Metric', 'Value'],
                ['Overall Compliance Score', f"{report.overall_score}%"],
                ['Total Users', str(report.total)],
                ['Valid Passwords', str(report.valid)],
                ['Invalid Passwords', str(report.invalid)]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 20))
            
            elements.append(Paragraph('User Details', summary_style))
            
            user_data = [['#', 'Username', 'Password', 'Valid', 'Strength']]
            for u in users[:50]:
                user_data.append([
                    str(u.row_index),
                    u.username,
                    u.masked_password,
                    'Yes' if u.is_valid else 'No',
                    f"{u.strength}%"
                ])
            
            user_table = Table(user_data, colWidths=[0.5*inch, 1.5*inch, 1.5*inch, 0.8*inch, 0.8*inch])
            user_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(user_table)
            
            if len(users) > 50:
                elements.append(Spacer(1, 12))
                elements.append(Paragraph(f'<i>Note: Showing first 50 of {len(users)} users</i>', info_style))
            
            doc.build(elements)
            buffer.seek(0)
            
            return send_file(
                buffer,
                as_attachment=True,
                download_name=f'compliance_report_{report.id}.pdf',
                mimetype='application/pdf'
            )
            
        except ImportError:
            return jsonify({
                'error': 'PDF generation requires reportlab library',
                'message': 'Please install reportlab: pip install reportlab'
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@reports_bp.route('/api/reports/<int:report_id>/excel', methods=['GET'])
@require_auth(roles=['admin','auditor','user'])
def export_report_excel(report_id):
    """Export report raw data as Excel"""
    try:
        report = db.session.get(Report, report_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
            
        users = report.users
        
        data = []
        for u in users:
            checks_dict = json.loads(u.checks or '{}')
            backup_dict = json.loads(u.backup_checks or '{}')
            data.append({
                'Row': u.row_index,
                'Username': u.username,
                'Password': u.masked_password,
                'Is Valid': 'Yes' if u.is_valid else 'No',
                'Strength': u.strength,
                'Length Check': 'Pass' if checks_dict.get('length') else 'Fail',
                'Uppercase Check': 'Pass' if checks_dict.get('uppercase') else 'Fail',
                'Lowercase Check': 'Pass' if checks_dict.get('lowercase') else 'Fail',
                'Digit Check': 'Pass' if checks_dict.get('digit') else 'Fail',
                'Special Char Check': 'Pass' if checks_dict.get('special') else 'Fail',
                'Last Backup OK': 'Yes' if backup_dict.get('last_backup_ok') else 'No',
                'Backup Frequency OK': 'Yes' if backup_dict.get('freq_ok') else 'No',
                'Backup Type OK': 'Yes' if backup_dict.get('type_ok') else 'No',
                'Retention OK': 'Yes' if backup_dict.get('retention_ok') else 'No'
            })
        
        df = pd.DataFrame(data)
        
        buffer = BytesIO()
        with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='User Data', index=False)
            
            summary_df = pd.DataFrame([
                {'Metric': 'Report ID', 'Value': report.id},
                {'Metric': 'Filename', 'Value': report.filename},
                {'Metric': 'Generated At', 'Value': report.uploaded_at},
                {'Metric': 'Total Users', 'Value': report.total},
                {'Metric': 'Valid Passwords', 'Value': report.valid},
                {'Metric': 'Invalid Passwords', 'Value': report.invalid},
                {'Metric': 'Overall Score', 'Value': f"{report.overall_score}%"}
            ])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'compliance_data_{report.id}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
