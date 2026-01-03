from flask import Blueprint, request, jsonify, send_file
from app.extensions import db
from app.models import Report, User
from app.auth_utils import require_auth
from app.services.policy_service import check_password_policy, get_password_checks, calculate_strength, evaluate_backup_policy
from app.services.analysis_service import generate_ai_analysis
from app.services.notification_service import create_notification
from app.utils import get_riyadh_time, mask_password
import pandas as pd
import json
from io import BytesIO
from sqlalchemy import select

reports_bp = Blueprint('reports', __name__)

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

        uploaded_at = get_riyadh_time()
        
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
        
        # Reconstruct results for AI Analysis
        results = []
        for u in users:
            backup_checks = json.loads(u.backup_checks or '{}')
            results.append({
                'strength': u.strength,
                'backup_checks': backup_checks
            })
            
        # Generate AI Analysis
        # We need previous score for trend analysis, fetch it
        prev_report = db.session.execute(
            select(Report).where(Report.uploaded_at < report.uploaded_at).order_by(Report.uploaded_at.desc()).limit(1)
        ).scalar_one_or_none()
        previous_score = prev_report.overall_score if prev_report else None
        
        alerts, recommendations = generate_ai_analysis(results, len(results), current_score=report.overall_score, previous_score=previous_score)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
            
            elements = []
            styles = getSampleStyleSheet()
            
            # --- Header ---
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=26, textColor=colors.HexColor('#2c3e50'), spaceAfter=10, alignment=TA_CENTER, fontName='Helvetica-Bold')
            elements.append(Paragraph('AI Compliance Report', title_style))
            elements.append(Spacer(1, 20))
            
            # --- Metadata ---
            meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#7f8c8d'), spaceAfter=2)
            elements.append(Paragraph(f'<b>Report ID:</b> {report.id}', meta_style))
            elements.append(Paragraph(f'<b>Filename:</b> {report.filename}', meta_style))
            elements.append(Paragraph(f'<b>Generated:</b> {report.uploaded_at}', meta_style))
            elements.append(Spacer(1, 25))
            
            # --- Summary Section ---
            h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#2c3e50'), spaceAfter=12, fontName='Helvetica-Bold')
            elements.append(Paragraph('Executive Summary', h2_style))
            
            summary_data = [
                ['Metric', 'Value'],
                ['Overall Compliance Score', f"{report.overall_score}%"],
                ['Total Users', str(report.total)],
                ['Policies Analyzed', '2 (Password, Backup)'],
                ['Alerts Detected', str(len(alerts))]
            ]
            
            summary_table = Table(summary_data, colWidths=[3.5*inch, 2*inch], hAlign='LEFT')
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('TOPPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 25))
            
            # --- AI Insights (Alerts & Recommendations) ---
            if alerts:
                elements.append(Paragraph('🚨 AI-Detected Alerts', h2_style))
                for alert in alerts:
                    color = '#e74c3c' if alert['severity'] == 'high' else ('#f39c12' if alert['severity'] == 'medium' else '#27ae60')
                    alert_title_style = ParagraphStyle('AlertTitle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor(color), fontName='Helvetica-Bold', spaceAfter=2)
                    elements.append(Paragraph(f"• {alert['title']}", alert_title_style))
                    elements.append(Paragraph(f"&nbsp;&nbsp; {alert['desc']}", styles['Normal']))
                    elements.append(Spacer(1, 8))
                elements.append(Spacer(1, 15))

            if recommendations:
                elements.append(Paragraph('💡 AI Recommendations', h2_style))
                for rec in recommendations:
                    rec_title_style = ParagraphStyle('RecTitle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#2980b9'), fontName='Helvetica-Bold', spaceAfter=2)
                    elements.append(Paragraph(f"• {rec['title']}", rec_title_style))
                    elements.append(Paragraph(f"&nbsp;&nbsp; {rec['desc']}", styles['Normal']))
                    elements.append(Spacer(1, 8))
                elements.append(Spacer(1, 25))

            # --- User Details Table ---
            elements.append(Paragraph('Detailed User Analysis', h2_style))
            
            # Table Header
            user_data = [['ID', 'Username', 'Password Strength', 'Backup Status', 'Result']]
            
            # Table Body
            for u in users: # Show all users, or limit if needed. PDF can handle many pages.
                # Strength Color
                s_val = u.strength
                s_color = '#27ae60' if s_val >= 75 else ('#f39c12' if s_val >= 50 else '#e74c3c')
                strength_cell = Paragraph(f'<font color="{s_color}"><b>{s_val}%</b></font>', styles['Normal'])
                
                # Backup Status
                b_checks = json.loads(u.backup_checks or '{}')
                b_ok = all(b_checks.values()) if b_checks else False
                b_text = "Active" if b_ok else "Failed"
                b_color = '#27ae60' if b_ok else '#e74c3c'
                backup_cell = Paragraph(f'<font color="{b_color}"><b>{b_text}</b></font>', styles['Normal'])
                
                # Result Status
                is_compliant = bool(u.is_valid) # Assuming is_valid covers overall compliance for now, or combine with backup
                # Web view logic: user.isValid ? Compliant : Non-Compliant. 
                # Note: In upload_excel, is_valid is purely password policy. 
                # But let's stick to the web view's "Result" column which uses user.isValid.
                r_text = "Compliant" if is_compliant else "Non-Compliant"
                r_color = '#27ae60' if is_compliant else '#e74c3c'
                result_cell = Paragraph(f'<font color="{r_color}"><b>{r_text}</b></font>', styles['Normal'])
                
                user_data.append([
                    str(u.row_index),
                    Paragraph(u.username, styles['Normal']), # Wrap username to avoid overflow
                    strength_cell,
                    backup_cell,
                    result_cell
                ])
            
            # Column Widths
            col_widths = [0.6*inch, 2.0*inch, 1.5*inch, 1.5*inch, 1.5*inch]
            
            user_table = Table(user_data, colWidths=col_widths, repeatRows=1)
            user_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('TOPPADDING', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ecf0f1')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fbfcfc')])
            ]))
            elements.append(user_table)
            
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
        
        # Reconstruct results for AI Analysis
        results = []
        data = []
        for u in users:
            checks_dict = json.loads(u.checks or '{}')
            backup_dict = json.loads(u.backup_checks or '{}')
            
            # For AI Analysis
            results.append({
                'strength': u.strength,
                'backup_checks': backup_dict
            })
            
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
        
        # Generate AI Analysis
        prev_report = db.session.execute(
            select(Report).where(Report.uploaded_at < report.uploaded_at).order_by(Report.uploaded_at.desc()).limit(1)
        ).scalar_one_or_none()
        previous_score = prev_report.overall_score if prev_report else None
        
        alerts, recommendations = generate_ai_analysis(results, len(results), current_score=report.overall_score, previous_score=previous_score)
        
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
            
            # AI Insights Sheet
            insights_data = []
            for a in alerts:
                insights_data.append({'Type': 'Alert', 'Severity': a['severity'].upper(), 'Title': a['title'], 'Description': a['desc']})
            for r in recommendations:
                insights_data.append({'Type': 'Recommendation', 'Severity': '-', 'Title': r['title'], 'Description': r['desc']})
                
            if insights_data:
                insights_df = pd.DataFrame(insights_data)
                insights_df.to_excel(writer, sheet_name='AI Insights', index=False)
        
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'compliance_data_{report.id}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
