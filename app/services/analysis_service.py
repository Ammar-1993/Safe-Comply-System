from app.services.notification_service import create_notification

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
