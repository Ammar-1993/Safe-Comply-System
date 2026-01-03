from flask import Blueprint, render_template

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('index.html')

@main_bp.route('/signin.html')
def signin():
    return render_template('signin.html')

@main_bp.route('/signup.html')
def signup():
    return render_template('Signup.html')

@main_bp.route('/dashboard.html')
def dashboard():
    return render_template('dashboard.html')

@main_bp.route('/password-policies.html')
def password_policies():
    return render_template('password-policies.html')

@main_bp.route('/backup-policies.html')
def backup_policies():
    return render_template('backup-policies.html')

@main_bp.route('/reports.html')
def reports():
    return render_template('reports.html')

@main_bp.route('/compliance-report-view.html')
def report_view():
    return render_template('compliance-report-view.html')

@main_bp.route('/recommendations.html')
def recommendations():
    return render_template('recommendations.html')

@main_bp.route('/settings.html')
def settings():
    return render_template('settings.html')

@main_bp.route('/policies.html')
def policies():
    return render_template('policies.html')

