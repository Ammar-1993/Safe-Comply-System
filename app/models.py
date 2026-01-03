from app.extensions import db

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime)
    uploaded_by = db.Column(db.String(100))
    total = db.Column(db.Integer)
    valid = db.Column(db.Integer)
    invalid = db.Column(db.Integer)
    overall_score = db.Column(db.Integer)
    
    users = db.relationship('User', backref='report', cascade='all, delete-orphan')

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'))
    row_index = db.Column(db.Integer)
    username = db.Column(db.String(100))
    masked_password = db.Column(db.String(255))
    is_valid = db.Column(db.Integer) # 0 or 1
    checks = db.Column(db.Text) # JSON string
    strength = db.Column(db.Integer)
    backup_checks = db.Column(db.Text) # JSON string

class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(50))
    email = db.Column(db.String(255))
    profile_picture = db.Column(db.Text) # Base64

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    login_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(50))

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)
