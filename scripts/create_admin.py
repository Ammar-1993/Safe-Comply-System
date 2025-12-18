from app import create_app, db
from app.models import Account, User
from werkzeug.security import generate_password_hash
from app.utils import get_riyadh_time

app = create_app()

with app.app_context():
    username = 'admin'
    password = 'Admin123!'
    email = 'admin@safecomply.com'
    
    existing_account = db.session.execute(db.select(Account).filter_by(username=username)).scalar_one_or_none()
    
    if existing_account:
        print(f"Admin account '{username}' already exists.")
        # Update password just in case
        existing_account.password_hash = generate_password_hash(password)
        db.session.commit()
        print(f"Password updated for '{username}'.")
    else:
        new_account = Account(
            username=username,
            password_hash=generate_password_hash(password),
            role='admin',
            email=email
        )
        db.session.add(new_account)
        
        # Also create a User profile if needed (depending on your model structure)
        # Checking User model
        existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if not existing_user:
            new_user = User(
                username=username,
                masked_password='***', # Placeholder
                password_strength_score=100,
                password_strength_label='Strong',
                last_checked=get_riyadh_time().isoformat()
            )
            db.session.add(new_user)
            
        db.session.commit()
        print(f"Admin account '{username}' created successfully.")
