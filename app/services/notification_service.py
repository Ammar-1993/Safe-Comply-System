from app.extensions import db
from app.models import Notification
from app.utils import get_riyadh_time

def create_notification(username, title, message, n_type='info'):
    """Helper to create a notification"""
    try:
        created_at = get_riyadh_time()
        notif = Notification(username=username, title=title, message=message, type=n_type, created_at=created_at)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        print(f"Error creating notification: {e}")
