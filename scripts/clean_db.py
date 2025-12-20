import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'safecomply.db')

def clean():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        print("Cleaning 'reports' table...")
        cursor.execute("DELETE FROM reports")
        print(f"Deleted {cursor.rowcount} rows from reports.")
        
        print("Cleaning 'users' table...")
        cursor.execute("DELETE FROM users")
        print(f"Deleted {cursor.rowcount} rows from users.")
        
        print("Cleaning 'notifications' table...")
        cursor.execute("DELETE FROM notifications")
        print(f"Deleted {cursor.rowcount} rows from notifications.")
        
        print("Cleaning 'login_history' table...")
        cursor.execute("DELETE FROM login_history")
        print(f"Deleted {cursor.rowcount} rows from login_history.")

        conn.commit()
        print("Database cleaned successfully.")
    except Exception as e:
        print(f"Error cleaning database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    clean()
