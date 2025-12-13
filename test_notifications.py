
import sqlite3
import datetime

DB_PATH = 'safecomply.db'

def create_manual_notification(username, title, message, n_type='info'):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        created_at = datetime.datetime.utcnow().isoformat()
        cur.execute(
            'INSERT INTO notifications (username, title, message, type, is_read, created_at) VALUES (?, ?, ?, ?, 0, ?)',
            (username, title, message, n_type, created_at)
        )
        conn.commit()
        conn.close()
        print(f"[SUCCESS] Created '{n_type}' notification for user '{username}'")
    except Exception as e:
        print(f"[ERROR] Failed to create notification: {e}")

if __name__ == "__main__":
    print("--- Manual Notification Injector ---")
    username = input("Enter username (default: admin): ") or "admin"
    
    print("\nSelect Notification Type to Inject:")
    print("1. Success (Report Ready)")
    print("2. Warning (Score Drop)")
    print("3. Critical (Security Alert)")
    print("4. Info (General Update)")
    
    choice = input("Choice (1-4): ")
    
    if choice == '1':
        create_manual_notification(username, "Analysis Complete", "Your compliance report has been successfully generated.", "success")
    elif choice == '2':
        create_manual_notification(username, "Compliance Warning", "Your overall score has dropped by 5% since last week.", "warning")
    elif choice == '3':
        create_manual_notification(username, "CRITICAL ALERT", "Unauthorized backup access detected on Server A!", "critical")
    else:
        create_manual_notification(username, "System Update", "The system will undergo maintenance tonight at 2 AM.", "info")
    
    print("\nDone! Check your dashboard bell icon in ~15 seconds (or refresh).")
