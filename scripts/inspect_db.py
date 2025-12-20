import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'safecomply.db')

def inspect():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("--- Reports Table Schema ---")
    cursor.execute("PRAGMA table_info(reports)")
    for col in cursor.fetchall():
        print(col)
        
    print("\n--- Reports Data (First 5) ---")
    try:
        cursor.execute("SELECT id, uploaded_at, typeof(uploaded_at) FROM reports LIMIT 5")
        rows = cursor.fetchall()
        for row in rows:
            print(row)
    except Exception as e:
        print(f"Error reading reports: {e}")

    conn.close()

if __name__ == '__main__':
    inspect()
