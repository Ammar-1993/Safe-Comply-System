
import sqlite3

DB_PATH = 'safecomply.db'

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute('ALTER TABLE reports ADD COLUMN uploaded_by TEXT')
        print("Successfully added 'uploaded_by' column.")
    except sqlite3.OperationalError as e:
        if 'duplicate column name' in str(e):
            print("Column 'uploaded_by' already exists.")
        else:
            print(f"Error: {e}")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    migrate()
