import sqlite3
from werkzeug.security import generate_password_hash

# 1. الاتصال بقاعدة البيانات
db_path = 'safecomply.db'
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 2. بيانات المدقق
username = "auditor"
email = "auditor@safecomply.com"
password = "auditor_password_123"
role = "auditor"

print(f"Connecting to database: {db_path}...")

try:
    # 3. حذف الحساب القديم من جدول accounts لتجنب التكرار
    c.execute("DELETE FROM accounts WHERE username = ?", (username,))
    conn.commit()
    print("Old auditor account removed (if existed).")

    # 4. تشفير كلمة المرور وإضافة المستخدم الجديد
    password_hash = generate_password_hash(password)
    
    c.execute('''
        INSERT INTO accounts (username, password_hash, role, email)
        VALUES (?, ?, ?, ?)
    ''', (username, password_hash, role, email))
    
    conn.commit()
    
    print("--------------------------------------------------")
    print("✅ Success! Auditor account restored.")
    print(f"👤 Username: {username}")
    print(f"🔑 Password: {password}")
    print("--------------------------------------------------")

except sqlite3.OperationalError as e:
    print(f"❌ Database Error: {e}")
except Exception as e:
    print(f"❌ Unexpected Error: {e}")

finally:
    conn.close()