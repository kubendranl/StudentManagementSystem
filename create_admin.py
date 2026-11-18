
from database import connect_db
from werkzeug.security import generate_password_hash

email = input("Enter admin email: ").strip().lower()
password = input("Enter admin password: ")

if not email or not password:
    print("Email and password are required!")
    raise SystemExit

hashed_password = generate_password_hash(password)

conn = connect_db()

if conn is None:
    print("Database connection failed!")
    raise SystemExit

cur = conn.cursor()

try:
    cur.execute("""
        INSERT INTO admins (email, password)
        VALUES (%s, %s)
        ON CONFLICT (email)
        DO UPDATE SET password = EXCLUDED.password
    """, (email, hashed_password))

    conn.commit()
    print("Admin account created successfully!")

except Exception as e:
    conn.rollback()
    print("Error:", e)

finally:
    cur.close()
    conn.close()
