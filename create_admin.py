
import psycopg2
from getpass import getpass
from werkzeug.security import generate_password_hash

print("Connect to Render PostgreSQL")

database_url = getpass("Paste External Database URL (hidden): ")

if not database_url.startswith("postgresql://"):
    print("Invalid URL. Please paste the complete External Database URL.")
    raise SystemExit

try:
    conn = psycopg2.connect(database_url, sslmode="require")
    print("Database connected successfully!")

    email = input("Enter admin email: ").strip().lower()
    password = getpass("Enter admin password: ")

    if not email or len(password) < 8:
        print("Enter a valid email and password (minimum 8 characters).")
    else:
        hashed_password = generate_password_hash(password)

        cur = conn.cursor()
        cur.execute("""
            INSERT INTO admins (email, password)
            VALUES (%s, %s)
            ON CONFLICT (email)
            DO UPDATE SET
                password = EXCLUDED.password,
                token_version = admins.token_version + 1
            RETURNING id, email
        """, (email, hashed_password))

        admin = cur.fetchone()
        conn.commit()

        print("Admin account saved successfully!")
        print("Admin ID:", admin[0])
        print("Admin Email:", admin[1])

        cur.close()

except Exception as e:
    print("Error:", e)

finally:
    if 'conn' in locals():
        conn.close()
