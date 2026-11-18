
import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()


# ---------------- DATABASE CONNECTION ----------------

def connect_db():
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT", "5432")
        )

        return conn

    except Exception as e:
        print("Database connection failed:", e)
        return None


# ---------------- CREATE TABLES ----------------

def create_table():

    conn = connect_db()

    if conn is None:
        return

    cur = None

    try:
        cur = conn.cursor()

        # STUDENTS TABLE
        cur.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                roll_no VARCHAR(30) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                department VARCHAR(100) NOT NULL,
                year INTEGER NOT NULL
            )
        """)

        # ADD MOBILE COLUMN IF NOT EXISTS
        cur.execute("""
            ALTER TABLE students
            ADD COLUMN IF NOT EXISTS mobile VARCHAR(15)
        """)

        # UNIQUE MOBILE INDEX
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_students_mobile
            ON students(mobile)
        """)

        # ADMINS TABLE
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                token_version INTEGER NOT NULL DEFAULT 0
            )
        """)

        # ADD TOKEN VERSION IF NOT EXISTS
        cur.execute("""
            ALTER TABLE admins
            ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0
        """)

        conn.commit()

        print("Students table ready!")
        print("Admins table ready!")
        print("JWT session management ready!")

    except Exception as e:

        conn.rollback()

        print("Table setup failed:", e)

    finally:

        if cur is not None:
            cur.close()

        conn.close()
