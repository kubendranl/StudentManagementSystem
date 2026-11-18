
from flask import Flask, render_template, request, jsonify
from database import connect_db, create_table
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import jwt
import os
import re
import uuid

# ---------------- CONFIGURATION ----------------

load_dotenv()

app = Flask(__name__)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_EXPIRATION_MINUTES = int(
    os.getenv("JWT_EXPIRATION_MINUTES", "30")
)

JWT_ISSUER = os.getenv("JWT_ISSUER", "student-management-api")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "student-management-client")

if not JWT_SECRET_KEY or len(JWT_SECRET_KEY) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY must be set in .env and contain at least 32 characters"
    )

if JWT_EXPIRATION_MINUTES <= 0:
    raise RuntimeError("JWT_EXPIRATION_MINUTES must be greater than zero")


# ---------------- DATABASE HELPER ----------------

def get_db_connection():
    conn = connect_db()

    if conn is None:
        return None

    return conn


# ---------------- JWT TOKEN GENERATION ----------------

def generate_access_token(admin_id, email, token_version):
    now = datetime.now(timezone.utc)

    payload = {
        "admin_id": admin_id,
        "email": email,
        "token_version": token_version,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "type": "access"
    }

    token = jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm="HS256"
    )

    return token


# ---------------- USER JWT TOKEN GENERATION ----------------

def generate_user_access_token(user_id, email, token_version):
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "email": email,
        "token_version": token_version,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "type": "access",
        "role": "user"
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


# ---------------- JWT TOKEN VERIFICATION ----------------

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Authorization token is missing"
            }), 401

        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return jsonify({
                "error": "Authorization token is missing"
            }), 401

        try:
            decoded = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=["HS256"],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                options={
                    "require": [
                        "admin_id",
                        "email",
                        "token_version",
                        "jti",
                        "iat",
                        "nbf",
                        "exp",
                        "iss",
                        "aud",
                        "type"
                    ]
                }
            )

            if decoded.get("type") != "access":
                return jsonify({
                    "error": "Invalid token type"
                }), 401

            admin_id = decoded.get("admin_id")
            token_version = decoded.get("token_version")

            if (
                not isinstance(admin_id, int)
                or not isinstance(token_version, int)
            ):
                return jsonify({
                    "error": "Invalid token"
                }), 401

        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Token expired. Please login again."
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                "error": "Invalid or tampered token"
            }), 401

        # Verify admin session from PostgreSQL

        conn = get_db_connection()

        if conn is None:
            return jsonify({
                "error": "Database connection failed"
            }), 500

        cur = conn.cursor()

        try:
            cur.execute("""
                SELECT id, email, token_version
                FROM admins
                WHERE id = %s
            """, (admin_id,))

            admin = cur.fetchone()

            if not admin:
                return jsonify({
                    "error": "Admin account not found"
                }), 401

            if admin[2] != token_version:
                return jsonify({
                    "error": "Session expired. Please login again."
                }), 401

            request.admin_id = admin[0]
            request.admin_email = admin[1]

        except Exception as e:
            print("Token verification error:", e)

            return jsonify({
                "error": "Token verification failed"
            }), 500

        finally:
            cur.close()
            conn.close()

        return func(*args, **kwargs)

    return wrapper


# ---------------- USER JWT VERIFICATION ----------------

def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token is missing"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = jwt.decode(
                token, JWT_SECRET_KEY, algorithms=["HS256"],
                issuer=JWT_ISSUER, audience=JWT_AUDIENCE,
                options={"require": [
                    "user_id", "email", "token_version", "jti",
                    "iat", "nbf", "exp", "iss", "aud", "type", "role"
                ]}
            )
            if decoded.get("type") != "access" or decoded.get("role") != "user":
                return jsonify({"error": "User access only"}), 403
            user_id = decoded.get("user_id")
            token_version = decoded.get("token_version")
            if not isinstance(user_id, int) or not isinstance(token_version, int):
                return jsonify({"error": "Invalid token"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired. Please login again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid or tampered token"}), 401

        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, email, token_version
                FROM users WHERE id = %s
            """, (user_id,))
            user = cur.fetchone()
            if not user or user[2] != token_version:
                return jsonify({"error": "Session expired. Please login again."}), 401

            # Resolve the current student ID by email. This remains valid even
            # if the admin's delete operation renumbers student IDs.
            cur.execute("""
                SELECT id FROM students WHERE LOWER(email) = LOWER(%s)
            """, (user[1],))
            student = cur.fetchone()
            if not student:
                return jsonify({"error": "Your student record is not linked or no longer exists. Contact the admin."}), 403

            request.user_id = user[0]
            request.user_email = user[1]
            request.student_id = student[0]
        except Exception as e:
            print("User token verification error:", e)
            return jsonify({"error": "User token verification failed"}), 500
        finally:
            cur.close()
            conn.close()
        return func(*args, **kwargs)
    return wrapper


# ---------------- HOME PAGE ----------------

@app.route("/")
def home():
    # Show the Admin / User login selection page first.
    return render_template("role_selection.html")


# ---------------- ADMIN LOGIN PAGE ----------------

@app.route("/login-page")
def login_page():
    return render_template("login.html")


# ---------------- ADMIN DASHBOARD PAGE ----------------

@app.route("/admin/dashboard")
def admin_dashboard_page():
    # The dashboard page is rendered here; its student APIs remain protected
    # by the admin JWT token_required decorator.
    return render_template("index.html")


# ---------------- USER PAGES ----------------

@app.route("/user/login-page")
def user_login_page():
    return render_template("user_login.html")


@app.route("/user/register-page")
def user_register_page():
    return render_template("user_register.html")


@app.route("/user/dashboard")
def user_dashboard_page():
    return render_template("user_dashboard.html")


# ---------------- ADMIN LOGIN API ----------------

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        # Verify email from PostgreSQL

        cur.execute("""
            SELECT id, email, password
            FROM admins
            WHERE LOWER(email) = %s
        """, (email,))

        admin = cur.fetchone()

        # Verify password hash

        if not admin or not check_password_hash(admin[2], password):
            return jsonify({
                "error": "Invalid email or password"
            }), 401

        # Create a new session version.
        # This invalidates previous access tokens.

        cur.execute("""
            UPDATE admins
            SET token_version = token_version + 1
            WHERE id = %s
            RETURNING token_version
        """, (admin[0],))

        token_version = cur.fetchone()[0]

        conn.commit()

        # Generate JWT access token

        token = generate_access_token(
            admin_id=admin[0],
            email=admin[1],
            token_version=token_version
        )

        return jsonify({
            "message": "Login successful",
            "token": token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_MINUTES * 60,
            "email": admin[1]
        }), 200

    except Exception as e:
        conn.rollback()
        print("Login error:", e)

        return jsonify({
            "error": "Login failed"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER REGISTRATION API ----------------

@app.route("/user/register", methods=["POST"])
def user_register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must contain at least 8 characters"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()
    try:
        # A user can register only with an email already added by the admin.
        cur.execute("""
            SELECT id FROM students WHERE LOWER(email) = %s
        """, (email,))
        student = cur.fetchone()
        if not student:
            return jsonify({
                "error": "This email is not in student records. Contact the admin first."
            }), 404

        cur.execute("""
            INSERT INTO users (email, password)
            VALUES (%s, %s)
            RETURNING id, email
        """, (email, generate_password_hash(password)))
        user = cur.fetchone()
        conn.commit()

        return jsonify({
            "message": "User registered successfully",
            "user_id": user[0],
            "email": user[1]
        }), 201

    except Exception as e:
        conn.rollback()
        if getattr(e, "pgcode", None) == "23505":
            return jsonify({"error": "This email is already registered"}), 409
        print("User registration error:", e)
        return jsonify({"error": "Unable to register user"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER LOGIN API ----------------

@app.route("/user/login", methods=["POST"])
def user_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, email, password
            FROM users
            WHERE LOWER(email) = %s
        """, (email,))
        user = cur.fetchone()

        if not user or not check_password_hash(user[2], password):
            return jsonify({"error": "Invalid email or password"}), 401

        cur.execute("""
            UPDATE users
            SET token_version = token_version + 1
            WHERE id = %s
            RETURNING token_version
        """, (user[0],))
        token_version = cur.fetchone()[0]
        conn.commit()

        token = generate_user_access_token(user[0], user[1], token_version)

        return jsonify({
            "message": "User login successful",
            "user_id": user[0],
            "email": user[1],
            "token": token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_MINUTES * 60
        }), 200

    except Exception as e:
        conn.rollback()
        print("User login error:", e)
        return jsonify({"error": "User login failed"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER: VIEW OWN STUDENT RECORD ----------------

@app.route("/user/me", methods=["GET"])
@user_required
def user_get_own_record():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, roll_no, name, email, mobile, department, year
            FROM students WHERE LOWER(email) = LOWER(%s)
        """, (request.user_email,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Your student record was not found"}), 404
        return jsonify({
            "id": row[0], "roll_no": row[1], "name": row[2],
            "email": row[3], "mobile": row[4],
            "department": row[5], "year": row[6]
        }), 200
    except Exception as e:
        print("User own-record error:", e)
        return jsonify({"error": "Unable to fetch your record"}), 500
    finally:
        cur.close()
        conn.close()


# ---------------- USER: UPDATE NAME ONLY ----------------

@app.route("/user/me", methods=["PUT", "PATCH"])
@user_required
def user_update_own_name():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400
    if len(name) > 150:
        return jsonify({"error": "Name must be 150 characters or fewer"}), 400

    # Reject attempts to update any other student field.
    if set(data.keys()) != {"name"}:
        return jsonify({"error": "You can update only your name"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE students SET name = %s
            WHERE LOWER(email) = LOWER(%s)
            RETURNING id, name
        """, (name, request.user_email))
        updated = cur.fetchone()
        if not updated:
            conn.rollback()
            return jsonify({"error": "Your student record was not found"}), 404
        conn.commit()
        return jsonify({"message": "Name updated successfully", "id": updated[0], "name": updated[1]}), 200
    except Exception as e:
        conn.rollback()
        print("User name update error:", e)
        return jsonify({"error": "Unable to update name"}), 500
    finally:
        cur.close()
        conn.close()


# ---------------- USER LOGOUT ----------------

@app.route("/user/logout", methods=["POST"])
@user_required
def user_logout():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users SET token_version = token_version + 1
            WHERE id = %s
        """, (request.user_id,))
        conn.commit()
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        conn.rollback()
        print("User logout error:", e)
        return jsonify({"error": "Logout failed"}), 500
    finally:
        cur.close()
        conn.close()


# ---------------- ADMIN LOGOUT API ----------------

@app.route("/logout", methods=["POST"])
@token_required
def logout():

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        # Increment token version to invalidate current token

        cur.execute("""
            UPDATE admins
            SET token_version = token_version + 1
            WHERE id = %s
        """, (request.admin_id,))

        conn.commit()

        return jsonify({
            "message": "Logged out successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        print("Logout error:", e)

        return jsonify({
            "error": "Logout failed"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- CHANGE ADMIN PASSWORD ----------------

@app.route("/change-password", methods=["POST"])
@token_required
def change_password():

    data = request.get_json(silent=True) or {}

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if (
        not isinstance(current_password, str)
        or not isinstance(new_password, str)
        or not current_password
        or not new_password
    ):
        return jsonify({
            "error": "Current password and new password are required"
        }), 400

    if len(new_password) < 8:
        return jsonify({
            "error": "New password must contain at least 8 characters"
        }), 400

    if current_password == new_password:
        return jsonify({
            "error": "New password must be different from current password"
        }), 400

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT password
            FROM admins
            WHERE id = %s
        """, (request.admin_id,))

        admin = cur.fetchone()

        if not admin or not check_password_hash(
            admin[0], current_password
        ):
            return jsonify({
                "error": "Current password is incorrect"
            }), 401

        new_hashed_password = generate_password_hash(new_password)

        # Update password and invalidate all existing tokens

        cur.execute("""
            UPDATE admins
            SET password = %s,
                token_version = token_version + 1
            WHERE id = %s
        """, (new_hashed_password, request.admin_id))

        conn.commit()

        return jsonify({
            "message": "Password changed successfully. Please login again."
        }), 200

    except Exception as e:
        conn.rollback()
        print("Password change error:", e)

        return jsonify({
            "error": "Unable to change password"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- DUPLICATE STUDENT VALIDATION ----------------

def check_duplicate(cur, roll_no, email, mobile, exclude_id=None):

    query = """
        SELECT roll_no, email, mobile
        FROM students
        WHERE (
            roll_no = %s
            OR LOWER(email) = %s
            OR mobile = %s
        )
    """

    params = [roll_no, email, mobile]

    if exclude_id is not None:
        query += " AND id != %s"
        params.append(exclude_id)

    cur.execute(query, tuple(params))

    existing = cur.fetchone()

    if existing:

        if existing[0] == roll_no:
            return f"Roll Number {roll_no} already exists!"

        if existing[1].lower() == email:
            return f"Email {email} already exists!"

        if existing[2] == mobile:
            return f"Mobile {mobile} already exists!"

    return None


# ---------------- GET ALL STUDENTS ----------------

@app.route("/students", methods=["GET"])
@token_required
def get_students():

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, roll_no, name, email, mobile, department, year
            FROM students
            ORDER BY id ASC
        """)

        rows = cur.fetchall()

        students = []

        for row in rows:
            students.append({
                "id": row[0],
                "roll_no": row[1],
                "name": row[2],
                "email": row[3],
                "mobile": row[4],
                "department": row[5],
                "year": row[6]
            })

        return jsonify(students), 200

    except Exception as e:
        print("Get students error:", e)

        return jsonify({
            "error": "Unable to fetch students"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- GET SINGLE STUDENT ----------------

@app.route("/students/<int:student_id>", methods=["GET"])
@token_required
def get_student(student_id):

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, roll_no, name, email, mobile, department, year
            FROM students
            WHERE id = %s
        """, (student_id,))

        student = cur.fetchone()

        if not student:
            return jsonify({
                "error": "Student not found"
            }), 404

        return jsonify({
            "id": student[0],
            "roll_no": student[1],
            "name": student[2],
            "email": student[3],
            "mobile": student[4],
            "department": student[5],
            "year": student[6]
        }), 200

    except Exception as e:
        print("Single student error:", e)

        return jsonify({
            "error": "Unable to fetch student"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- ADD STUDENT ----------------

@app.route("/students", methods=["POST"])
@token_required
def add_student():

    data = request.get_json(silent=True) or {}

    roll_no = str(data.get("roll_no", "")).strip()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    mobile = str(data.get("mobile", "")).strip()
    department = str(data.get("department", "")).strip()
    year = str(data.get("year", "")).strip()

    if not all([roll_no, name, email, mobile, department, year]):
        return jsonify({
            "error": "Please fill all fields"
        }), 400

    if not year.isdigit():
        return jsonify({
            "error": "Year must be a number"
        }), 400

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        duplicate_message = check_duplicate(
            cur, roll_no, email, mobile
        )

        if duplicate_message:
            return jsonify({
                "error": duplicate_message
            }), 409

        cur.execute("""
            INSERT INTO students
            (roll_no, name, email, mobile, department, year)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            roll_no,
            name,
            email,
            mobile,
            department,
            int(year)
        ))

        conn.commit()

        return jsonify({
            "message": "Student added successfully"
        }), 201

    except Exception as e:
        conn.rollback()
        print("Add student error:", e)

        return jsonify({
            "error": "Unable to add student"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- UPDATE STUDENT ----------------

@app.route("/students/<int:student_id>", methods=["PUT"])
@token_required
def update_student(student_id):

    data = request.get_json(silent=True) or {}

    roll_no = str(data.get("roll_no", "")).strip()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    mobile = str(data.get("mobile", "")).strip()
    department = str(data.get("department", "")).strip()
    year = str(data.get("year", "")).strip()

    if not all([roll_no, name, email, mobile, department, year]):
        return jsonify({
            "error": "Please fill all fields"
        }), 400

    if not year.isdigit():
        return jsonify({
            "error": "Year must be a number"
        }), 400

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        duplicate_message = check_duplicate(
            cur, roll_no, email, mobile, student_id
        )

        if duplicate_message:
            return jsonify({
                "error": duplicate_message
            }), 409

        cur.execute("""
            UPDATE students
            SET roll_no = %s,
                name = %s,
                email = %s,
                mobile = %s,
                department = %s,
                year = %s
            WHERE id = %s
        """, (
            roll_no,
            name,
            email,
            mobile,
            department,
            int(year),
            student_id
        ))

        if cur.rowcount == 0:
            conn.rollback()

            return jsonify({
                "error": "Student not found"
            }), 404

        conn.commit()

        return jsonify({
            "message": "Student updated successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        print("Update student error:", e)

        return jsonify({
            "error": "Unable to update student"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- DELETE STUDENT ----------------

@app.route("/students/<int:student_id>", methods=["DELETE"])
@token_required
def delete_student(student_id):

    conn = get_db_connection()

    if conn is None:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cur = conn.cursor()

    try:
        cur.execute("LOCK TABLE students IN EXCLUSIVE MODE")

        cur.execute(
            "DELETE FROM students WHERE id = %s",
            (student_id,)
        )

        if cur.rowcount == 0:
            conn.rollback()

            return jsonify({
                "error": "Student not found"
            }), 404

        # Preserve the existing ID renumbering behaviour

        cur.execute("""
            UPDATE students
            SET id = -id
        """)

        cur.execute("""
            WITH numbered AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY -id) AS new_id
                FROM students
            )
            UPDATE students AS s
            SET id = numbered.new_id
            FROM numbered
            WHERE s.id = numbered.id
        """)

        cur.execute("""
            SELECT setval(
                pg_get_serial_sequence('students', 'id'),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM students
        """)

        conn.commit()

        return jsonify({
            "message": "Student deleted successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        print("Delete student error:", e)

        return jsonify({
            "error": "Unable to delete student"
        }), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER TABLE SETUP ----------------

def create_user_table():
    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection failed while creating users table")

    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migrate older versions safely. Student accounts are linked by email,
        # so changing/renumbering a student ID will not break the user account.
        cur.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0
        """)
        cur.execute("""
            ALTER TABLE users
            DROP CONSTRAINT IF EXISTS users_student_id_fkey
        """)
        cur.execute("DROP INDEX IF EXISTS users_student_id_unique")
        cur.execute("""
            ALTER TABLE users
            DROP COLUMN IF EXISTS student_id
        """)

        conn.commit()
        print("Users table ready!")
        print("User accounts are linked to student records by email.")
    except Exception as e:
        conn.rollback()
        print("Users table setup failed:", e)
        raise
    finally:
        cur.close()
        conn.close()


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    create_table()
    create_user_table()
    app.run(debug=True)
