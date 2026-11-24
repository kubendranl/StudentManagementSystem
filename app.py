
from flask import Flask, render_template, request, jsonify
from database import connect_db, create_table
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import jwt
import os

load_dotenv()

app = Flask(__name__)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "30"))

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing in .env file")


# ---------------- TOKEN GENERATION ----------------

def generate_token(user_id, email, role):
    return jwt.encode({
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc)
               + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }, JWT_SECRET_KEY, algorithm="HS256")


# ---------------- ADMIN TOKEN VERIFICATION ----------------

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token is missing"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            decoded = jwt.decode(
                token, JWT_SECRET_KEY, algorithms=["HS256"]
            )

            if decoded.get("role") != "admin":
                return jsonify({"error": "Admin access required"}), 403

            request.admin_id = decoded["user_id"]

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired. Please login again."}), 401
        except (jwt.InvalidTokenError, KeyError):
            return jsonify({"error": "Invalid token"}), 401

        return func(*args, **kwargs)

    return wrapper


# ---------------- USER TOKEN VERIFICATION ----------------

def user_token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token is missing"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            decoded = jwt.decode(
                token, JWT_SECRET_KEY, algorithms=["HS256"]
            )

            if decoded.get("role") != "user":
                return jsonify({"error": "User access required"}), 403

            conn = connect_db()
            if conn is None:
                return jsonify({"error": "Database connection failed"}), 500

            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT token_version FROM users WHERE id = %s",
                    (decoded["user_id"],)
                )
                row = cur.fetchone()
                cur.close()

                if not row or row[0] != decoded.get("token_version"):
                    return jsonify({"error": "Invalid session"}), 401

            finally:
                conn.close()

            request.user_id = decoded["user_id"]
            request.user_email = decoded["email"]

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired. Please login again."}), 401
        except (jwt.InvalidTokenError, KeyError):
            return jsonify({"error": "Invalid token"}), 401

        return func(*args, **kwargs)

    return wrapper


# ---------------- HOME PAGE ----------------

@app.route("/")
def home():
    return render_template("app.html")


# ---------------- ROLE SELECTION API ----------------

@app.route("/api/select-role", methods=["POST"])
def select_role():
    data = request.get_json(silent=True) or {}
    role = str(data.get("role", "")).strip().lower()

    if role == "admin":
        return jsonify({
            "success": True,
            "role": "admin",
            "screen": "adminLoginScreen"
        }), 200

    if role == "user":
        return jsonify({
            "success": True,
            "role": "user",
            "screen": "userLoginScreen"
        }), 200

    return jsonify({
        "success": False,
        "error": "Invalid role"
    }), 400


# ---------------- OLD PAGE ROUTES ----------------

@app.route("/login-page")
def login_page():
    return render_template("login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    return render_template("index.html")


@app.route("/user/login-page")
def user_login_page():
    return render_template("user_login.html")


@app.route("/user/register-page")
def user_register_page():
    return render_template("user_register.html")


@app.route("/user/dashboard")
def user_dashboard():
    return render_template("user_dashboard.html")


# ---------------- ADMIN LOGIN API ----------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password FROM admins WHERE LOWER(email) = %s",
            (email,)
        )
        admin = cur.fetchone()

        if not admin or not check_password_hash(admin[2], password):
            return jsonify({"error": "Invalid email or password"}), 401

        token = generate_token(admin[0], admin[1], "admin")

        return jsonify({
            "message": "Login successful",
            "token": token,
            "email": admin[1]
        }), 200

    except Exception as e:
        print("Admin login error:", e)
        return jsonify({"error": "Login failed"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- ADMIN LOGOUT API ----------------

@app.route("/logout", methods=["POST"])
@token_required
def admin_logout():
    return jsonify({"message": "Admin logout successful"}), 200


# ---------------- USER REGISTRATION API ----------------

@app.route("/user/register", methods=["POST"])
def user_register():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must contain at least 8 characters"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        # Check whether this email belongs to an existing student
        cur.execute("""
            SELECT name FROM students
            WHERE LOWER(email) = %s
        """, (email,))

        student = cur.fetchone()

        if not student:
            return jsonify({
                "error": "Student record not found. Contact your administrator."
            }), 404

        # Check duplicate registration
        cur.execute(
            "SELECT id FROM users WHERE LOWER(email) = %s",
            (email,)
        )

        if cur.fetchone():
            return jsonify({"error": "Email is already registered"}), 409

        hashed_password = generate_password_hash(password)

        cur.execute("""
            INSERT INTO users (name, email, password)
            VALUES (%s, %s, %s)
        """, (student[0], email, hashed_password))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful"
        }), 201

    except Exception as e:
        conn.rollback()
        print("User registration error:", e)
        return jsonify({"error": "Registration failed"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER LOGIN API ----------------

@app.route("/user/login", methods=["POST"])
def user_login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, email, password, token_version
            FROM users
            WHERE LOWER(email) = %s
        """, (email,))

        user = cur.fetchone()

        if not user or not check_password_hash(user[2], password):
            return jsonify({"error": "Invalid email or password"}), 401

        token = jwt.encode({
            "user_id": user[0],
            "email": user[1],
            "role": "user",
            "token_version": user[3],
            "exp": datetime.now(timezone.utc)
                   + timedelta(minutes=JWT_EXPIRATION_MINUTES)
        }, JWT_SECRET_KEY, algorithm="HS256")

        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "email": user[1]
        }), 200

    except Exception as e:
        print("User login error:", e)
        return jsonify({"error": "Login failed"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER PROFILE API ----------------

@app.route("/user/me", methods=["GET"])
@user_token_required
def user_profile():

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                s.id,
                s.roll_no,
                u.name,
                u.email,
                s.mobile,
                s.department,
                s.year
            FROM users u
            JOIN students s ON LOWER(s.email) = LOWER(u.email)
            WHERE u.id = %s
        """, (request.user_id,))

        student = cur.fetchone()

        if not student:
            return jsonify({"error": "Student profile not found"}), 404

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
        print("User profile error:", e)
        return jsonify({"error": "Unable to load profile"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- UPDATE USER PROFILE NAME ----------------

@app.route("/user/me", methods=["PATCH"])
@user_token_required
def update_user_profile():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()

    if not name:
        return jsonify({"error": "Name cannot be empty"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE users
            SET name = %s
            WHERE id = %s
        """, (name, request.user_id))

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "User not found"}), 404

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Name updated successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        print("Profile update error:", e)
        return jsonify({"error": "Unable to update name"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- USER LOGOUT API ----------------

@app.route("/user/logout", methods=["POST"])
@user_token_required
def user_logout():
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE users
            SET token_version = token_version + 1
            WHERE id = %s
        """, (request.user_id,))

        conn.commit()

        return jsonify({"message": "User logout successful"}), 200

    except Exception as e:
        conn.rollback()
        print("User logout error:", e)
        return jsonify({"error": "Logout failed"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- GET ALL STUDENTS ----------------

@app.route("/students", methods=["GET"])
@token_required
def get_students():
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, roll_no, name, email, mobile, department, year
            FROM students
            ORDER BY id ASC
        """)

        rows = cur.fetchall()

        students = [{
            "id": row[0],
            "roll_no": row[1],
            "name": row[2],
            "email": row[3],
            "mobile": row[4],
            "department": row[5],
            "year": row[6]
        } for row in rows]

        return jsonify(students), 200

    except Exception as e:
        print("Get students error:", e)
        return jsonify({"error": "Unable to fetch students"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- GET SINGLE STUDENT ----------------

@app.route("/students/<int:student_id>", methods=["GET"])
@token_required
def get_student(student_id):
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id, roll_no, name, email, mobile, department, year
            FROM students
            WHERE id = %s
        """, (student_id,))

        row = cur.fetchone()

        if not row:
            return jsonify({"error": "Student not found"}), 404

        return jsonify({
            "id": row[0],
            "roll_no": row[1],
            "name": row[2],
            "email": row[3],
            "mobile": row[4],
            "department": row[5],
            "year": row[6]
        }), 200

    except Exception as e:
        print("Get student error:", e)
        return jsonify({"error": "Unable to fetch student"}), 500

    finally:
        cur.close()
        conn.close()



@app.route("/students", methods=["POST"])
@token_required
def add_student():
    data = request.get_json(silent=True) or {}

    roll_no = str(data.get("roll_no", "")).strip()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    mobile = str(data.get("mobile", "")).strip()
    department = str(data.get("department", "")).strip()
    year = data.get("year")

    if not all([roll_no, name, email, mobile, department, year]):
        return jsonify({"error": "Please fill all fields"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id FROM students WHERE roll_no = %s",
            (roll_no,)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This roll number is already registered."
            }), 409

        cur.execute(
            "SELECT id FROM students WHERE LOWER(email) = %s",
            (email,)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This email address is already registered."
            }), 409

        cur.execute(
            "SELECT id FROM students WHERE mobile = %s",
            (mobile,)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This mobile number is already used."
            }), 409

        cur.execute("""
            INSERT INTO students
            (roll_no, name, email, mobile, department, year)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (roll_no, name, email, mobile, department, year))

        conn.commit()

        return jsonify({
            "message": "Student added successfully"
        }), 201

    except Exception as e:
        conn.rollback()
        print("Add student error:", e)
        return jsonify({"error": "Unable to add student"}), 500

    finally:
        cur.close()
        conn.close()



@app.route("/students/<int:student_id>", methods=["PUT"])
@token_required
def update_student(student_id):
    data = request.get_json(silent=True) or {}

    roll_no = str(data.get("roll_no", "")).strip()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    mobile = str(data.get("mobile", "")).strip()
    department = str(data.get("department", "")).strip()
    year = data.get("year")

    if not all([roll_no, name, email, mobile, department, year]):
        return jsonify({"error": "Please fill all fields"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id FROM students WHERE roll_no = %s AND id != %s",
            (roll_no, student_id)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This roll number is already registered."
            }), 409

        cur.execute(
            "SELECT id FROM students WHERE LOWER(email) = %s AND id != %s",
            (email, student_id)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This email address is already registered."
            }), 409

        cur.execute(
            "SELECT id FROM students WHERE mobile = %s AND id != %s",
            (mobile, student_id)
        )
        if cur.fetchone():
            return jsonify({
                "error": "This mobile number is already used."
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
            roll_no, name, email, mobile,
            department, year, student_id
        ))

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Student not found"}), 404

        conn.commit()

        return jsonify({
            "message": "Student updated successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        print("Update student error:", e)
        return jsonify({"error": "Unable to update student"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- DELETE STUDENT ----------------

@app.route("/students/<int:student_id>", methods=["DELETE"])
@token_required
def delete_student(student_id):
    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cur = conn.cursor()

    try:
        cur.execute("LOCK TABLE students IN EXCLUSIVE MODE")

        cur.execute(
            "DELETE FROM students WHERE id = %s",
            (student_id,)
        )

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error": "Student not found"}), 404

        cur.execute("UPDATE students SET id = -id")

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

        return jsonify({"message": "Student deleted successfully"}), 200

    except Exception as e:
        conn.rollback()
        print("Delete student error:", e)
        return jsonify({"error": "Unable to delete student"}), 500

    finally:
        cur.close()
        conn.close()


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    create_table()
    app.run(debug=True)
