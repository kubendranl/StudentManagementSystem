
from database import connect_db

name = input("Enter student name: ")
roll_no = input("Enter roll number: ")
email = input("Enter email: ")
department = input("Enter department: ")
year = int(input("Enter year: "))

conn = connect_db()

if conn:
    cur = conn.cursor()

    try:
        cur.execute(
            """INSERT INTO students
            (name, roll_no, email, department, year)
            VALUES (%s, %s, %s, %s, %s)""",
            (name, roll_no, email, department, year)
        )

        conn.commit()
        print("Student added successfully!")

    except Exception as e:
        conn.rollback()
        print("Error:", e)

    finally:
        cur.close()
        conn.close()
