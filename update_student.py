
from database import connect_db

student_id = int(input("Enter student ID to update: "))

conn = connect_db()

if conn:
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM students WHERE id = %s",
        (student_id,)
    )

    student = cur.fetchone()

    if student:
        print("Current Name:", student[1])

        new_name = input("Enter new name: ")
        new_department = input("Enter new department: ")

        cur.execute(
            """UPDATE students
            SET name = %s, department = %s
            WHERE id = %s""",
            (new_name, new_department, student_id)
        )

        conn.commit()

        print("Student updated successfully!")

    else:
        print("Student not found!")

    cur.close()
    conn.close()
