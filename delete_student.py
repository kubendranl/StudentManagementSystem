
from database import connect_db

student_id = int(input("Enter student ID to delete: "))

conn = connect_db()

if conn:
    cur = conn.cursor()

    cur.execute(
        "SELECT name FROM students WHERE id = %s",
        (student_id,)
    )

    student = cur.fetchone()

    if student:
        print("Student Name:", student[0])

        confirm = input("Do you want to delete? (yes/no): ")

        if confirm.lower() == "yes":
            cur.execute(
                "DELETE FROM students WHERE id = %s",
                (student_id,)
            )

            conn.commit()
            print("Student deleted successfully!")

        else:
            print("Delete cancelled.")

    else:
        print("Student not found!")

    cur.close()
    conn.close()
