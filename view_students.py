
from database import connect_db

conn = connect_db()

if conn:
    cur = conn.cursor()

    cur.execute("SELECT * FROM students")

    students = cur.fetchall()

    if students:
        print("\nSTUDENT DETAILS")
        print("------------------------------")

        for student in students:
            print("ID:", student[0])
            print("Name:", student[1])
            print("Roll Number:", student[2])
            print("Email:", student[3])
            print("Department:", student[4])
            print("Year:", student[5])
            print("------------------------------")
    else:
        print("No student records found.")

    cur.close()
    conn.close()
