import sqlite3

conn = sqlite3.connect('university_system.db')
cursor = conn.cursor()

cursor.execute('SELECT * FROM users;')
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()
