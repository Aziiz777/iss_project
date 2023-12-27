# import sqlite3

# conn = sqlite3.connect('university_system.db')
# cursor = conn.cursor()

# cursor.execute('SELECT * FROM users;')
# rows = cursor.fetchall()

# for row in rows:
#     print(row)

# conn.close()


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import User, Professor,Student

# Assuming you've defined your models and created the engine already
engine = create_engine('sqlite:///university_system.db')

# Create a session
Session = sessionmaker(bind=engine)
session = Session()

# Query all professors with their data
professors = session.query(User, Student).filter(User.id == Student.id).all()

# Print the results
for user, professor in professors:
    print("User ID:", user.id)
    print("Username:", user.username)
    # print("Research Area:", professor.research_area)
    # Add more fields as needed

# Close the session
session.close()
