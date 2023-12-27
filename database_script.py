import sqlite3

conn = sqlite3.connect('university_system.db')
cursor = conn.cursor()

cursor.execute('SELECT * FROM marks;')
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()


# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# from database.models import User, Professor,Student

# # Assuming you've defined your models and created the engine already
# engine = create_engine('sqlite:///university_system.db')

# # Create a session
# Session = sessionmaker(bind=engine)
# session = Session()

# # Query all professors with their data
# professors = session.query(User, Student).filter(User.id == Student.id).all()

# # Print the results
# for user, professor in professors:
#     print("User ID:", user.id)
#     print("Username:", user.username)
#     # print("Research Area:", professor.research_area)
#     # Add more fields as needed

# # Close the session
# session.close()





# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# from database.models import Base,User,Student,Professor,UniversityAuthority

# # Replace 'your_module_containing_models' with the actual module name where your models are defined
# # For example, if your models are defined in models.py, replace 'your_module_containing_models' with 'models'
# # from models import Base, Student

# # Create an SQLite database engine
# engine = create_engine('sqlite:///university_system.db', echo=True)

# # Create a session
# Session = sessionmaker(bind=engine)
# session = Session()

# # Query all project_descriptions from the students table
# students = session.query(Student).all()

# for student in students:
#     print(f"Student {student.username}'s project descriptions: {student.project_descriptions}")

# # Close the session
# session.close()
