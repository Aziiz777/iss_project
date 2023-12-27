from sqlalchemy import Column, Integer, String, Boolean, create_engine,ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, index=True)
    password = Column(String(256))
    phone_number = Column(String(20))  
    mobile_number = Column(String(20))  
    address = Column(String(255))  
    national_id = Column(String(256)) 
    jwt_token = Column(String(512))
    public_key = Column(String(512))
    session_key = Column(String(512))

class Student(User):
    __tablename__ = 'students'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    project_descriptions = Column(JSON)  # Use JSON or JSONB based on your database type

class Professor(User):
    __tablename__ = 'professors'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    research_area = Column(String(255))

class UniversityAuthority(User):
    __tablename__ = 'university_authorities'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    department = Column(String(100))