from sqlalchemy import Column, Integer, String, Boolean, create_engine,ForeignKey, JSON,DateTime,Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

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
    csr_pem = Column(Text)
    # Add this line to establish the relationship
    certificate = relationship("Certificate", back_populates="user")

class Student(User):
    __tablename__ = 'students'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    project_descriptions = Column(JSON) 
    marks = relationship("Mark", back_populates="student")

class Professor(User):
    __tablename__ = 'professors'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    marks = relationship("Mark", back_populates="professor")
    # certificate = relationship("Certificate", back_populates="user")


class Mark(Base):
    __tablename__ = 'marks'

    id = Column(Integer, primary_key=True)
    professor_id = Column(Integer, ForeignKey('professors.id'))
    student_id = Column(Integer, ForeignKey('students.id'))
    project_description = Column(String(255))
    mark = Column(Integer)
    signature = Column(String(512))  # Store the signature for the mark

    # Define relationships
    professor = relationship("Professor", back_populates="marks")
    student = relationship("Student", back_populates="marks")


class CertificateAuthority(User):
    __tablename__ = 'certificate_authorities'

    id = Column(Integer, ForeignKey('users.id'), primary_key=True, autoincrement=True)
    private_key = Column(String(512)) 
    # public_key = Column(String(512))
    certificates = relationship("Certificate", back_populates="ca")

class Certificate(Base):
    __tablename__ = 'certificates'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    public_key = Column(String(512), unique=True)
    expiration_date = Column(DateTime)
    certificate_data = Column(String)
    
    # Update this line to specify the foreign key relationship
    ca_id = Column(Integer, ForeignKey('certificate_authorities.id'))

    # Define relationships
    user = relationship("User", back_populates="certificate")
    
    # Specify the foreign key relationship for CertificateAuthority
    ca = relationship("CertificateAuthority", back_populates="certificates", foreign_keys=[ca_id])



