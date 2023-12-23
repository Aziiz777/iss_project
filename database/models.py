from sqlalchemy import Column, Integer, String, Boolean, create_engine
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