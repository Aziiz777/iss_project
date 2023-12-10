from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base

def init_db():
    engine = create_engine('sqlite:///university_system.db', echo=True)
    Base.metadata.create_all(engine)

def create_session():
    engine = create_engine('sqlite:///university_system.db')
    Session = sessionmaker(bind=engine)
    return Session()

