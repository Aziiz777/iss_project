from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base

def init_db():
    # engine = create_engine('sqlite:///university_system.db', echo=True, connect_args={'check_same_thread': False})
    engine = create_engine('sqlite:///university_system.db', connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)

def create_session():
    engine = create_engine('sqlite:///university_system.db', connect_args={'check_same_thread': False})
    Session = sessionmaker(bind=engine)
    return Session()

