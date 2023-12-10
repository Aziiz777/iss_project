# database/auth_operations.py
from database.models import User

def create_account(session, username, password):
    # Check if the username already exists
    existing_user = session.query(User).filter_by(username=username).first()
    if existing_user:
        return {'status': 'error', 'message': 'Username already exists'}
    else:
        # Create a new user account
        new_user = User(username=username, password=password)
        session.add(new_user)
        session.commit()
        return {'status': 'success', 'message': 'Account created successfully'}

def login(session, username, password):
    user = session.query(User).filter_by(username=username, password=password).first()
    if user:
        user.is_authenticated = True
        session.commit()
        return {'status': 'success', 'message': 'Login successful'}
    else:
        return {'status': 'error', 'message': 'Invalid username or password'}
