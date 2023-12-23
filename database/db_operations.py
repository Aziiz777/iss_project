# database/auth_operations.py
from database.models import User
import hashlib
import jwt
from datetime import datetime, timedelta


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(hashed_password, password):
    return hashed_password == hash_password(password)

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_jwt_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_account(session, username, password):
    # Check if the username already exists
    existing_user = session.query(User).filter_by(username=username).first()
    if existing_user:
        return {'status': 'error', 'message': 'Username already exists'}
    else:
        # Create a new user account
        new_user = User(username=username, password=hash_password(password))
        session.add(new_user)
        session.commit()
        return {'status': 'success', 'message': 'Account created successfully'}

def login(session, username, password):
    user = session.query(User).filter_by(username=username, password=hash_password(password)).first()
    if user:
        jwt_data = {"sub": str(user.id)}
        jwt_token = create_jwt_token(jwt_data)
        user.jwt_token = jwt_token
        session.commit()
        return {'status': 'success', 'message': 'Login successful', 'jwt_token': user.jwt_token}
    else:
        return {'status': 'error', 'message': 'Invalid username or password'}

def add_national_id(session,jwt_token,national_id,user_id):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        user_id_from_token = int(payload.get("sub"))
        
        if str(user_id) == str(user_id_from_token):
            
            user = session.query(User).filter(User.id == user_id, User.jwt_token == jwt_token).first()
            if user:
                user.national_id = national_id
                session.commit()
                return {'status': 'success', 'message': 'national_id added successfully'}
            else:
                print("User not found or unauthorized")
                return {'status': 'error', 'message': 'User not found or unauthorized'}
        else:
            print("Invalid JWT token inside")
            return {'status': 'error', 'message': 'Invalid JWT token'}
    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        print("Invalid JWT token outside")
        return {'status': 'error', 'message': 'Invalid JWT token'}


def get_user_data(session, jwt_token):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id_from_token = int(payload.get("sub"))

        user = session.query(User).filter(User.id == user_id_from_token, User.jwt_token == jwt_token).first()
        if user:
            user_data = {
                'status': 'success',
                'message' : 'User data retrieved successfully',
                'user_id': user.id,
                'national_id': user.national_id,
            }
            return user_data
        else:
            return {'status': 'error', 'message': 'User not found or unauthorized'}
    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid JWT token'}


def complete_user_data(session, user_id, phone_number, mobile_number, address, shared_key, jwt_token):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Payload: {payload}")
        user_id_from_token = int(payload.get("sub"))
        print(f"User ID from token: {user_id_from_token}")
        print(f"user_id: {user_id}, user_id_from_token: {user_id_from_token}")
        if str(user_id) == str(user_id_from_token):
            print("Entered if block")
            user = session.query(User).filter(User.id == user_id, User.jwt_token == jwt_token).first()
            if user:
                print("Entered inner if block")
                user.phone_number = phone_number
                user.mobile_number = mobile_number
                user.address = address
                user.shared_key = shared_key
                session.commit()
                return {'status': 'success', 'message': 'User data completed successfully'}
            else:
                print("User not found or unauthorized")
                return {'status': 'error', 'message': 'User not found or unauthorized'}
        else:
            print("Invalid JWT token inside")
            return {'status': 'error', 'message': 'Invalid JWT token'}
    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        print("Invalid JWT token outside")
        return {'status': 'error', 'message': 'Invalid JWT token'}
