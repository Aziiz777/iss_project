# database/auth_operations.py
from database.models import User,Student,Professor,UniversityAuthority
import hashlib
import jwt
from datetime import datetime, timedelta
from eth_account import Account,messages
from web3 import Web3
from hexbytes import HexBytes



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

def create_account(session, username, password,role,**kwargs):
    # Check if the username already exists
    existing_user = session.query(User).filter_by(username=username).first()
    if existing_user:
        return {'status': 'error', 'message': 'Username already exists'}
    else:
                # Create a new user account based on the specified role
        if role == 'student':
            new_user = Student(username=username, password=hash_password(password), **kwargs)
            
        elif role == 'professor':
            new_user = Professor(username=username, password=hash_password(password), **kwargs)
        elif role == 'university_authority':
            new_user = UniversityAuthority(username=username, password=hash_password(password), **kwargs)
        # Create a new user account
        # new_user = User(username=username, password=hash_password(password))
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
                'session_key': user.session_key
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
                user.national_id = shared_key
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


def handShaking(session,client_public_key,session_key,signature,user_id,jwt_token,server_public_key):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        user_id_from_token = int(payload.get("sub"))
        
        if str(user_id) == str(user_id_from_token):
            
            user = session.query(User).filter(User.id == user_id, User.jwt_token == jwt_token).first()
            if user:
                user.public_key = client_public_key
                # Convert client_public_key and signature to bytes
                print("no error 1")
                w3 = Web3(Web3.HTTPProvider(""))
                print("no error 2")
                address = w3.eth.account.recover_message(messages.encode_defunct(text=session_key),signature=HexBytes(signature))
                print("no error 3")
                print(f"address : {address}")
                if address ==client_public_key:
                    user.session_key = session_key
                    session.commit()
                    print(f"signature if statements")
                    if server_public_key:
                        return {'status': 'success', 'message': 'handShaking done successfully','server_public_key':server_public_key}
                    else:
                        return {'status': 'error', 'message':'handShaking failed'}
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

def add_project_descriptions(session, jwt_token,user_id, project_descriptions):
    try:
        print("no error1")
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        print("no error2")
        user_id_from_token = int(payload.get("sub"))
        print("no error3")
        if str(user_id) == str(user_id_from_token):
            print("no error4")
            student  = session.query(User).filter(User.id == user_id_from_token, User.jwt_token == jwt_token).first()
            print("no error5")
            if student:  # Check if the user is a Student
                print("no error6")
                # Update the project_descriptions field
                student.project_descriptions = project_descriptions
                print("no error7")

                session.commit()
                print("no error8")

                return {'status': 'success', 'message': 'Project descriptions stored successfully'}
            else:
                return {'status': 'error', 'message': 'User is not a student'}

    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid JWT token'}
