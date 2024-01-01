# database/auth_operations.py
from database.models import User,Student,Professor,CertificateAuthority, Mark,Certificate
import hashlib
import jwt
import json

from datetime import datetime, timedelta
from eth_account import Account,messages
from web3 import Web3
from hexbytes import HexBytes
from sqlalchemy.orm import joinedload,load_only
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sqlalchemy.exc import IntegrityError






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
        if role.lower() == 'student' :
            new_user = Student(username=username, password=hash_password(password), **kwargs)
            
        elif role.lower() == 'professor':
            new_user = Professor(username=username, password=hash_password(password), **kwargs)
        # elif role == 'university_authority':
        #     new_user = UniversityAuthority(username=username, password=hash_password(password), **kwargs)
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
        return {'status': 'success', 'message': 'Login successful', 'jwt_token': user.jwt_token, 'user_id': user.id}
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
                'session_key': user.session_key,
                'public_key': user.public_key
            }
            return user_data
        else:
            return {'status': 'error', 'message': 'User not found or unauthorized'}
    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid JWT token'}


def get_ca_data(session,jwt_token, ca_username):
    try:
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        ca_id_from_token = int(payload.get("sub"))
        ca = session.query(CertificateAuthority).filter(CertificateAuthority.id == ca_id_from_token).first()
        if ca:
            ca_data = {
                'status': 'success',
                'message': 'CA data retrieved successfully',
                'ca_id': ca.id,
                'username': ca.username,
                'public_key': ca.public_key,
                'private_key': ca.private_key
                    }
            return ca_data
        else:
         return {'status': 'error', 'message': 'CA not found'}
    except Exception as e:
        # Handle exceptions, log errors, etc.
        print(f"Error retrieving CA data: {e}")
        return {'status': 'error', 'message': 'Error retrieving CA data'}


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
                    # user.session_key_signature= signature
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
            student = session.query(Student).filter(Student.id == user_id_from_token, Student.jwt_token == jwt_token).first()
            print("no error5")
            if student:
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


def get_all_project_descriptions(session):
    try:
        students = session.query(Student).all()

        project_descriptions = {}
        print(f"sudentsss : {students[0].project_descriptions}")

        for student in students:
            user_data = {
                'user_id': student.id,
                'username': student.username,
                'project_descriptions':  student.project_descriptions
            }

            project_descriptions[student.id] = user_data

        return {'status': 'success', 'project_descriptions': project_descriptions}

    except Exception as e:
        print(f"Error fetching project descriptions: {e}")
        return {'status': 'error', 'message': 'Error fetching project descriptions'}


# professor_id,user_id,project_id,mark
def send_marks(session, jwt_token,client_public_key,data_signature,data):
    try:
        student_id = data['student_id']
        professor_id = data['professor_id'] 
        project_id = data['project_id']
        mark = data['mark']

        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_from_token = int(payload.get("sub"))
        print('no error 1')

        if str(professor_id) == str(user_id_from_token):
            print('no error 2')

            w3 = Web3(Web3.HTTPProvider(""))
            print('no error 3')

            address = w3.eth.account.recover_message(messages.encode_defunct(text=json.dumps(data, sort_keys=True)),signature=HexBytes(data_signature))
            print('no error 4')
            student = session.query(Student).filter(Student.id == student_id).first()

            if student:
                # Check if the project_id is valid
                if 1 <= project_id <= len(student.project_descriptions):
                    # Create a new Mark entry
                    new_mark = Mark(
                        professor_id=professor_id,  # Set this based on your application logic
                        student_id=student_id,
                        project_description=student.project_descriptions[project_id - 1],
                        mark=mark,
                        signature=data_signature
                    )

                    # Add the new Mark entry to the database
                    session.add(new_mark)
                    session.commit()

                    return {'status': 'success', 'message': 'Marks sent successfully'}
                else:
                    return {'status': 'error', 'message': 'Invalid project_id'}
            else:
                return {'status': 'error', 'message': 'User is not a student'}
        else:
            return {'status': 'error', 'message': 'Invalid JWT token'}
    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid JWT token'}


def store_csr(session, jwt_token, user_id, csr_pem):
    try:
        # Decode the JWT token to get the user ID
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_from_token = int(payload.get("sub"))
        if str(user_id) == str(user_id_from_token):
            user = session.query(User).filter(User.id == user_id, User.jwt_token == jwt_token).first()

            if user:
                user.csr_pem = csr_pem
                session.commit()

                return {'status': 'success', 'message': 'CSR stored successfully'}
            else:
                return {'status': 'error', 'message': 'User not found or unauthorized'}
        else:
            return {'status': 'error', 'message': 'Invalid JWT token'}
    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'JWT token has expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid JWT token'}


# Function to store a certificate for the user
def store_certificate(session, client_name: str,ca_name,certificate_data: str):
    try:
        # Retrieve the user by username
        print(1)
        user = session.query(User).filter(User.username == client_name).first()
        print(2)
        if user:
            print(3)

            # Check if the user already has a CSR
            if user.csr_pem:
                print(4)

                # Create a CertificateAuthority instance (for demonstration purposes)
                # In a real-world scenario, you would retrieve the CA information appropriately
                ca = session.query(CertificateAuthority).filter(CertificateAuthority.username == ca_name).first()
                print(5)
                print(user.id)
                print(user.public_key)
                print(ca.id)
                print(datetime.utcnow() + timedelta(days=365))


                # Generate a certificate
                certificate = Certificate(
                    user_id=user.id,
                    public_key=user.public_key if user.public_key else "",
                    expiration_date=datetime.utcnow() + timedelta(days=365),
                    ca_id=ca.id ,
                    certificate_data = certificate_data
                )
                print(6)


                # Add the certificate to the session and commit
                session.add(certificate)
                session.commit()

                return {'status': 'success', 'message': 'Certificate created successfully', 'certificate_data':certificate_data}
            else:
                return {'status': 'error', 'message': 'User does not have a CSR'}
        else:
            return {'status': 'error', 'message': 'User not found'}
    except IntegrityError as e:
        print(f"IntegrityError: {e}")
        session.rollback()
        return {'status': 'error', 'message': 'Certificate creation failed (IntegrityError)'}
