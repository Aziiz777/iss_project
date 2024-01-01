# server/server.py
import socket
import threading
import json
import base64
import secrets
from eth_account import Account
import pickle
from database.db_manager import create_session
from database.models import User,CertificateAuthority
from database.db_operations import create_account,login,complete_user_data,add_national_id,get_user_data,get_ca_data,get_all_project_descriptions,handShaking,add_project_descriptions,send_marks,store_csr,hash_password,store_certificate
from symmetric_encryption import encrypt_data,decrypt_data
from sqlalchemy.orm import Session
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.x509.oid import ExtensionOID


import time

def handle_client(client_socket, session,server_public_key=None):
   
    try:
        # Receive client request
        request_data = client_socket.recv(1024)
        print(f"Received raw data: {request_data}")
        request_json = json.loads(request_data)
        print(f"Received json:{request_json} ")

        # Extract JWT token from headers if present
        jwt_token = None
        if 'headers' in request_json:
            headers = request_json['headers']
            if 'Authorization' in headers:
                jwt_token = headers['Authorization']
                # Extract the token part from the Authorization header
                # _, jwt_token = auth_header.split(' ', 1)

        if 'certificate' in request_json: 
            print('enter')
            certificate = request_json['certificate']
            print('enter1')
            ca_data = get_ca_data(session,jwt_token,"name")
            print('erorororor')
            ca_pub_key = ca_data['public_key']
            # certificate_info = retrieve_certificate_info(certificate)
            # print('enter2')
            # ca_pub_key = certificate_info['public_key']
            print(ca_pub_key)
            response_data =  verify_client_certificate(certificate,ca_pub_key)
            print(response_data)
            if response_data['status'] =='error':
                send_response(client_socket,response_data)
            print('enter3')


        if request_json['action'] == 'handshake':
            client_public_key= request_json['data']['public_key']
            session_key = request_json['data']['session_key']
            signature = request_json['data']['signature']
            user_id = request_json['data']['user_id']
            handShaking_handler(client_socket, session, client_public_key,session_key,signature,user_id,jwt_token,server_public_key)

        # Process the request
        if request_json['action'] == 'create_account':
            username = request_json['data']['username']
            password = request_json['data']['password']
            role = request_json['data']['role']
            create_account_handler(client_socket, session, username, password,role)

        elif request_json['action'] == 'login':
            username = request_json['data']['username']
            password = request_json['data']['password']
            login_handler(client_socket, session, username, password)
        elif request_json['action'] == 'add_national_id':
            national_id = request_json['data']['national_id']
            jwt_token = request_json['data']['jwt_token']
            user_id = request_json['data']['user_id']
            add_national_id_handler(client_socket,session,jwt_token,national_id,user_id)
        elif request_json['action'] == 'get_user_data':
            jwt_token = request_json['data']['jwt_token']
            get_user_data_handler(client_socket,session,jwt_token)
        elif request_json['action'] == 'get_all_project_descriptions':
            get_all_project_descriptions_handler(client_socket,session)
        # else
        #  here we should decrypt the request to get the action and the data 

        elif request_json['action'] == 'complete_user_data':
            # print('entered the action block1')
            user_data = get_user_data(session, jwt_token)
            # print('entered the action block2')
            encrypted_request_data = base64.b64decode(request_json['data'])
            # print(f"here is the encrypted_request_data  {encrypted_request_data}")
            decrypted_request_data = decrypt_data(user_data['national_id'], encrypted_request_data)
            # print('entered the action block3')
            decrypted_request_json = json.loads(decrypted_request_data)
            # print('entered the action block4')

            user_id = decrypted_request_json['user_id']
            phone_number = decrypted_request_json['phone_number']
            mobile_number = decrypted_request_json['mobile_number']
            address = decrypted_request_json['address']
            national_id = decrypted_request_json['national_id']
            jwt_token = decrypted_request_json['jwt_token']
            # print(' the action block')


            complete_user_data_handler(client_socket, session, user_id, phone_number, mobile_number, address, national_id, jwt_token)
        elif request_json['action'] == 'project_descriptions':
            user_data = get_user_data(session, jwt_token)
            encrypted_request_data = base64.b64decode(request_json['data'])
            decrypted_request_data = decrypt_data(user_data['session_key'], encrypted_request_data)
            decrypted_request_json = json.loads(decrypted_request_data)
            user_id = decrypted_request_json['user_id']
            project_descriptions = decrypted_request_json['project_descriptions']
            jwt_token = decrypted_request_json['jwt_token']
            project_descriptions_handler(client_socket, session, user_id,project_descriptions,user_data['session_key'], jwt_token)
        elif request_json['action'] == 'send_marks':
            user_data = get_user_data(session, jwt_token)
            client_public_key= user_data['public_key']
            session_key = user_data['session_key']
            encrypted_request_data = base64.b64decode(request_json['data'])
            decrypted_request_data = decrypt_data(session_key, encrypted_request_data)
            decrypted_request_json = json.loads(decrypted_request_data)
            marks_data = decrypted_request_json['marks_data']
            marks_data_signature = decrypted_request_json['marks_data_signature']
            jwt_token = decrypted_request_json['jwt_token']
            send_marks_handler(client_socket, session,jwt_token,client_public_key,marks_data_signature,marks_data,session_key)
        elif request_json['action'] == 'send_csr': 
            user_data = get_user_data(session, jwt_token)
            session_key = user_data['session_key']
            user_id = user_data['user_id']
            encrypted_request_data = base64.b64decode(request_json['data'])
            decrypted_request_data = decrypt_data(session_key, encrypted_request_data)
            decrypted_request_json = json.loads(decrypted_request_data)
            professor_csr = decrypted_request_json['professor_csr']
            jwt_token = decrypted_request_json['jwt_token']
            send_csr_handler(client_socket,session,jwt_token,user_id,professor_csr,session_key)
        elif request_json['action'] == 'sign_csr':
            jwt_token = request_json['data']['jwt_token']
            ca_username = request_json['data']['ca_username']
            client_csr = request_json['data']['client_csr']
            client_name = request_json['data']['client_name']
            print('erorororor')
            ca_data = get_ca_data(session,jwt_token,ca_username)
            print('erorororor')
            ca_public_key = ca_data['public_key']
            print('erorororor')
            ca_private_key = ca_data['private_key']
            print(ca_private_key)
            print('erorororor')
            signed_certificate = sign_csr(client_csr,ca_private_key,ca_data['username'])
            print('erorororor')
            store_certificate_handler(client_socket,session,signed_certificate)

        else:
            send_response(client_socket, {'status': 'error', 'message': 'Invalid action'})

    except Exception as e:
        print(f"Error handling client: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

    finally:
        client_socket.close()

def create_account_handler(client_socket, session, username, password,role):
    response_data = create_account(session, username, password,role)
    send_response(client_socket, response_data)

def login_handler(client_socket, session, username, password):
    response_data = login(session, username, password)
    send_response(client_socket, response_data)

def add_national_id_handler(client_socket,session,jwt_token,national_id,user_id):
    response_data = add_national_id(session,jwt_token,national_id,user_id)
    print(f'this response data: {response_data}')
    send_response(client_socket,response_data)

def get_user_data_handler(client_socket, session, jwt_token):
    response_data = get_user_data(session, jwt_token)
    send_response(client_socket, response_data)

def get_all_project_descriptions_handler(client_socket,session):
    response_data = get_all_project_descriptions(session)
    send_response(client_socket,response_data)

def complete_user_data_handler(client_socket, session, user_id, phone_number, mobile_number, address, national_id, jwt_token):
    try:
        response_data = complete_user_data(
            session,
            user_id,
            phone_number,
            mobile_number,
            address,
            national_id,
            jwt_token
        )
        response_json = json.dumps(response_data)
        print(f'data raw::: {response_data}')
        encrypted_response_data = encrypt_data(national_id, response_json)
        encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')
        print(f"error ::: {encrypted_response_base64}")
        send_response(client_socket, {'data': encrypted_response_base64})
        print("error here 4")
    except Exception as e:
        print(f"Error handling complete_user_data request: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

def handShaking_handler(client_socket,session,client_public_key,session_key,signature,user_id,jwt_token,server_public_key):
    response_data = handShaking(session,client_public_key,session_key,signature,user_id,jwt_token,server_public_key)
    send_response(client_socket,response_data)

def project_descriptions_handler(client_socket, session, user_id, project_descriptions,session_key,jwt_token):
    try:
        response_data = add_project_descriptions(
            session,
            jwt_token,
            user_id,
            project_descriptions,
        )
        response_json = json.dumps(response_data)
        print(f'data raw::: {response_data}')
        encrypted_response_data = encrypt_data(session_key, response_json)
        encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')
        print(f"error ::: {encrypted_response_base64}")
        send_response(client_socket, {'data': encrypted_response_base64})
        print("error here 4")
    except Exception as e:
        print(f"Error handling complete_user_data request: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

def send_marks_handler(client_socket,session, jwt_token,client_public_key,marks_data_signature,marks_data,session_key):
    response_data = send_marks(session, jwt_token,client_public_key,marks_data_signature,marks_data)
    response_json = json.dumps(response_data)
    encrypted_response_data = encrypt_data(session_key, response_json)
    encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')
    send_response(client_socket, {'data': encrypted_response_base64})
    # send_response(client_socket,response_data)

def send_csr_handler(client_socket,session,jwt_token,user_id,professor_csr,session_key):
    response_data = store_csr(session, jwt_token,user_id, professor_csr)
    response_json = json.dumps(response_data)
    encrypted_response_data = encrypt_data(session_key, response_json)
    encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')
    send_response(client_socket, {'data': encrypted_response_base64})
    # send_response(client_socket,response_data)

def store_certificate_handler(client_socket,session, certificate):
    print("nooooo error ")
    certificate_info = retrieve_certificate_info(certificate)
    response_data = store_certificate(session , certificate_info['subject'].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,certificate_info['issuer'].get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,certificate)
    print("nooooo error ")
    send_response(client_socket,response_data)

def send_response(client_socket, response_data):
    try:

        response_data = json.dumps(response_data)
        length = str(len(response_data)).ljust(16)
        if client_socket.fileno() != -1:
<<<<<<< HEAD
            # Socket is open, proceed with sending data
            # print(f"send length : {length.encode('utf-8')}")
=======
            print(f"send length : {length.encode('utf-8')}")
>>>>>>> develop
            client_socket.send(length.encode('utf-8'))
            # print(f"send data : {response_data.encode('utf-8')}")
            client_socket.send(response_data.encode('utf-8'))
        else:
            print("Socket is closed.")
    except ConnectionAbortedError:
        print("Connection aborted by the client.")
    finally:
        client_socket.close()



def generate_key_pair():
    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    acct = Account.from_key(private_key)

    # Get the Ethereum address from the account
    address = acct.address

    print(f"private_key: {private_key}, public_key: {address}")

    return {
        "private_key": private_key,
        "public_key": address
    }

def generate_ecdsa_key_pair():
    # Generate a random private key
    private_key_bytes = secrets.token_bytes(32)

    # Create an EC private key object
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder='big'),
        ec.SECP256R1(),
        default_backend()
    )

    # Get the corresponding public key
    public_key = private_key.public_key()

    return private_key, public_key

def save_private_key_pem(private_key):
    # Save private key (keep it secure)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_pem

def save_public_key_pem(public_key):
    # Save public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem

def create_certificate_authority(session, name,password):
    private_key, public_key = generate_ecdsa_key_pair()

    private_key_pem = save_private_key_pem(private_key)
    public_key_pem = save_public_key_pem(public_key)
    print(private_key_pem)
    print(private_key_pem.decode())

    # Define file paths in the current directory
    private_key_file_path = 'private_key.pem'
    public_key_file_path = 'public_key.pem'

    with open(private_key_file_path, 'w') as private_key_file:
        private_key_file.write(private_key_pem.decode())

    with open(public_key_file_path, 'w') as public_key_file:
        public_key_file.write(public_key_pem.decode())

    # Create CertificateAuthority instance
    ca = CertificateAuthority(username=name,password=password, private_key=private_key_pem.decode(), public_key=public_key_pem.decode())

    # Add CA to the session and commit
    session.add(ca)
    session.commit()

    return ca

def generate_csr(private_key_pem, common_name):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]))

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    return csr_pem.decode()


def sign_csr(csr_pem, ca_private_key_pem, ca_name):
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    ca_private_key = serialization.load_pem_private_key(
        ca_private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    certificate = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_name)
        ])
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Adjust validity period as needed
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    return certificate_pem.decode()


# def validate_csr(csr_pem, ca_public_key):
#     try:
#         print("aaaa")
#         # Load CSR from PEM format
#         csr = x509.load_pem_x509_csr(csr_pem, default_backend())
#         hash_algorithm = hashes.SHA256()
#         print("aaaaa")
#         tbs_bytes = csr.tbs_certrequest_bytes


#         # Use tbs_certrequest_bytes instead of tbs_certificate_bytes
#         print("aaaaa4")

#         ca_public_key.verify(
#             csr.signature,
#             tbs_bytes,
#             ec.ECDSA(hash_algorithm)
#         )
#         print("aaaaa5")

#     except Exception as e:
#         raise ValueError("CSR signature validation failed") from e

def verify_client_certificate(client_certificate_pem, ca_public_key_pem):
    try:
        # Load the CA's public key
        ca_public_key = serialization.load_pem_public_key(ca_public_key_pem.encode(), backend=default_backend())

        # Load the client's certificate
        pem_data = client_certificate_pem.encode('utf-8')
        certificate = x509.load_pem_x509_certificate(pem_data, default_backend())

        # Extract the signature and TBS bytes from the certificate
        signature = certificate.signature
        tbs_certificate_bytes = certificate.tbs_certificate_bytes

        # Validate the client's certificate against the CA's public key
        ca_public_key.verify(
            signature,
            tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return {'status': 'success', 'message': 'Client certificate verification successful'}

    except Exception as e:
        print(f"Error verifying client certificate: {e}")
        return {'status': 'error', 'message': 'Client certificate verification failed'}


def retrieve_certificate_info(certificate_pem):
    # Load the certificate
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())

    # Retrieve specific fields
    subject = certificate.subject
    issuer = certificate.issuer
    validity_period = (certificate.not_valid_before, certificate.not_valid_after)
    public_key = certificate.public_key()
    serial_number = certificate.serial_number
    # key_usage_extension = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)

    # # Check if KeyUsage extension is present
    # key_usage = key_usage_extension.value if key_usage_extension else None

    signature_algorithm = certificate.signature_algorithm_oid

    # Convert public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        'subject': subject,
        'issuer': issuer,
        'validity_period': validity_period,
        'public_key': public_key_pem.decode(),
        'serial_number': serial_number,
        # 'key_usage': key_usage,
        'signature_algorithm': signature_algorithm
    }



# # Create a new Certificate Authority
# ca_instance = create_certificate_authority(session, name="YourCAName")

# # Assuming you have a university professor instance (adjust as needed)
# professor_name = "Professor Name"
# professor_instance = create_account(session, username="professor_username", password="professor_password", role="professor", **{"name": professor_name})

# # Generate CSR and sign it to get the certificate
# professor_csr = generate_csr(professor_instance.public_key, professor_name)
# signed_certificate = sign_csr(ca_instance.private_key, ca_instance.public_key, professor_csr, professor_name)

# # Save the signed certificate in the database or use it as needed
# # You can associate the certificate with the professor in the database
# # For example, create a new Certificate entry in the database
# certificate_entry = Certificate(user_id=professor_instance.id, public_key=signed_certificate, expiration_date=datetime.utcnow() + timedelta(days=365), ca_id=ca_instance.id)
# session.add(certificate_entry)
# session.commit()

def start_server():
    host = '127.0.0.1'
    port = 12345

    # Setup socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(socket.SOMAXCONN)

    print(f"Server listening on {host}:{port}")

    keys_info = generate_key_pair()
    private_key, public_key = generate_ecdsa_key_pair()
    private_key_pem = save_private_key_pem(private_key)
    public_key_pem = save_public_key_pem(public_key)
    session = create_session()
    print('no error 1')
    ca = create_certificate_authority(session, name="name",password= hash_password("caPassword"))
    print('no error 2')
    server_csr = generate_csr(private_key_pem.decode(), 'serverName')
    print('no error3')

    signed_certificate = sign_csr(server_csr, ca.private_key, 'serverName')

    print('no error4')


<<<<<<< HEAD
    # with open('server_public_key.pem', 'wb') as f:
    #     f.write(keys_info["public_key"].to_pem())
    
    # Create a new thread for handling the third task
=======
>>>>>>> develop

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, create_session(),keys_info["public_key"]))
            client_thread.start()

    except KeyboardInterrupt:
        print("Server shutting down.")
        

    except ConnectionAbortedError:
        print(f"Connection aborted by the client.")

    finally:
        server_socket.close()


if __name__ == "semaphore":
    start_server()
