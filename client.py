# client.py
import socket
import json
import base64
import pickle
import secrets
from eth_account import Account,messages
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
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

certificate_data = None

def send_request(action, data,jwt_token=None):
    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        request_data = {}
        request_data['data'] = data
        request_data['action']=action
        if certificate_data:
            request_data['certificate'] = certificate_data 

        if jwt_token:
         request_data['headers'] = {'Authorization':jwt_token}

        # Encrypt data if the action is "complete_user_data"
        if action == 'add_national_id':
            request_data['data']['jwt_token'] = data['jwt_token']
            request_data['data']['national_id'] = data['national_id']
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))
            
                    
        elif action == 'complete_user_data':
            national_id = data['national_id']
            encrypted_data = encrypt_data(national_id, json.dumps(request_data['data']))

            # Convert the encrypted data to base64 before including it in the JSON
            encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            request_data['data'] = encrypted_data_base64

            # print(f"The request_data is: {request_data}")

            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

            # Send the length of the data after sending the JSON
            length = len(request_json)
            client_socket.send(str(length).encode('utf-8').ljust(16))
        elif action == 'project_descriptions':
            session_key = data['session_key']
            encrypted_data = encrypt_data(session_key,json.dumps(request_data['data']))
            encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            request_data['data'] = encrypted_data_base64
            # print(f"The request_data is: {request_data}")
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

            # Send the length of the data after sending the JSON
            length = len(request_json)
            client_socket.send(str(length).encode('utf-8').ljust(16))
        elif action == 'send_marks':
            session_key = data['session_key']
            encrypted_data = encrypt_data(session_key,json.dumps(request_data['data']))
            encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            request_data['data'] = encrypted_data_base64
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

            # Send the length of the data after sending the JSON
            length = len(request_json)
            client_socket.send(str(length).encode('utf-8').ljust(16))
        elif action == 'send_csr':
            session_key = data['session_key']
            encrypted_data =encrypt_data(session_key, json.dumps(request_data['data']))
            encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            request_data['data'] = encrypted_data_base64
            # print(f"The request_data is: {request_data}")
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))
            length = len(request_json)
            client_socket.send(str(length).encode('utf-8').ljust(16))
            

        else:
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

        response_length = int(client_socket.recv(16).strip())

        received_data = b''
        while len(received_data) < response_length:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            received_data += chunk

        try:
            # Decrypt data if the action is "complete_user_data"
            if action == 'complete_user_data':
                # Decode base64 before decrypting
                response_json = json.loads(received_data.decode('utf-8'))
                print(f"encrypted Data: {response_json['data']}")
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(national_id, encrypted_data)
                response_json = json.loads(decrypted_response)
                print(f"decrypted Data: {response_json}")
                return response_json
                # print(f"Decrypted data: {decrypted_response['message']}")

            if action == 'project_descriptions':

                response_json = json.loads(received_data.decode('utf-8'))
                print(f"encrypted Data: {response_json['data']}")
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(session_key, encrypted_data)
                response_json = json.loads(decrypted_response)
                print(f"decrypted Data: {response_json}")
                return response_json
            if action =='send_marks':
                response_json = json.loads(received_data.decode('utf-8'))
                print(f"encrypted Data: {response_json['data']}")
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(session_key, encrypted_data)
                response_json = json.loads(decrypted_response)
                print(f"decrypted Data: {response_json}")
                return response_json
            if action =='send_csr':
                response_json = json.loads(received_data.decode('utf-8'))
                print(f"encrypted Data: {response_json['data']}")
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(session_key, encrypted_data)
                response_json = json.loads(decrypted_response)
                print(f"decrypted Data: {response_json}")
                return response_json

            else:
                decrypted_response = received_data
            response_json = json.loads(decrypted_response)

            return response_json  # Return the entire response

        except json.decoder.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return {'status': 'error', 'message': 'Invalid JSON'}



def encrypt_data(key, data):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'saltsalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode('utf-8'))

    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add PKCS7 padding to the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()


    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data


def decrypt_data(key, encrypted_data):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'saltsalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode('utf-8'))

    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode('utf-8')


def generate_key_pair():
    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    acct = Account.from_key(private_key)

    # Get the Ethereum address from the account
    address = acct.address
    print(f"\n------------------------PRIVATE-KEY-------------------------------")
    print(private_key)
    print(f"\n------------------------PUBLIC-KEY--------------------------------")
    print(address)

    return {
        "private_key": private_key,
        "public_key": address
    }

def generate_session_key(client_private_key):
    # Generate a random session key for symmetric encryption (e.g., AES)
    session_key = secrets.token_hex(16)  # 16 bytes for AES-128, adjust as needed

    private_key_bytes = bytes.fromhex(client_private_key[2:])

    # Sign the message
    signed_message = messages.encode_defunct(text=session_key)
    signature = Account.sign_message(signed_message, private_key_bytes)

    return {
        "session_key": session_key,
        "signature": signature.signature.hex()
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


def generate_csr(private_key_pem, common_name):
    # Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    # Create a CSR builder
    builder = x509.CertificateSigningRequestBuilder()

    # Add subject information
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]))

    # Sign the CSR with the private key
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Convert the CSR to PEM format
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    return csr_pem.decode()

def read_key_from_file(file_path):
    with open(file_path, 'r') as key_file:
        key_content = key_file.read()
    return key_content


if __name__ == "__main__":
    # Test creating an account
    print("---------------------Start Create Account Test --------------------------------\n")
    # create_account_response = send_request('create_account', {'username': 'testuserStudent', 'password': 'testpasswordStudent','role':'student'})
    create_account_response = send_request('create_account', {'username': 'testuserProfessor', 'password': 'testpasswordProfessor','role':'professor'})
    print(f"{create_account_response} \n")
    print("---------------------End Create Account Test --------------------------------")


    # Test login
    print("\n---------------------Start LogIn Test --------------------------------\n")

    login_response = send_request('login', {'username': 'testuserProfessor', 'password': 'testpasswordProfessor'})
    # login_response = send_request('login', {'username': 'testuserStudent', 'password': 'testpasswordStudent'})
    print(f"{login_response} \n")
    print("---------------------End LogIn Test --------------------------------")




    # print(f"Received Complete login Response: {login_response}")

    jwt_token = login_response.get('jwt_token','')
    user_id = login_response.get('user_id','')
    print("\n---------------------Start add_national_id Test --------------------------------\n")

    add_national_id_response = send_request('add_national_id', {'jwt_token': jwt_token, 'national_id': '12345678911','user_id': user_id},jwt_token)
    print(f"{add_national_id_response}\n")
    print("---------------------End add_national_id Test --------------------------------")

    get_user_data_response = send_request ('get_user_data', {'jwt_token':jwt_token},jwt_token)
    user_id = get_user_data_response.get('user_id','')
    national_id = get_user_data_response.get('national_id','')
    # # Test complete_user_data
    print("\n---------------------Start complete_user_data Test --------------------------------\n")

    complete_user_data_response= send_request('complete_user_data', {
        'user_id': user_id,
        'phone_number': '1233234435',
        'mobile_number': '1241421',
        'address': 'barzeh',
        'national_id': national_id,
        'jwt_token': jwt_token
    },jwt_token)

    print("---------------------End complete_user_data Test --------------------------------")


    # print(f"Received Complete User Data Response: {complete_user_data_response}")

    keys_info =generate_key_pair()

    # # Generate a session key and signature
    session_key_info = generate_session_key(keys_info["private_key"])
    session_key = session_key_info["session_key"]
    print("\n -------------------session-key----------------------------")
    print(f"{session_key}")
    print("\n -------------------session-key-signature----------------------------")
    signature = session_key_info["signature"]
    print(f"{signature}")
    # # Handshake with the server
    print("\n-----------------------Start HandShaking-------------------------------")
    handshake_response = send_request('handshake', {'public_key': keys_info["public_key"],'user_id': user_id,'session_key': session_key, 'signature': signature},jwt_token)
    server_public_key = handshake_response.get('server_public_key', None)
    print(f"server_public_key: {server_public_key}")
    print("-----------------------End HandShaking-------------------------------")

    print("\n------------------Start sending projects_descriptions-----------------")
    project_descriptions = ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']
    action = 'project_descriptions'
    data = {'jwt_token': jwt_token,'user_id':user_id,'session_key':session_key, 'project_descriptions': project_descriptions}
    send_request(action, data, jwt_token)
    print("\n------------------End sending projects_descriptions-----------------")


    get_all_project_response = send_request ('get_all_project_descriptions',{'jwt_token':jwt_token})
    # print(get_all_project_response)
    # # Assuming the response structure
    # response = {
    # 'status': 'success',
    # 'project_descriptions': {
    #     '1': {'user_id': 1, 'username': 'testuser17', 'project_descriptions': ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']},
    #     '2': {'user_id': 2, 'username': 'testuser173', 'project_descriptions': ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']}
    # }
    # }

    student_id = 2
    project_id = 1

    # # Get the project descriptions for the specific user and project
    user_projects = get_all_project_response.get('project_descriptions', {})
    project_description = user_projects.get(str(student_id), {}).get('project_descriptions', [])[project_id - 1]
    client_private_key = keys_info["private_key"]
    private_key_bytes = bytes.fromhex(client_private_key[2:])

    # # Example marks data
    marks_data = {
        'student_id': student_id,
        'professor_id':user_id,
        'project_id': project_id,
        'mark': 90,
    }

    # Encode marks_data to a string
    marks_data_str = json.dumps(marks_data, sort_keys=True)
    signed_message = messages.encode_defunct(text=marks_data_str)

    # # Sign the message
    signature = Account.sign_message(signed_message, private_key_bytes)

    # # Send marks for the specific project
    print("\n------------------Start sending projects marks-----------------")
    send_request('send_marks', {'jwt_token': jwt_token,'marks_data_signature':signature.signature.hex(), 'marks_data': marks_data,'session_key':session_key},jwt_token)
    print("\n------------------End sending projects marks -----------------\n")


    professor_private, professor_public = generate_ecdsa_key_pair()
    # Save private and public keys in PEM format
    private_key_pem = save_private_key_pem(professor_private)
    public_key_pem = save_public_key_pem(professor_public)

    # private_key_content = read_key_from_file('private_key.pem')
    # print(private_key_content)
    # public_key_content = read_key_from_file('public_key.pem')
    print("----------------generating professor csr -----------------------------")
    professor_csr = generate_csr(private_key_pem.decode(),"testuserProfessor")
    print(f"the csr :\n    {professor_csr}")


    print("----------------Start sending professor csr -----------------------------")

    send_csr_response = send_request('send_csr',{'jwt_token': jwt_token , 'professor_csr': professor_csr,'session_key': session_key},jwt_token)
    # print(send_csr_response)

    print("----------------End sending professor csr -----------------------------")

    print("\n----------------Start LogIn with CA Credentials -----------------------------\n")


    login_response = send_request('login', {'username': 'name', 'password': 'caPassword'})
    jwt_token = login_response.get('jwt_token','')
    print(login_response)

    print("----------------End LogIn with CA Credentials -----------------------------\n")

    # print("Before send_request:", certificate_data)
    print("----------------Start signning professor csr -----------------------------\n")

    sign_csr_response = send_request('sign_csr', {'jwt_token': jwt_token, 'client_csr': professor_csr, 'client_name': 'testuserProfessor', 'ca_username': 'name'}, jwt_token)
    print(sign_csr_response)
    certificate_data = sign_csr_response.get('certificate_data', "")
    print("----------------End signning professor csr -----------------------------")
    # print("After send_request:", certificate_data)
    login_response = send_request('login', {'username': 'name', 'password': 'caPassword'})


    

