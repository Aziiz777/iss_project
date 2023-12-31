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

def send_request(action, data,jwt_token=None,):
    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        request_data = {}
        request_data['data'] = data
        request_data['action']=action

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

            print(f"The request_data is: {request_data}")

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
            print(f"The request_data is: {request_data}")
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
            print(f"The request_data is: {request_data}")
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

            # Send the length of the data after sending the JSON
            length = len(request_json)
            client_socket.send(str(length).encode('utf-8').ljust(16))

        else:
            request_json = json.dumps(request_data)
            client_socket.send(request_json.encode('utf-8'))

        # Receive the length of the response
        response_length = int(client_socket.recv(16).strip())
        print(f"Received response length: {response_length}")

        # Receive the response data
        received_data = b''
        while len(received_data) < response_length:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            received_data += chunk

        print(f"Received response: {received_data.decode('utf-8')}")

        try:
            print("enter try ")
            # Decrypt data if the action is "complete_user_data"
            if action == 'complete_user_data':
                # Decode base64 before decrypting
                print(f"Recieved dataaa: {received_data.strip()}")

                response_json = json.loads(received_data.decode('utf-8'))
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(national_id, encrypted_data)
            if action == 'project_descriptions':
                # Decode base64 before decrypting
                print(f"Recieved dataaa: {received_data.strip()}")

                response_json = json.loads(received_data.decode('utf-8'))
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(session_key, encrypted_data)
                print (f"decrypted_response :: {decrypted_response}")


            else:
                decrypted_response = received_data

            response_json = json.loads(decrypted_response)
            print(f"Parsed JSON: {response_json}")

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
    print(f"Decrypted data: {unpadded_data}")


    return unpadded_data.decode('utf-8')


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

def execute():
    # Test creating an account
    print("CCCcCCCCCcccCCcccCcccCCCCccccCCcccC")
    send_request('create_account', {'username': 'testuserProfessor', 'password': 'testpasswordProfessor','role':'professor'})

    # Test login
    login_response = send_request('login', {'username': 'testuserProfessor', 'password': 'testpasswordProfessor'})
    # print(f"Received Complete login Response: {login_response}")

    jwt_token = login_response.get('jwt_token','')
    add_national_id_response = send_request('add_national_id', {'jwt_token': jwt_token, 'national_id': '12345678911','user_id': "3"})
    get_user_data_response = send_request ('get_user_data', {'jwt_token':jwt_token})
    user_id = get_user_data_response.get('user_id','')
    national_id = get_user_data_response.get('national_id','')
    # Test complete_user_data
    # complete_user_data_response= send_request('complete_user_data', {
    #     'user_id': user_id,
    #     'phone_number': '1233234435',
    #     'mobile_number': '1241421',
    #     'address': 'barzeh',
    #     'national_id': national_id,
    #     'jwt_token': jwt_token
    # },jwt_token)

    # print(f"Received Complete User Data Response: {complete_user_data_response}")

    keys_info =generate_key_pair()

    # Generate a session key and signature
    session_key_info = generate_session_key(keys_info["private_key"])
    session_key = session_key_info["session_key"]
    print(f"session_key:: {session_key}")
    signature = session_key_info["signature"]
    print(f"signature:: {signature}")

    # Handshake with the server
    handshake_response = send_request('handshake', {'public_key': keys_info["public_key"],'user_id': user_id,'session_key': session_key, 'signature': signature},jwt_token)
    server_public_key = handshake_response.get('server_public_key', None)
    print(f"server_public_key: {server_public_key}")

    # project_descriptions = ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']
    # action = 'project_descriptions'
    # data = {'jwt_token': jwt_token,'user_id':user_id,'session_key':session_key, 'project_descriptions': project_descriptions}
    # send_request(action, data, jwt_token,session_key)

    get_all_project_response = send_request ('get_all_project_descriptions',{'jwt_token':jwt_token})
    print(get_all_project_response)

    # Assuming the response structure
    response = {
    'status': 'success',
    'project_descriptions': {
        '1': {'user_id': 1, 'username': 'testuser17', 'project_descriptions': ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']},
        '2': {'user_id': 2, 'username': 'testuser173', 'project_descriptions': ['Project 1: Description', 'Project 2: Description', 'Project 3: Description']}
    }
    }

    student_id = 1
    project_id = 1

    # Get the project descriptions for the specific user and project
    user_projects = get_all_project_response.get('project_descriptions', {})
    project_description = user_projects.get(str(student_id), {}).get('project_descriptions', [])[project_id - 1]
    client_private_key = keys_info["private_key"]
    private_key_bytes = bytes.fromhex(client_private_key[2:])

    # Example marks data
    marks_data = {
        'student_id': student_id,
        'professor_id':user_id,
        'project_id': project_id,
        'mark': 90,
    }
    
    # Encode marks_data to a string
    marks_data_str = json.dumps(marks_data, sort_keys=True)
    signed_message = messages.encode_defunct(text=marks_data_str)

    # Sign the message
    signature = Account.sign_message(signed_message, private_key_bytes)

    # Send marks for the specific project
    send_request('send_marks', {'jwt_token': jwt_token,'marks_data_signature':signature.signature.hex(), 'marks_data': marks_data,'session_key':session_key},jwt_token)


if __name__ == "semaphore":
    execute()


