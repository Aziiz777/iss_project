# client.py
import socket
import json
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def send_request(action, data,jwt_token=None):
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
            # Decrypt data if the action is "complete_user_data"
            if action == 'complete_user_data':
                # Decode base64 before decrypting
                print(f"Recieved dataaa: {received_data.strip()}")

                response_json = json.loads(received_data.decode('utf-8'))
                encrypted_data = base64.b64decode(response_json.get('data', '').strip())
                decrypted_response = decrypt_data(national_id, encrypted_data)


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


if __name__ == "__main__":
    # Test creating an account
    send_request('create_account', {'username': 'testuser133', 'password': 'testpassword133'})

    # Test login
    login_response = send_request('login', {'username': 'testuser133', 'password': 'testpassword133'})
    # print(f"Received Complete login Response: {login_response}")

    jwt_token = login_response.get('jwt_token','')
    # add_national_id_response = send_request('add_national_id', {'jwt_token': jwt_token, 'national_id': '12345678911','user_id': "1"})
    get_user_data_response = send_request ('get_user_data', {'jwt_token':jwt_token})
    # print(f'thisss is the user data: {get_user_data_response}')
    user_id = get_user_data_response.get('user_id','')
    national_id = get_user_data_response.get('national_id','')
    # Test complete_user_data
    complete_user_data_response= send_request('complete_user_data', {
        'user_id': user_id,
        'phone_number': '1233234435',
        'mobile_number': '1241421',
        'address': 'barzeh',
        'national_id': national_id,
        'jwt_token': jwt_token
    },jwt_token)

    print(f"Received Complete User Data Response: {complete_user_data_response}")
