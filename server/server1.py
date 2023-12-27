# server/server.py
import socket
import threading
import json
import base64
import secrets
from eth_account import Account
import pickle
from database.db_manager import create_session
from database.models import User
from database.db_operations import create_account,login,complete_user_data,add_national_id,get_user_data,get_all_project_descriptions,handShaking,add_project_descriptions,send_marks
from symmetric_encryption import encrypt_data,decrypt_data,encrypt_message,decrypt_message



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
            send_marks_handler(client_socket, session,jwt_token,client_public_key,marks_data_signature,marks_data)

        else:
            send_response(client_socket, {'status': 'error', 'message': 'Invalid action'})

    except Exception as e:
        print(f"Error handling client: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

    finally:
        client_socket.close()

# Function to create a new account
def create_account_handler(client_socket, session, username, password,role):
    response_data = create_account(session, username, password,role)
    send_response(client_socket, response_data)

# Function to handle login
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
        # Convert bytes to base64 before sending
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

        # Convert bytes to base64 before sending
        encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')
        print(f"error ::: {encrypted_response_base64}")

        send_response(client_socket, {'data': encrypted_response_base64})
        print("error here 4")

    except Exception as e:
        print(f"Error handling complete_user_data request: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

def send_marks_handler(client_socket,session, jwt_token,client_public_key,marks_data_signature,marks_data):
    response_data = send_marks(session, jwt_token,client_public_key,marks_data_signature,marks_data)
    send_response(client_socket,response_data)

def send_response(client_socket, response_data):
    try:

        response_data = json.dumps(response_data)
        length = str(len(response_data)).ljust(16)
        if client_socket.fileno() != -1:
            # Socket is open, proceed with sending data
            print(f"send length : {length.encode('utf-8')}")
            client_socket.send(length.encode('utf-8'))
            print(f"send data : {response_data.encode('utf-8')}")
            client_socket.send(response_data.encode('utf-8'))
            print(f"send data : {response_data.encode('utf-8')}")
        else:
            # Socket is closed, handle accordingly
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




def start_server():
    host = '127.0.0.1'
    port = 12345

    # Setup socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(socket.SOMAXCONN)

    print(f"Server listening on {host}:{port}")

    # Save the server's key pair
    keys_info = generate_key_pair()
    # with open('server_private_key.pem', 'wb') as f:
    #     f.write(keys_info["private_key"].to_pem())

    # with open('server_public_key.pem', 'wb') as f:
    #     f.write(keys_info["public_key"].to_pem())

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, create_session(),keys_info["public_key"]))
            client_thread.start()

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
