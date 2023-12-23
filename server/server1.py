# server/server.py
import socket
import threading
import json
from database.db_manager import create_session
from database.models import User
from database.db_operations import create_account,login,complete_user_data,add_national_id,get_user_data
from symmetric_encryption import encrypt_data,decrypt_data
import base64



def handle_client(client_socket, session):
   

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
        print("after jwt ")
   

        # Process the request
        if request_json['action'] == 'create_account':
            username = request_json['data']['username']
            password = request_json['data']['password']
            create_account_handler(client_socket, session, username, password)

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

        else:
            send_response(client_socket, {'status': 'error', 'message': 'Invalid action'})

    except Exception as e:
        print(f"Error handling client: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})

    finally:
        client_socket.close()

# Function to create a new account
def create_account_handler(client_socket, session, username, password):
    response_data = create_account(session, username, password)
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


        encrypted_response_data = encrypt_data(national_id, response_json)

        # Convert bytes to base64 before sending
        encrypted_response_base64 = base64.b64encode(encrypted_response_data).decode('utf-8')

        send_response(client_socket, {'data': encrypted_response_base64})
        print("error here 4")

    except Exception as e:
        print(f"Error handling complete_user_data request: {e}")
        send_response(client_socket, {'status': 'error', 'message': 'Server error'})




def send_response(client_socket, response_data):
    try:

        response_data = json.dumps(response_data)

        
        length = str(len(response_data)).ljust(16)


        client_socket.send(length.encode('utf-8'))


        client_socket.send(response_data.encode('utf-8'))


    except ConnectionAbortedError:
        print("Connection aborted by the client.")
    finally:
        client_socket.close()


# Function to hash a password using SHA-256
# def hash_password(password):
#     return hashlib.sha256(password.encode('utf-8')).hexdigest()


def start_server():
    host = '127.0.0.1'
    port = 12345

    # Setup socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(socket.SOMAXCONN)

    print(f"Server listening on {host}:{port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, create_session()))
            client_thread.start()

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
