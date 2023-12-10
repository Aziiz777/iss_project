# server/server.py
import socket
import threading
import json
from database.db_manager import create_session
from database.models import User
from database.db_operations import create_account,login

# Server state (for simplicity)
symmetric_key = None

# Function to handle client connections
def handle_client(client_socket, session):
    global symmetric_key

    try:
        # Receive client request
        request_data = client_socket.recv(1024)
        request_json = json.loads(request_data)

        # Process the request
        if request_json['action'] == 'create_account':
            username = request_json['username']
            password = request_json['password']
            create_account_handler(client_socket, session, username, password)

        elif request_json['action'] == 'login':
            username = request_json['username']
            password = request_json['password']
            login_handler(client_socket, session, username, password)

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
# Function to send a JSON response to the client
def send_response(client_socket, response_data):
    global symmetric_key
    response_data = json.dumps(response_data)
    
    # Send the length of the data first
    length = len(response_data)
    client_socket.send(str(length).encode('utf-8').ljust(16))

    # Send the data in chunks
    for i in range(0, length, 1024):
        chunk = response_data[i:i + 1024]
        client_socket.send(chunk.encode('utf-8'))


# Function to hash a password using SHA-256
# def hash_password(password):
#     return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Function to start the server
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
