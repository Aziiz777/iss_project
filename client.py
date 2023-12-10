# client.py
import socket
import json

def send_request(action, data):
    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        request_data = {'action': action, **data}
        request_json = json.dumps(request_data)
        client_socket.send(request_json.encode('utf-8'))

        # Receive the length of the response
        response_length = int(client_socket.recv(16).strip())
        print(f"Received response length: {response_length}")

        # Receive the response data in chunks
        received_data = ''
        while len(received_data) < response_length:
            chunk = client_socket.recv(1024).decode('utf-8')
            received_data += chunk

        print(f"Received response: {received_data}")

        try:
            response_json = json.loads(received_data)
            print(f"Parsed JSON: {response_json}")
        except json.decoder.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return

if __name__ == "__main__":
    # Test creating an account
    send_request('create_account', {'username': 'testuser13', 'password': 'testpassword13'})

    # Test login
    send_request('login', {'username': 'testuser4', 'password': 'testpassword'})
