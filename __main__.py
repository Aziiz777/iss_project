
from server.server1 import start_server
from database.db_manager import init_db

if __name__ == "__main__":
    init_db()  # Initialize the database
    start_server()  # Start the server
