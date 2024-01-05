from database.db_manager import init_db
from server.server1 import start_server

if __name__ == "__main__":
    init_db()
    start_server()