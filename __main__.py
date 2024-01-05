from database.db_manager import init_db
from server.server1 import start_server
import os

if __name__ == "__main__":

    db_file = 'university_system.db'
    if os.path.exists(db_file):
        os.remove(db_file)

    init_db()
    start_server()