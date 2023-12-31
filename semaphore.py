import threading, time
from database.db_manager import init_db
from server.server1 import start_server
from client import execute

class Semaphore:
    def __init__(self, count):
        self.count = count
        self.mutex = threading.Lock()

    def acquire(self):
        with self.mutex:
            if self.count > 0:
                self.count -= 1
                return True
            else:
                return False

    def release(self):
        with self.mutex:
            self.count += 1

class Thread1(threading.Thread):
    def run(self):
        print("Thread 1 started")
        
        init_db()
        start_server()

        # Acquire the semaphore to signal that Thread 1 is ready
        semaphore.acquire()

        # Perform the work of Thread 1
        print("Thread 1 is performing its work")
        time.sleep(2)

        # Release the semaphore to signal that Thread 1 is done
        semaphore.release()

class Thread2(threading.Thread):
    def run(self):
        print("Thread 2 started")

        execute()

        # Wait for Thread 1 to signal that it is ready
        while semaphore.acquire() is False:
            time.sleep(0.1)  # Check every 0.1 seconds

        # Perform the work of Thread 2
        print("Thread 2 is performing its work")
        time.sleep(2)
        
def runSemaphore():
    global semaphore
    semaphore = Semaphore(0)  # Initialize the semaphore to 0

    thread1 = Thread1()
    thread2 = Thread2()

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

if __name__ == "__main__":
    runSemaphore()