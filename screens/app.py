import tkinter as tk
from screens.login import Login
from screens.signup import SignUp


class Application():

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ISS Project")
        self.root.geometry("400x400")
        self.root.resizable(False, False)

        login_btn = tk.Button(self.root, text="Login", command=self.open_login_screen)
        login_btn.pack(pady=20)

        signup_btn = tk.Button(self.root, text="Signup", command=self.open_signup_screen)
        signup_btn.pack(pady=20)

        self.root.mainloop()
        

    def open_login_screen(self):
        self.login_frame = Login()
        

    def open_signup_screen(self):
        self.signup_frame = SignUp()


def start_app():
    app = Application()

if __name__ == "semaphore":
    start_app()