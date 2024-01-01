import tkinter as tk
from screens.login import Login
from screens.signup import SignUp


class Application(tk.Frame):

    def __init__(self, master):
        tk.Frame.__init__(self, master)

        login_btn = tk.Button(self, text="Login", command=self.open_login_screen)
        login_btn.pack(pady=[150, 10], anchor="center", ipady=2, ipadx=10)

        signup_btn = tk.Button(self, text="Sign up", command=self.open_signup_screen)
        signup_btn.pack(pady=[10, 50], anchor="center", ipady=2, ipadx=10)
        

    def open_login_screen(self):
        self.pack_forget()
        login_frame = Login(self.master, self.show_main)
        login_frame.pack()
        

    def open_signup_screen(self):
        self.pack_forget()
        signup_frame = SignUp(self.master, self.show_main)
        signup_frame.pack()


    def show_main(self):
        self.pack()


def start_app():
    root = tk.Tk()
    root.title("ISS Project")
    root.geometry("400x400")
    root.resizable(False, False)

    app = Application(root)
    app.pack()

    root.mainloop()

if __name__ == "semaphore":
    start_app()