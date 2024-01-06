import tkinter as tk
from tkinter import messagebox
from client import send_request
from screens.national_id import NationalId
from screens.professor import Professor
from screens.ca import CA

class Login(tk.Frame):
    def __init__(self, master, show_main):
        tk.Frame.__init__(self, master)
        self.show_main = show_main

        # Label for the login form
        label = tk.Label(self, text="Login", font=("Arial", 18))
        label.pack(pady=20)

        # Username field
        username_label = tk.Label(self, text="Username:")
        username_label.pack()

        self.username_entry = tk.Entry(self, width=30)
        self.username_entry.pack()

        # Password field
        password_label = tk.Label(self, text="Password:")
        password_label.pack()
        
        self.password_entry = tk.Entry(self, width=30, show="*")
        self.password_entry.pack()

        # Login button
        login_button = tk.Button(
            self, 
            text="Login", 
            command=self.login_handler,            
            )
        login_button.pack(pady=[30, 10], ipady=2, ipadx=10)

        # Back button
        back_button = tk.Button(
            self, 
            text="Back", 
            command=self.back
            )
        back_button.pack(pady=10, ipady=2, ipadx=10)
    
    def login_handler(self):
        
        username = self.username_entry.get()
        password = self.password_entry.get()

        
        response = send_request(
            "login", 
            {
                'username': username,
                'password': password
            }
            )

        message = response['message']
    
        # Display response using a messagebox
        messagebox.showinfo("Response", message)

        if response['status'].lower() == 'success':
            token = response['jwt_token']
            user_id = response['user_id']
            role = response['role']
            self.next_page(token, user_id, role)
    
    def next_page(self, token, user_id, role):        
        self.pack_forget()
        if role.lower() == 'student':
            national_id_frame = NationalId(self.master.master, token, user_id)
            national_id_frame.pack()
        elif role.lower() == 'professor':
            professor_frame = Professor(self.master.master, token, user_id)
            professor_frame.pack()
        else:
            csrs_response = send_request ('get_all_csrs',{'jwt_token':token})
            ca_frame = CA(self.master.master, token, csrs_response['csrs'])
            ca_frame.pack()


    def back(self):
        self.destroy()        
        self.show_main()
