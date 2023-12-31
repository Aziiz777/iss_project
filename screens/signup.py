import tkinter as tk
from tkinter import messagebox
from client import send_request

class SignUp(tk.Frame):
    def __init__(self, master, show_main):
        tk.Frame.__init__(self, master)
        self.show_main = show_main
    
        # Label for the Signup form
        label = tk.Label(self, text="Sign Up", font=("Arial", 18))
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

        # Role Select
        role_label = tk.Label(self, text="Role:")
        role_label.pack()

        self.role_var = tk.StringVar(self)
        self.role_var.set("Student")  # Default value
        self.role_dropdown = tk.OptionMenu(self, self.role_var, "Student", "Professor")
        self.role_dropdown.pack()

        # Sign up button
        signup_button = tk.Button(
            self, 
            text="Sign up", 
            command=self.signup_handler,            
            )
        signup_button.pack(pady=[30, 10], ipady=2, ipadx=10)

        # Back button
        back_button = tk.Button(
            self, 
            text="Back", 
            command=self.back
            )
        back_button.pack(pady=10, ipady=2, ipadx=10)
    
    def signup_handler(self):
        # Retrieve values from entry fields in the Login tab
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = self.role_var.get()

        response = send_request(
            "create_account", 
            {
                'username': username,
                'password': password,
                'role': role
            }
            )

        message = response['message']

        # Display response using a messagebox
        messagebox.showinfo("Response", message)

    def back(self):
        self.destroy()
        self.show_main()