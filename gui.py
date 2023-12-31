import tkinter as tk
from tkinter import ttk, messagebox

class ClientGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Client GUI")

        # Create tabs
        self.tabs = ttk.Notebook(master)

        self.create_account_tab = ttk.Frame(self.tabs)
        self.login_tab = ttk.Frame(self.tabs)

        self.tabs.add(self.create_account_tab, text="Create Account")
        self.tabs.add(self.login_tab, text="Login")

        # Initialize tabs
        self.initialize_create_account_tab()
        self.initialize_login_tab()

        # Pack tabs
        self.tabs.pack(expand=1, fill="both")

    def initialize_create_account_tab(self):
        # Configure row and column weights
        self.create_account_tab.rowconfigure(0, weight=1)
        self.create_account_tab.rowconfigure(1, weight=1)
        self.create_account_tab.rowconfigure(2, weight=1)
        self.create_account_tab.rowconfigure(3, weight=1)
        self.create_account_tab.columnconfigure(0, weight=1)
        self.create_account_tab.columnconfigure(1, weight=1)

        # Widgets for the Create Account tab
        self.create_username_label = tk.Label(self.create_account_tab, text="Username:")
        self.create_username_entry = tk.Entry(self.create_account_tab)

        self.create_password_label = tk.Label(self.create_account_tab, text="Password:")
        self.create_password_entry = tk.Entry(self.create_account_tab, show="*")

        self.role_label = tk.Label(self.create_account_tab, text="Role:")
        self.role_var = tk.StringVar()
        self.role_combobox = ttk.Combobox(self.create_account_tab, textvariable=self.role_var, values=["Student", "Professor"])

        self.create_account_button = tk.Button(self.create_account_tab, text="Create Account", command=self.create_account)

        # Grid layout for Create Account tab
        self.create_username_label.grid(row=0, column=0, sticky=tk.E)
        self.create_username_entry.grid(row=0, column=1, sticky=tk.W)

        self.create_password_label.grid(row=1, column=0, sticky=tk.E)
        self.create_password_entry.grid(row=1, column=1, sticky=tk.W)

        self.role_label.grid(row=2, column=0, sticky=tk.E)
        self.role_combobox.grid(row=2, column=1, sticky=tk.W)

        self.create_account_button.grid(row=3, column=0, columnspan=2, pady=10)


    def initialize_login_tab(self):
        # Widgets for the Login tab
        self.login_username_label = tk.Label(self.login_tab, text="Username:")
        self.login_username_entry = tk.Entry(self.login_tab)

        self.login_password_label = tk.Label(self.login_tab, text="Password:")
        self.login_password_entry = tk.Entry(self.login_tab, show="*")

        self.login_button = tk.Button(self.login_tab, text="Login", command=self.login)
        # Grid layout for Login tab
        self.login_username_label.grid(row=0, column=0, sticky=tk.E)
        self.login_username_entry.grid(row=0, column=1)

        self.login_password_label.grid(row=1, column=0, sticky=tk.E)
        self.login_password_entry.grid(row=1, column=1)

        self.login_button.grid(row=2, column=0, columnspan=2)

    def create_account(self):
        # Retrieve values from entry fields in the Create Account tab
        username = self.create_username_entry.get()
        password = self.create_password_entry.get()

        # Placeholder for actual account creation code
        response = f"Creating account for {username}"

        # Display response using a messagebox
        messagebox.showinfo("Response", response)

    def login(self):
        # Retrieve values from entry fields in the Login tab
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()

        # Placeholder for actual login code
        response = f"Logging in with {username}"

        # Display response using a messagebox
        messagebox.showinfo("Response", response)
    
def startGUI():

    root = tk.Tk()
    app = ClientGUI(root)
    # Set the initial size of the window
    root.geometry("1200x800")  # Width x Height
    # default_font = tk.font.nametofont("TkDefaultFont")
    # default_font.configure(size=12) 
    root.mainloop()