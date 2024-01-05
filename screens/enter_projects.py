import tkinter as tk
from tkinter import scrolledtext
from client import generate_key_pair
from client import generate_session_key
from client import send_request
from tkinter import messagebox as messagebox

class Project:
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc

    def get_project_info(self):
        info = f'{self.name}: {self.desc.rstrip()}'
        return info

class ProjectWindow:
    def __init__(self, master, project_list, project_textbox):
        self.window = tk.Toplevel(master)
        self.window.geometry("300x300")
        self.window.title("New Project")
        self.window.resizable(False, False)

        self.name_label = tk.Label(self.window, text="Name:")
        self.name_label.pack(pady=[25,0])
        self.name_entry = tk.Entry(self.window)
        self.name_entry.pack()

        self.desc_label = tk.Label(self.window, text="Description:")
        self.desc_label.pack(pady=[5,0])
        self.desc_entry = tk.Text(self.window, height=6, width=25)
        self.desc_entry.pack()

        self.confirm_button = tk.Button(self.window, text="Confirm", command=lambda: self.add_project(project_list, project_textbox))
        self.confirm_button.pack(pady= [20] ,ipady=2, ipadx=4)

    def add_project(self, project_list, project_textbox):
        name = self.name_entry.get()
        description = self.desc_entry.get('1.0', tk.END)
        project = Project(name, description)
        project_list.append(project)
        project_text = f"{project.name}\n{project.desc.rstrip()}"
        project_textbox.config(state=tk.NORMAL)
        project_textbox.insert(tk.END, project_text + "\n" + "-" * 20 + "\n")
        project_textbox.config(state=tk.DISABLED)
        self.window.destroy()

class EnterProjects(tk.Frame):
    def __init__(self, master, user_id, token):
        tk.Frame.__init__(self, master)
        
        self.user_id = user_id
        self.token = token
        self.project_list = []
        self.first_run = True
        self.keys_info = None
        self.session_key_info = None
        self.session_key = None
        self.signature = None

        self.scrollbar = tk.Scrollbar(self)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.project_textbox = scrolledtext.ScrolledText(self, yscrollcommand=self.scrollbar.set, width=50, height=15)
        self.project_textbox.pack(padx=10, pady=[20, 5])
        self.project_textbox.config(state=tk.DISABLED)        

        self.add_button = tk.Button(self, text="Add Project", command=self.add_project_window)
        self.add_button.pack(ipady=2, ipadx=2, pady=[20, 5])

        self.send_button = tk.Button(self, text="Send", command=self.send_projects)
        self.send_button.pack(ipady=2, ipadx=2, pady=5)

        self.scrollbar.config(command=self.project_textbox.yview)

    def add_project_window(self):
        project_window = ProjectWindow(self.master, self.project_list, self.project_textbox)

    def send_projects(self):

        user_id = self.user_id
        token = self.token

        if self.first_run:
            self.keys_info = generate_key_pair()
            self.session_key_info = generate_session_key(self.keys_info['private_key'])
            self.session_key = self.session_key_info['session_key']
            self.signature = self.session_key_info['signature']

            response = send_request(
                'handshake',
                {
                    'user_id': user_id,
                    'public_key': self.keys_info['public_key'],
                    'session_key': self.session_key,
                    'signature': self.signature
                },
                token
                )

            if response['status'].lower() == 'success':
                message = (f"Handshaking done successfully."
                f"\nPrivate key: {self.keys_info['private_key']}" 
                f"\nPublic key: {self.keys_info['public_key']}" 
                f"\nServer key: {response['server_public_key']}")

                messagebox.showinfo("Handshaking", message)

                self.first_run = False

        selected_projects = [project.get_project_info() for project in self.project_list]

        response = send_request(
            'project_descriptions',
            {
                'user_id': user_id,
                'jwt_token': token,
                'session_key': self.session_key,
                'project_descriptions': selected_projects
            },
            token
        )

        message = response['message']
        messagebox.showinfo('Response', message)

        if response['status'].lower() == 'success':
            self.project_textbox.config(state=tk.NORMAL)
            self.project_textbox.delete(1.0, tk.END)
            self.project_textbox.config(state=tk.DISABLED)