import json
import tkinter as tk
from tkinter import messagebox
from screens.enter_projects import Project
from client import send_request
from client import generate_key_pair
from client import generate_session_key
from eth_account import Account,messages

class SendMarks(tk.Frame):
    def __init__(self, master, args, back_to_prof):
        tk.Frame.__init__(self, master)

        self.user_id = args['user_id']
        self.token = args['token']
        data = args['data']['project_descriptions']
        self.projects = self.extract_projects(data)
        self.back_to_prof = back_to_prof

        self.keys_info = generate_key_pair()
        self.session_key_info = generate_session_key(self.keys_info['private_key'])
        self.signature = self.session_key_info["signature"]
        self.session_key = self.session_key_info['session_key']
        send_request(
            'handshake',
            {
                'user_id': self.user_id,
                'public_key': self.keys_info['public_key'],
                'session_key': self.session_key,
                'signature': self.signature
            },
            self.token
            )

        label = tk.Label(self, text="Projects", font=("Arial", 18))
        label.pack(pady=[20, 10])

        # Create a canvas for scrollable content
        self.canvas = tk.Canvas(self)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)        
        self.canvas.config(height=350)

        content_frame = tk.Frame(self.canvas)

        for project in self.projects:
            # Create a label for project name and description
            name_label = tk.Label(content_frame, text='Project name: ' + project.name, width=50)
            name_label.pack(pady=2)
            desc_label = tk.Label(content_frame, text='Project description: ' + project.desc, wraplength=200)
            desc_label.pack(pady=2)

            # Create an "Add Mark" button for each project
            add_mark_button = tk.Button(
                content_frame, 
                text="Add Mark", 
                command= lambda copy=project  : self.add_mark(copy)
                )
            add_mark_button.pack(ipady=2, ipadx=4, pady=2)

            divider = tk.Label(content_frame, bg="grey")
            divider.pack(fill=tk.X)

        
        self.back_btn = tk.Button(content_frame, text="Back", command=self.back)
        self.back_btn.pack(pady=20 ,anchor="center", ipady=2, ipadx=10)
        
        # Create the scrollbar and canvas
        self.scrollbar = tk.Scrollbar(self, command=self.canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window((125, 0), window=content_frame, anchor="nw")
        content_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

    
    def add_mark(self, project):
        # Create a new popup window
        popup = tk.Toplevel(self.master)
        popup.geometry('300x150')
        popup.resizable(False, False)
        popup.title("Add Mark")        

        # Create a label and an entry field for entering the mark
        mark_label = tk.Label(popup, text="Enter the mark for " + project.name)
        mark_label.pack(pady=[20,5])
        mark_entry = tk.Entry(popup)
        mark_entry.pack(pady=[5,20])

        # Create a "Send" button to submit the mark
        send_button = tk.Button(popup, text="Send", command=lambda: self.send_mark(popup, project, mark_entry))
        send_button.pack(ipadx=4, ipady=2)

    
    def send_mark(self, popup, project, mark_entry):
        mark = mark_entry.get()
        marks_data = {
            'student_id': project.user_id,
            'professor_id': self.user_id,
            'project_id': project.project_id,
            'mark': mark,
        }

        private_key = self.keys_info['private_key']
        private_key_bytes = bytes.fromhex(private_key[2:])

        # Encode marks_data to a string
        marks_data_str = json.dumps(marks_data, sort_keys=True)
        signed_message = messages.encode_defunct(text=marks_data_str)

        # Sign the message
        signature = Account.sign_message(signed_message, private_key_bytes)

        user_data_response = send_request(
            'get_user_data',
            {
                'jwt_token': self.token
            },
            self.token
        )
        
        if 'certificate' in user_data_response:
            response = send_request(
                'send_marks',
                {
                    'jwt_token': self.token,
                    'marks_data_signature': signature.signature.hex(),
                    'marks_data': marks_data,
                    'session_key': self.session_key,
                    'certificate': user_data_response['certificate']
                },
                self.token
            )
        else:
            response = send_request(
                'send_marks',
                {
                    'jwt_token': self.token,
                    'marks_data_signature': signature.signature.hex(),
                    'marks_data': marks_data,
                    'session_key': self.session_key,
                },
                self.token
            )

        message = response['message']
        messagebox.showinfo('Response', message)

        if response['status'].lower() == 'success':
            popup.destroy()
        

    def extract_projects(self, data: dict):
        projects = []

        count = 1
        for user_id, user_data in data.items():
            user_projects = user_data['project_descriptions']

            for user_project in user_projects:
                project_info = user_project.split(':')
                project_name = project_info[0].strip()
                project_desc = project_info[1].strip()

                project = Project(project_name, project_desc, user_id, count)

                projects.append(project)
                count += 1

        return projects
    
    def back(self):
        self.destroy()
        self.back_to_prof()