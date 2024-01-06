import tkinter as tk
from client import send_request
from screens.send_marks import SendMarks

class Professor(tk.Frame):
    def __init__(self, master, token, user_id):

        tk.Frame.__init__(self, master)

        self.user_id = user_id 
        self.token = token

        projects_btn = tk.Button(self, text="Projects", command=self.open_projects_screen)
        projects_btn.pack(pady=[150, 10], anchor="center", ipady=2, ipadx=10)

        csr_btn = tk.Button(self, text="Generate CSR", command=self.generate_csr)
        csr_btn.pack(pady=[10, 50], anchor="center", ipady=2, ipadx=10)

    
    def open_projects_screen(self):

        self.pack_forget()
        
        response = send_request(
            'get_all_project_descriptions',
            {
                'jwt_token': self.token
            }
        )

        if response['status'].lower() == 'success':
            args = {
                'user_id': self.user_id,
                'token': self.token,
                'data': response,
            }

            send_marks_frame = SendMarks(self.master, args, self.back)
            send_marks_frame.pack()

    
    def back(self):
        self.pack()        


    def generate_csr(self):
        print("CSR")