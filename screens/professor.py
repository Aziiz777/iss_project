import tkinter as tk
from tkinter import messagebox
from client import send_request, generate_key_pair, generate_session_key
from client import generate_ecdsa_key_pair, save_public_key_pem, save_private_key_pem, generate_csr
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

        professor_private, professor_public = generate_ecdsa_key_pair()
        # Save private and public keys in PEM format
        private_key_pem = save_private_key_pem(professor_private)
        public_key_pem = save_public_key_pem(professor_public)

        challenge_response = send_request(
            'generate_challenge',
            {},
            self.token
        )

        challenge = challenge_response['challenge']

        # Create a new popup window
        popup = tk.Toplevel(self.master)
        popup.geometry('300x150')
        popup.resizable(False, False)
        popup.title("Solve Challenge")        

        # Create a label and an entry field for solving the challenge
        label = tk.Label(popup, text="What is " + challenge)
        label.pack(pady=[20,5])
        solution_entry = tk.Entry(popup)
        solution_entry.pack(pady=[5,20])

        submit_button = tk.Button(
            popup, 
            text="Submit", 
            command=lambda: self.send_csr_request(private_key_pem, challenge, solution_entry, popup)
            )
        submit_button.pack(ipadx=4, ipady=2)

    
    def send_csr_request(self, pk_pem, challenge, solution_entry, popup):
        
        user_data = send_request(
            'get_user_data',
            {
                'jwt_token': self.token
            },
            self.token
        )

        user_name = user_data['user_name']

        session_key = None

        if user_data['session_key'] != None:
            session_key = user_data['session_key']
        else:
            session_key = self.handshake()

        solution = solution_entry.get()

        csr = generate_csr(
            pk_pem.decode(),
            user_name,
            challenge,
            solution
        )

        response = send_request(
            'send_csr',
            {
                'jwt_token': self.token,
                'professor_csr': csr,
                'session_key': session_key
            },
            self.token
        )

        message = response['message']
        messagebox.showinfo('Response', message)

        popup.destroy()

    
    def handshake(self):
        keys_info = generate_key_pair()
        session_key_info = generate_session_key (keys_info['private_key'])
        signature = session_key_info["signature"]
        session_key = session_key_info['session_key']
        send_request(
            'handshake',
            {
                'user_id': self.user_id,
                'public_key': keys_info['public_key'],
                'session_key': session_key,
                'signature': signature
            },
            self.token
            )
        return session_key