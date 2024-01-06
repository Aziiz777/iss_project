import tkinter as tk
from tkinter import messagebox
from client import send_request

class CSR:
    def __init__(self, client_id, client_name, client_csr):
        self.client_id = client_id
        self.client_name = client_name
        self.client_csr = client_csr

class CA(tk.Frame):
    def __init__(self, master, token, csrs):
        tk.Frame.__init__(self, master)        

        self.token = token
        self.csrs = self.extract_csrs(csrs)

        label = tk.Label(self, text="Pending Certificates", font=("Arial", 18))
        label.pack(pady=20)

        # Create a canvas for scrollable content
        self.canvas = tk.Canvas(self)
        self.canvas.pack(fill=tk.BOTH, expand=True, anchor='center')
        self.canvas.config(height=350)

        content_frame = tk.Frame(self.canvas)

        for csr in self.csrs:
            
            name_label = tk.Label(content_frame, text='Client name: ' + csr.client_name)
            name_label.pack(pady=2)

            # Create a "Sign" button for each CSR
            sign_button = tk.Button(
                content_frame, 
                text="Sign", 
                command= lambda copy=csr  : self.sign(copy)
                )
            sign_button.pack(ipady=2, ipadx=4, pady=2)

            divider = tk.Label(content_frame, bg="grey")
            divider.pack(fill=tk.X)

        # Create the scrollbar and canvas
        self.scrollbar = tk.Scrollbar(self, command=self.canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window((150, 0), window=content_frame, anchor="nw")
        content_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

    
    def sign(self, csr):
        # Create a new popup window
        popup = tk.Toplevel(self.master)
        popup.geometry('600x300')
        popup.resizable(False, False)
        popup.title("Sign CSR")        

        # Create a label and an entry field for entering the mark
        label = tk.Label(popup, text="CSR is")
        label.pack(pady=[20,5])
        csr_label = tk.Label(popup, text=csr.client_csr)
        csr_label.pack(pady=[20,5])

        submit_button = tk.Button(popup, text="Submit", command=lambda: self.submit(popup, csr))
        submit_button.pack(ipadx=4, ipady=2)

    
    def submit(self, popup, csr):
        response = send_request(
            'sign_csr',
            {
                'jwt_token': self.token,
                'client_csr': csr.client_csr, 
                'client_name': csr.client_name, 
                'ca_username': 'name'
            }
        )

        message = response['message']
        messagebox.showinfo('Response', message)

        if response['status'].lower() == 'success':
            self.csrs.remove(csr)
            popup.destroy()
    
    def extract_csrs(self, csrs: dict):
        temp_csrs = []

        for user_id, csr_data in csrs.items():
            
            name = csr_data['username']
            csr_pem = csr_data['csr_pem']
            csr = CSR(user_id, name, csr_pem)

            temp_csrs.append(csr)

        return temp_csrs