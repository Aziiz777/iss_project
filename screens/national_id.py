import tkinter as tk
import tkinter.messagebox as messagebox
from screens.complete_data import CompleteData
from client import send_request

class NationalId(tk.Frame):

    def __init__(self, master, token, user_id):
        tk.Frame.__init__(self, master)
        
        self.token = token
        self.user_id = user_id

        label = tk.Label(self, text="Enter your national ID:")
        label.pack(pady=[100, 10])

        self.entry = tk.Entry(self, width=50)
        self.entry.pack(pady=[0, 20], ipady=5)

        submit_button = tk.Button(self, text="Submit", command=self.submit)
        submit_button.pack(pady=10, ipadx= 5)

    def submit(self):
        national_id = self.entry.get()
        token = self.token
        user_id = self.user_id
        response = send_request(
            'add_national_id',
            {
                'user_id': user_id,
                'national_id': national_id,
                'jwt_token': token
            }
        )

        message = response['message']
        messagebox.showinfo("Response", message)

        if response['status'].lower() == 'success':
            self.next_page(user_id, token, national_id)
    
    def next_page(self, user_id, token, national_id):
        self.pack_forget()

        complete_data_frame = CompleteData(self.master, user_id, token, national_id)
        complete_data_frame.pack()
