import tkinter as tk
import tkinter.messagebox as messagebox
from client import send_request
from screens.enter_projects import EnterProjects

class CompleteData(tk.Frame):

    def __init__(self, master, user_id, token, national_id):
        tk.Frame.__init__(self, master)
        
        self.user_id = user_id
        self.token = token
        self.national_id = national_id

        label = tk.Label(self, text="Complete your data", font=("Arial", 18))
        label.pack(pady=[50, 20])

        label1 = tk.Label(self, text="Phone Number:")
        label1.pack()

        self.phoneEntry = tk.Entry(self, width=30)
        self.phoneEntry.pack()

        labe2 = tk.Label(self, text="Mobile Number:")
        labe2.pack()

        self.mobileEntry = tk.Entry(self, width=30)
        self.mobileEntry.pack()

        labe3 = tk.Label(self, text="Address:")
        labe3.pack()

        self.addEntry = tk.Entry(self, width=50)
        self.addEntry.pack()

        submit_button = tk.Button(self, text="Submit", command=self.submit)
        submit_button.pack(pady=20, ipadx= 5)

    def submit(self):
        phone = self.phoneEntry.get()
        mobile = self.mobileEntry.get()
        add = self.addEntry.get()

        user_id = self.user_id
        national_id = self.national_id
        token = self.token

        # response = send_request(
        #     'complete_user_data',
        #     {
        #         'phone_number': phone,
        #         'mobile_number': mobile,
        #         'address': add,
        #         'user_id': user_id,
        #         'national_id': national_id,
        #         'jwt_token': token
        #     },
        #     token
        #     )
        
        # message = response['message']
        # messagebox.showinfo("Response", message)

        # if response['status'].lower() == 'success':
        #     self.next_page(user_id, token, national_id)

        self.next_page(user_id, token)

    def next_page(self, user_id, token):
        self.pack_forget()

        projects_frame = EnterProjects(self.master, user_id, token)
        projects_frame.pack()