import os
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, filedialog
from cryptography.fernet import Fernet
import base64

# Helper functions
def generate_key(password):
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)[:32])

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(data, key):
    f = Fernet(key)
    return f.decrypt(data).decode('utf-8')

def save_credentials():
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return

    save_password = simpledialog.askstring("Save Password", "Enter a password to encrypt the data:", show='*')
    if not save_password:
        return

    key = generate_key(save_password)
    encrypted_data = encrypt_data(f"{username}:{password}", key)

    file_name = simpledialog.askstring("File Name", "Enter a name for this credential file:")
    if not file_name:
        return

    filename = os.path.join(directory, f"{file_name}.enc")

    with open(filename, 'wb') as file:
        file.write(encrypted_data)

    listbox.insert(tk.END, file_name)
    messagebox.showinfo("Success", f"Credentials saved and encrypted in {filename}")

def load_credentials():
    selected_file = listbox.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("Selection Error", "Please select a file to load.")
        return

    filename = os.path.join(directory, f"{selected_file}.enc")
    load_password = simpledialog.askstring("Load Password", "Enter the password to decrypt the data:", show='*')
    if not load_password:
        return

    key = generate_key(load_password)

    try:
        with open(filename, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = decrypt_data(encrypted_data, key)
        username, password = decrypted_data.split(':')
        messagebox.showinfo("Credentials", f"Username: {username}\nPassword: {password}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt data: {e}")

def delete_credentials():
    selected_file = listbox.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("Selection Error", "Please select a file to delete.")
        return

    confirm = messagebox.askyesno("Delete Confirmation", f"Are you sure you want to delete '{selected_file}'?")
    if confirm:
        filename = os.path.join(directory, f"{selected_file}.enc")
        try:
            os.remove(filename)
            listbox.delete(tk.ACTIVE)
            messagebox.showinfo("Success", f"'{selected_file}' has been deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {e}")

def select_directory():
    global directory
    directory = filedialog.askdirectory(title="Select Directory to Save and Load Credentials")
    if directory:
        refresh_listbox()

def refresh_listbox():
    listbox.delete(0, tk.END)
    for file in os.listdir(directory):
        if file.endswith(".enc"):
            listbox.insert(tk.END, file[:-4])

# GUI Setup
app = tk.Tk()
app.title("Password Manager")
app.resizable(False, False)
style = ttk.Style(app)
style.configure('TButton', font=('Helvetica', 12), padding=10)
style.configure('TLabel', font=('Helvetica', 12))
style.configure('TEntry', font=('Helvetica', 12))
style.configure('TFrame', padding=20)
style.configure('TSeparator', background='black')

main_frame = ttk.Frame(app)
main_frame.pack(padx=20, pady=20)

select_dir_button = ttk.Button(main_frame, text="Select Directory", command=select_directory)
select_dir_button.grid(row=0, column=0, columnspan=2, pady=10)

username_label = ttk.Label(main_frame, text="Username:")
username_label.grid(row=1, column=0, sticky=tk.W, pady=5)

username_entry = ttk.Entry(main_frame, width=30)
username_entry.grid(row=1, column=1, pady=5)

password_label = ttk.Label(main_frame, text="Password:")
password_label.grid(row=2, column=0, sticky=tk.W, pady=5)

password_entry = ttk.Entry(main_frame, width=30, show='*')
password_entry.grid(row=2, column=1, pady=5)

button_frame = ttk.Frame(main_frame)
button_frame.grid(row=3, column=0, columnspan=2, pady=10)

save_button = ttk.Button(button_frame, text="Save", command=save_credentials)
save_button.grid(row=0, column=0, padx=10)

load_button = ttk.Button(button_frame, text="Load", command=load_credentials)
load_button.grid(row=0, column=1, padx=10)

delete_button = ttk.Button(button_frame, text="Delete", command=delete_credentials)
delete_button.grid(row=0, column=2, padx=10)

listbox_label = ttk.Label(main_frame, text="Saved Credentials:")
listbox_label.grid(row=4, column=0, columnspan=2, pady=5)

listbox = tk.Listbox(main_frame, height=10, width=50)
listbox.grid(row=5, column=0, columnspan=2, pady=5)

app.mainloop()
