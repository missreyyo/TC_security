import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import hashlib
import secrets
import sqlite3
from sympy import primefactors

# Prime number for random number generation
prime = 101

# Database connection
conn = sqlite3.connect('authentication.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hashed_tc TEXT UNIQUE,
        hashed_username TEXT UNIQUE,
        random_number INTEGER,
        algorithm TEXT
    )
''')

# Create symmetric keys table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS symmetric_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_hashed_username TEXT,
        recipient_hashed_username TEXT,
        symmetric_key TEXT,
        FOREIGN KEY(sender_hashed_username) REFERENCES users(hashed_username),
        FOREIGN KEY(recipient_hashed_username) REFERENCES users(hashed_username)
    )
''')
conn.commit()

def hash_string(string):
    return hashlib.sha256(string.encode()).hexdigest()

def generate_random_number():
    return secrets.randbelow(prime)

def validate_tc_number(tc_number):
    return len(tc_number) == 11 and tc_number.isdigit()

def register():
    tc_number = entry_register.get()
    username = entry_username.get()
    
    if not validate_tc_number(tc_number):
        messagebox.showerror("Error", "Invalid TC ID.")
        return
    
    if not username:
        messagebox.showerror("Error", "Username cannot be empty.")
        return
    
    hashed_tc = hash_string(tc_number)
    hashed_username = hash_string(username)
    
    if is_tc_registered(hashed_tc):
        messagebox.showerror("Error", "This TC ID is already registered.")
        return
    
    if is_username_registered(hashed_username):
        messagebox.showerror("Error", "This username is already registered.")
        return
    
    random_number = generate_random_number()
    algorithm = algorithm_combobox.get()
    save_user(hashed_tc, hashed_username, random_number, algorithm)
    
    key_display.delete(1.0, tk.END)
    key_display.insert(tk.END, f"Username: {username}\nHashed TC ID: {hashed_tc}\n")
    key_display.insert(tk.END, f"Random Number: {random_number}\n")
    key_display.insert(tk.END, f"Algorithm: {algorithm}\n")
    
    messagebox.showinfo("Success", "Registration successful!")
    open_symmetric_key_tab()

def authenticate():
    tc_number = entry_auth.get()
    username = entry_auth_username.get()
    hashed_tc = hash_string(tc_number)
    hashed_username = hash_string(username)
    algorithm = algorithm_combobox_auth.get()
    input_value = entry_algorithm_input.get().strip()

    try:
        if algorithm == "prime factors":
            input_value = list(map(int, input_value.split(',')))
        else:
            input_value = int(input_value)
    except ValueError:
        messagebox.showerror("Error", "Invalid input for the selected algorithm.")
        return

    if check_key_and_algorithm(hashed_tc, input_value, algorithm):
        messagebox.showinfo("Success", "Authentication successful!")
        open_symmetric_key_tab()
    else:
        messagebox.showerror("Error", "Invalid key or algorithm input!")

def view_symmetric_keys():
    keys_window = tk.Toplevel()
    keys_window.title("Symmetric Keys")

    keys_label = tk.Label(keys_window, text="Your generated symmetric keys:")
    keys_label.pack()

    keys_text = scrolledtext.ScrolledText(keys_window, width=50, height=10, wrap=tk.WORD)
    keys_text.pack()

    keys_text.delete(1.0, tk.END)  # Clear the text widget before inserting keys
    current_hashed_username = hash_string(entry_auth_username.get())
    cursor.execute('SELECT symmetric_key FROM symmetric_keys WHERE sender_hashed_username = ?', (current_hashed_username,))
    symmetric_keys = cursor.fetchall()
    if symmetric_keys:
        for key in symmetric_keys:
            keys_text.insert(tk.END, f"{key[0]}\n")
    else:
        keys_text.insert(tk.END, "No symmetric keys found.")

def generate_and_store_symmetric_key():
    symmetric_key = secrets.token_hex(16)
    sender_hashed_username = hash_string(entry_auth_username.get())  # Assuming the authenticated user is sending the key
    recipient_hashed_username = hash_string(entry_recipient.get())
    if not is_username_registered(recipient_hashed_username):
        messagebox.showerror("Error", "Recipient username not found.")
        return
    save_symmetric_key(sender_hashed_username, recipient_hashed_username, symmetric_key)
    messagebox.showinfo("Success", "Symmetric key generated and stored successfully!")
    view_symmetric_keys()

def send_symmetric_key():
    recipient_username = entry_recipient.get()
    symmetric_key = entry_symmetric_key.get()

    if not recipient_username or not symmetric_key:
        messagebox.showerror("Error", "Recipient username and key cannot be empty.")
        return

    sender_hashed_username = hash_string(entry_auth_username.get())
    recipient_hashed_username = hash_string(recipient_username)
    
    if not is_username_registered(recipient_hashed_username):
        messagebox.showerror("Error", "Recipient username not found.")
        return

    save_symmetric_key(sender_hashed_username, recipient_hashed_username, symmetric_key)
    messagebox.showinfo("Success", "Symmetric key sent successfully!")


    entry_symmetric_key.delete(0, tk.END)

def view_received_keys():
    keys_window = tk.Toplevel()
    keys_window.title("Received Keys")

    keys_label = tk.Label(keys_window, text="Keys received from other users:")
    keys_label.pack()

    keys_text = scrolledtext.ScrolledText(keys_window, width=50, height=10, wrap=tk.WORD)
    keys_text.pack()

    keys_text.delete(1.0, tk.END)  
    recipient_hashed_username = hash_string(entry_auth_username.get())
    cursor.execute('SELECT symmetric_key FROM symmetric_keys WHERE recipient_hashed_username = ?', (recipient_hashed_username,))
    result = cursor.fetchall()
    if result:
        for key in result:
            keys_text.insert(tk.END, f"{key[0]}\n")
    else:
        keys_text.insert(tk.END, "No keys received.")

def save_user(hashed_tc, hashed_username, random_number, algorithm):
    cursor.execute('INSERT INTO users (hashed_tc, hashed_username, random_number, algorithm) VALUES (?, ?, ?, ?)', (hashed_tc, hashed_username, random_number, algorithm))
    conn.commit()

def save_symmetric_key(sender_hashed_username, recipient_hashed_username, symmetric_key):
    cursor.execute('INSERT INTO symmetric_keys (sender_hashed_username, recipient_hashed_username, symmetric_key) VALUES (?, ?, ?)', (sender_hashed_username, recipient_hashed_username, symmetric_key))
    conn.commit()

def is_tc_registered(hashed_tc):
    cursor.execute('SELECT hashed_tc FROM users WHERE hashed_tc = ?', (hashed_tc,))
    return cursor.fetchone() is not None

def is_username_registered(hashed_username):
    cursor.execute('SELECT hashed_username FROM users WHERE hashed_username = ?', (hashed_username,))
    return cursor.fetchone() is not None

def check_key_and_algorithm(hashed_tc, input_value, algorithm):
    cursor.execute('SELECT random_number, algorithm FROM users WHERE hashed_tc = ?', (hashed_tc,))
    result = cursor.fetchone()
    if result:
        saved_random_number, saved_algorithm = result
        if saved_algorithm == "square root" and input_value == int(saved_random_number ** 0.5):
            return True
        elif saved_algorithm == "square" and input_value == saved_random_number ** 2:
            return True
        elif saved_algorithm == "prime factors" and set(primefactors(saved_random_number)) == set(input_value):
            return True
    return False

def open_symmetric_key_tab():
    global entry_symmetric_key, entry_recipient  # Declare as global to use in send_symmetric_key function

    # Symmetric key
    frame_symmetric_key = tk.Frame(notebook)
    notebook.add(frame_symmetric_key, text="Symmetric Key")

    label_generate_key = tk.Label(frame_symmetric_key, text="Generate and store your symmetric key:")
    label_generate_key.pack()

    generate_key_button = tk.Button(frame_symmetric_key, text="Generate and Store Key", command=generate_and_store_symmetric_key)
    generate_key_button.pack()

    view_keys_button = tk.Button(frame_symmetric_key, text="View Keys", command=view_symmetric_keys)
    view_keys_button.pack()

    label_recipient = tk.Label(frame_symmetric_key, text="Send symmetric key to another user:")
    label_recipient.pack()

    entry_recipient = tk.Entry(frame_symmetric_key)
    entry_recipient.pack()

    label_symmetric_key = tk.Label(frame_symmetric_key, text="Enter symmetric key:")
    label_symmetric_key.pack()

    entry_symmetric_key = tk.Entry(frame_symmetric_key)
    entry_symmetric_key.pack()

    send_key_button = tk.Button(frame_symmetric_key, text="Send Key", command=send_symmetric_key)
    send_key_button.pack()

    view_received_keys_button = tk.Button(frame_symmetric_key, text="View Received Keys", command=view_received_keys)
    view_received_keys_button.pack()

# GUI
root = tk.Tk()
root.title("Two-Factor Authentication System")

# Notebook widget creating
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Register window
frame_register = tk.Frame(notebook)
notebook.add(frame_register, text="Register")

label_register = tk.Label(frame_register, text="Enter your TC ID:")
label_register.pack()

entry_register = tk.Entry(frame_register)
entry_register.pack()

label_username = tk.Label(frame_register, text="Enter your username:")
label_username.pack()

entry_username = tk.Entry(frame_register)
entry_username.pack()

label_algorithm = tk.Label(frame_register, text="Select an algorithm:")
label_algorithm.pack()

algorithm_combobox = ttk.Combobox(frame_register, values=["square root", "square", "prime factors"])
algorithm_combobox.pack()

register_button = tk.Button(frame_register, text="Register", command=register)
register_button.pack()

key_display = scrolledtext.ScrolledText(frame_register, width=50, height=5, wrap=tk.WORD)
key_display.pack()

# Authentication window
frame_authenticate = tk.Frame(notebook)
notebook.add(frame_authenticate, text="Authenticate")

label_auth = tk.Label(frame_authenticate, text="Enter your TC ID:")
label_auth.pack()

entry_auth = tk.Entry(frame_authenticate)
entry_auth.pack()

label_auth_username = tk.Label(frame_authenticate, text="Enter your username:")
label_auth_username.pack()

entry_auth_username = tk.Entry(frame_authenticate)
entry_auth_username.pack()

label_algorithm_auth = tk.Label(frame_authenticate, text="Select the algorithm used for registration:")
label_algorithm_auth.pack()

algorithm_combobox_auth = ttk.Combobox(frame_authenticate, values=["square root", "square", "prime factors"])
algorithm_combobox_auth.pack()

label_algorithm_input = tk.Label(frame_authenticate, text="Enter the algorithm input (e.g., square root value or prime factors):")
label_algorithm_input.pack()

entry_algorithm_input = tk.Entry(frame_authenticate)
entry_algorithm_input.pack()

authenticate_button = tk.Button(frame_authenticate, text="Authenticate", command=authenticate)
authenticate_button.pack()

# Close the database connection when the GUI is closed
def on_closing():
    conn.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()