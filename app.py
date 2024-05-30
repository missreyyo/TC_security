import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import hashlib
import secrets
import sqlite3
from sympy import primefactors

# prime number for easy using
prime = 101

# database
conn = sqlite3.connect('authentication.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hashed_tc TEXT UNIQUE,
        random_number INTEGER,
        algorithm TEXT
    )
''')
conn.commit()

def hash_tc(tc_number):
    hashed_tc = hashlib.sha256(tc_number.encode()).hexdigest()
    return hashed_tc

def generate_random_number():
    random_number = secrets.randbelow(prime)
    return random_number

def validate_tc_number(tc_number):
    if len(tc_number) != 11 or not tc_number.isdigit():
        return False
    return True

def register():
    tc_number = entry_register.get()
    if not validate_tc_number(tc_number):
        messagebox.showerror("Error", "Invalid TC ID.")
        return

    hashed_key = hash_tc(tc_number)
    if is_key_registered(hashed_key):
        messagebox.showerror("Error", "This TC ID is already registered.")
        return

    random_number = generate_random_number()
    algorithm = algorithm_combobox.get() 
    save_key_and_random_number(hashed_key, random_number, algorithm)
    key_display.delete(1.0, tk.END)
    key_display.insert(tk.END, f"Hashed TC ID: {hashed_key}\n")
    key_display.insert(tk.END, f"Random Number: {random_number}\n")
    key_display.insert(tk.END, f"Algorithm: {algorithm}\n")
    messagebox.showinfo("Success", f"Registration successful! Your hashed TC ID and random number are displayed below.")
    open_symmetric_key_tab()  

def authenticate():
    tc_number = entry_auth.get()
    hashed_key = hash_tc(tc_number)
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

    if check_key_and_algorithm(hashed_key, input_value, algorithm):
        messagebox.showinfo("Success", "Authentication successful!")
        open_symmetric_key_tab()  
    else:
        messagebox.showerror("Error", "Invalid key or algorithm input!")

def view_symmetric_keys():
    keys_window = tk.Toplevel()
    keys_window.title("Symmetric Keys")

    keys_label = tk.Label(keys_window, text="Previously generated symmetric keys:")
    keys_label.pack()

    keys_text = scrolledtext.ScrolledText(keys_window, width=50, height=10, wrap=tk.WORD)
    keys_text.pack()

    cursor.execute('SELECT hashed_tc FROM users WHERE algorithm = "symmetric"')
    symmetric_keys = cursor.fetchall()
    if symmetric_keys:
        for key in symmetric_keys:
            keys_text.insert(tk.END, f"{key[0]}\n")
    else:
        keys_text.insert(tk.END, "No symmetric keys found.")

def generate_and_store_symmetric_key():
    symmetric_key = secrets.token_hex(16)   
    save_key_and_random_number(symmetric_key, None, "symmetric")  
    messagebox.showinfo("Success", "Symmetric key generated and stored successfully!")
    view_symmetric_keys() 

def save_key_and_random_number(key, random_number, algorithm):
    cursor.execute('INSERT INTO users (hashed_tc, random_number, algorithm) VALUES (?, ?, ?)', (key, random_number, algorithm))
    conn.commit()

def is_key_registered(key):
    cursor.execute('SELECT hashed_tc FROM users WHERE hashed_tc = ?', (key,))
    return cursor.fetchone() is not None

def check_key_and_algorithm(key, input_value, algorithm):
    cursor.execute('SELECT random_number, algorithm FROM users WHERE hashed_tc = ?', (key,))
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
    # Symmetric key
    frame_symmetric_key = tk.Frame(notebook)
    notebook.add(frame_symmetric_key, text="Symmetric Key")

    label_generate_key = tk.Label(frame_symmetric_key, text="Generate and store your symmetric key:")
    label_generate_key.pack()

    generate_key_button = tk.Button(frame_symmetric_key, text="Generate and Store Key", command=generate_and_store_symmetric_key)
    generate_key_button.pack()

    view_keys_button = tk.Button(frame_symmetric_key, text="View Keys", command=view_symmetric_keys)
    view_keys_button.pack()

# GUI
root = tk.Tk()
root.title("Two-Factor Authentication System")

# Notebook widget creating
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# register window
frame_register = tk.Frame(notebook)
notebook.add(frame_register, text="Register")

label_register = tk.Label(frame_register, text="Enter your TC ID:")
label_register.pack()

entry_register = tk.Entry(frame_register)
entry_register.pack()

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