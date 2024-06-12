import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import hashlib
import secrets
import sqlite3
from sympy import isprime, randprime
import pycryptosat
import subprocess

# Database connection
conn = sqlite3.connect('authentication.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hashed_tc TEXT UNIQUE,
        hashed_username TEXT UNIQUE,
        public_key TEXT,
        g TEXT,
        p TEXT
    )
''')
conn.commit()

# Helper functions
def hash_string(string):
    return hashlib.sha256(string.encode()).hexdigest()

def validate_tc_number(tc_number):
    return len(tc_number) == 11 and tc_number.isdigit()

def generate_prime_group(bits=256):
    q = randprime(2**(bits-1), 2**bits)
    p = 2 * q + 1
    while not isprime(p):
        q = randprime(2**(bits-1), 2**bits)
        p = 2 * q + 1
    g = 2
    return p, q, g

def schnorr_generate_keys(p, q, g):
    secret = secrets.randbelow(q)
    public_key = pow(g, secret, p)
    return secret, public_key

def schnorr_generate_commitment(p, g, q):
    r = secrets.randbelow(q)
    commitment = pow(g, r, p)
    return r, commitment

def schnorr_generate_challenge():
    return secrets.randbits(256)

def schnorr_generate_response(secret, r, challenge, q):
    return (r + secret * challenge) % q

def schnorr_verify(public_key, response, challenge, commitment, p, g):
    left = pow(g, response, p)
    right = (commitment * pow(public_key, challenge, p)) % p
    return left == right

# ZkSNARK functions
def zk_snark_prove(statement):
    # Use libsnark to generate a proof
    proof = subprocess.check_output(['libsnark_prove', statement])
    return proof

def zk_snark_verify(proof, statement):
    # Use libsnark to verify the proof
    result = subprocess.check_output(['libsnark_verify', proof, statement])
    return result == b'1'

# Register function
def register():
    try:
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
        
        # Generate Schnorr keys
        p, q, g = generate_prime_group()
        secret, public_key = schnorr_generate_keys(p, q, g)
        
        # Save user
        save_user(hashed_tc, hashed_username, str(public_key), str(g), str(p))
        
        key_display.delete(1.0, tk.END)
        key_display.insert(tk.END, f"Username: {username}\nHashed TC ID: {hashed_tc}\n")
        key_display.insert(tk.END, f"Public Key: {public_key}\n")
        key_display.insert(tk.END, f"Secret Key (Save this!): {secret}\n")
        
        messagebox.showinfo("Success", "Registration successful! Save your secret key.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Authentication function
def authenticate():
    try:
        tc_number = entry_auth.get()
        username = entry_auth_username.get()
        secret_key = entry_secret_key.get()
        auth_method = combo_method.get()
        
        if not validate_tc_number(tc_number):
            messagebox.showerror("Error", "Invalid TC ID.")
            return
        
        if not username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return

        if not secret_key.isdigit():
            messagebox.showerror("Error", "Invalid secret key.")
            return
        
        hashed_tc = hash_string(tc_number)
        hashed_username = hash_string(username)

        cursor.execute('SELECT public_key, g, p FROM users WHERE hashed_tc = ?', (hashed_tc,))
        result = cursor.fetchone()

        if not result:
            messagebox.showerror("Error", "User not found.")
            return

        public_key, g, p = result
        public_key = int(public_key)
        g = int(g)
        p = int(p)
        secret_key = int(secret_key)

        if auth_method == 'Schnorr':
            # Perform Schnorr authentication
            r, commitment = schnorr_generate_commitment(p, g, p - 1)
            challenge = schnorr_generate_challenge()
            response = schnorr_generate_response(secret_key, r, challenge, p - 1)
            
            if schnorr_verify(public_key, response, challenge, commitment, p, g):
                messagebox.showinfo("Success", "Authentication successful!")
            else:
                messagebox.showerror("Error", "Authentication failed.")
        elif auth_method == 'ZkSNARK':
            # ZkSNARK Authentication
            statement = f"{hashed_tc}{hashed_username}"
            proof = zk_snark_prove(statement)
            
            if zk_snark_verify(proof, statement):
                messagebox.showinfo("Success", "ZkSNARK Authentication successful!")
            else:
                messagebox.showerror("Error", "ZkSNARK Authentication failed.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Helper functions to manage users and keys
def is_tc_registered(hashed_tc):
    cursor.execute('SELECT COUNT(*) FROM users WHERE hashed_tc = ?', (hashed_tc,))
    return cursor.fetchone()[0] > 0

def is_username_registered(hashed_username):
    cursor.execute('SELECT COUNT(*) FROM users WHERE hashed_username = ?', (hashed_username,))
    return cursor.fetchone()[0] > 0

def save_user(hashed_tc, hashed_username, public_key, g, p):
    cursor.execute('''
        INSERT INTO users (hashed_tc, hashed_username, public_key, g, p)
        VALUES (?, ?, ?, ?, ?)
    ''', (hashed_tc, hashed_username, public_key, g, p))
    conn.commit()


def on_closing():
    try:
        conn.close()
    except Exception as e:
        print(f"Error closing the database connection: {e}")
    app.destroy()

# GUI setup
app = tk.Tk()
app.title("Schnorr & ZkSNARK Authentication")

# Tab Control
tabControl = ttk.Notebook(app)
tab_register = ttk.Frame(tabControl)
tab_authenticate = ttk.Frame(tabControl)
tabControl.add(tab_register, text='Register')
tabControl.add(tab_authenticate, text='Authenticate')
tabControl.pack(expand=1, fill="both")

# Registration tab
tk.Label(tab_register, text="TC ID:").grid(row=0, column=0, padx=5, pady=5)
entry_register = tk.Entry(tab_register)
entry_register.grid(row=0, column=1, padx=5, pady=5)

tk.Label(tab_register, text="Username:").grid(row=1, column=0, padx=5, pady=5)
entry_username = tk.Entry(tab_register)
entry_username.grid(row=1, column=1, padx=5, pady=5)

tk.Button(tab_register, text="Register", command=register).grid(row=2, columnspan=2, pady=10)

key_display = scrolledtext.ScrolledText(tab_register, width=50, height=10, wrap=tk.WORD)
key_display.grid(row=3, columnspan=2, pady=10)

# Authentication tab
tk.Label(tab_authenticate, text="TC ID:").grid(row=0, column=0, padx=5, pady=5)
entry_auth = tk.Entry(tab_authenticate)
entry_auth.grid(row=0, column=1, padx=5, pady=5)

tk.Label(tab_authenticate, text="Username:").grid(row=1, column=0, padx=5, pady=5)
entry_auth_username = tk.Entry(tab_authenticate)
entry_auth_username.grid(row=1, column=1, padx=5, pady=5)

tk.Label(tab_authenticate, text="Secret Key:").grid(row=2, column=0, padx=5, pady=5)
entry_secret_key = tk.Entry(tab_authenticate)
entry_secret_key.grid(row=2, column=1, padx=5, pady=5)

tk.Label(tab_authenticate, text="Authentication Method:").grid(row=3, column=0, padx=5, pady=5)
combo_method = ttk.Combobox(tab_authenticate, values=["Schnorr", "ZkSNARK"])
combo_method.grid(row=3, column=1, padx=5, pady=5)
combo_method.current(0)  # Default to "Schnorr"

tk.Button(tab_authenticate, text="Authenticate", command=authenticate).grid(row=4, columnspan=2, pady=10)

app.protocol("WM_DELETE_WINDOW", on_closing)
app.mainloop()