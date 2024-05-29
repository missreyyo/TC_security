import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
import hashlib
import secrets
from sympy import primefactors

# Önceden tanımlanmış bir prime sayısı
prime = 101

def hash_tc(tc_number):
    # TC kimlik numarasını hashleme işlemi
    hashed_tc = hashlib.sha256(tc_number.encode()).hexdigest()
    return hashed_tc

def generate_random_number():
    # Rastgele bir sayı üretme işlemi
    random_number = secrets.randbelow(prime)  # 0 ile prime arasında rastgele bir sayı seç
    return random_number

def register():
    # Kullanıcının kayıt olma işlemi
    tc_number = entry_register.get()
    hashed_key = hash_tc(tc_number)
    
    if is_key_registered(hashed_key):
        messagebox.showerror("Error", "This TC ID is already registered.")
        return
    
    random_number = generate_random_number()
    save_key_and_random_number(hashed_key, random_number)
    key_display.delete(1.0, tk.END)
    key_display.insert(tk.END, f"Hashed TC ID: {hashed_key}\n")
    key_display.insert(tk.END, f"Random Number: {random_number}\n")
    messagebox.showinfo("Success", f"Registration successful! Your hashed TC ID and random number ({random_number}) are displayed below.")

def authenticate():
    # Kullanıcının doğrulama işlemi
    hashed_key = entry_auth.get()
    prime_factors_input = entry_prime_factors.get().split(",")
    prime_factors_input = [int(factor.strip()) for factor in prime_factors_input]
    
    if check_key_and_prime_factors(hashed_key, prime_factors_input):
        messagebox.showinfo("Success", "Authentication successful!")
    else:
        messagebox.showerror("Error", "Invalid key or prime factors!")

def save_key_and_random_number(key, random_number):
    # Kimlik hash'ini ve rastgele sayıyı yerel olarak kaydetme işlemi
    with open("data.txt", "a") as file:
        file.write(f"{key}::{random_number}\n")

def is_key_registered(key):
    # Anahtarın zaten kayıtlı olup olmadığını kontrol etme işlemi
    with open("data.txt", "r") as file:
        saved_data = file.readlines()
        saved_keys = [line.strip().split("::")[0] for line in saved_data]
    return key in saved_keys

def check_key_and_prime_factors(key, prime_factors_input):
    # Anahtarın ve asal çarpanlarının doğruluğunu kontrol etme işlemi
    with open("data.txt", "r") as file:
        saved_data = file.readlines()
        saved_data = [line.strip().split("::") for line in saved_data]
    
    for saved_key, saved_random_number in saved_data:
        saved_random_number = int(saved_random_number)
        if saved_key == key and set(prime_factors_input) == set(primefactors(saved_random_number)):
            return True
    return False

# GUI
root = tk.Tk()
root.title("Two-Factor Authentication System")

# Notebook widget'ı oluşturma
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Register sekmesi
frame_register = tk.Frame(notebook)
notebook.add(frame_register, text="Register")

label_register = tk.Label(frame_register, text="Enter your TC ID:")
label_register.pack()

entry_register = tk.Entry(frame_register)
entry_register.pack()

register_button = tk.Button(frame_register, text="Register", command=register)
register_button.pack()

key_display = scrolledtext.ScrolledText(frame_register, width=50, height=5, wrap=tk.WORD)
key_display.pack()

# Authenticate sekmesi
frame_authenticate = tk.Frame(notebook)
notebook.add(frame_authenticate, text="Authenticate")

label_auth = tk.Label(frame_authenticate, text="Enter your hashed TC ID:")
label_auth.pack()

entry_auth = tk.Entry(frame_authenticate)
entry_auth.pack()

label_prime_factors = tk.Label(frame_authenticate, text="Enter the prime factors of the random number (comma-separated):")
label_prime_factors.pack()

entry_prime_factors = tk.Entry(frame_authenticate)
entry_prime_factors.pack()

authenticate_button = tk.Button(frame_authenticate, text="Authenticate", command=authenticate)
authenticate_button.pack()

root.mainloop()
