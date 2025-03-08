import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def generate_key(password: str, salt: bytes):
    """
    Generates a 256-bit AES encryption key from a user-provided password.
    The salt ensures each encryption is unique, even with the same password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, output_file: str, password: str):
    """
    Encrypts a file using AES-256 encryption.
    - Generates a unique salt and IV for each encryption.
    - Uses CBC mode for strong security.
    """
    salt = os.urandom(16)  # Random salt for key derivation
    key = generate_key(password, salt)  # Derive a strong key from password
    iv = os.urandom(16)  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Padding to make data size a multiple of 16 bytes (AES block size)
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length
    
    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Save salt, IV, and ciphertext in the output file
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    messagebox.showinfo("Success", f"File encrypted: {output_file}")

def decrypt_file(input_file: str, output_file: str, password: str):
    """
    Decrypts a file encrypted with AES-256.
    - Extracts salt, IV, and encrypted data.
    - Derives the key from the password and salt.
    - Decrypts and removes padding.
    """
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Extract salt, IV, and ciphertext
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = generate_key(password, salt)  # Recreate the key using stored salt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    
    # Save decrypted content
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    messagebox.showinfo("Success", f"File decrypted: {output_file}")

def browse_file(entry):
    """Opens a file dialog to let the user choose a file and inserts the path in the entry field."""
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def encrypt_action():
    """Handles the encrypt button click event, ensuring all fields are filled before encrypting."""
    input_file = input_entry.get()
    output_file = output_entry.get()
    password = password_entry.get()
    if input_file and output_file and password:
        encrypt_file(input_file, output_file, password)
    else:
        messagebox.showerror("Error", "Please fill all fields")

def decrypt_action():
    """Handles the decrypt button click event, ensuring all fields are filled before decrypting."""
    input_file = input_entry.get()
    output_file = output_entry.get()
    password = password_entry.get()
    if input_file and output_file and password:
        decrypt_file(input_file, output_file, password)
    else:
        messagebox.showerror("Error", "Please fill all fields")

# Setting up the graphical user interface
app = tk.Tk()
app.title("Advanced Encryption Tool")
app.geometry("400x300")

tk.Label(app, text="Input File").pack()
input_entry = tk.Entry(app, width=40)
input_entry.pack()
tk.Button(app, text="Browse", command=lambda: browse_file(input_entry)).pack()

tk.Label(app, text="Output File").pack()
output_entry = tk.Entry(app, width=40)
output_entry.pack()

tk.Label(app, text="Password").pack()
password_entry = tk.Entry(app, show="*", width=40)
password_entry.pack()

tk.Button(app, text="Encrypt", command=encrypt_action).pack(pady=5)
tk.Button(app, text="Decrypt", command=decrypt_action).pack(pady=5)

# Run the Tkinter application loop
app.mainloop()
