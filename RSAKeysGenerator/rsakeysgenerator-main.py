##
# @file RSAKeysGenerator.py
#
# @brief Application generating private and public keys by implementing RSA algorithm.
# Includes GUI for selecting Pin and keys' names.
#


import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

app_font = ("Arial", 12)


##
# @brief Generates an RSA key pair.
#
# @return A tuple containing the private key and public key both in PEM format.
#
def generate_keys() -> (bytes, bytes):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


##
# @brief Encrypts the private key using AES with a key derived from the user's PIN.
#
# @param private_key_pem The private key in PEM format as bytes.
# @param pin A 6-digit user-provided PIN string.
# @return The encrypted private key with prepended IV as bytes.
#
def encrypt_private_key(private_key_pem: bytes, pin: str):
    pin_hash = hashes.Hash(hashes.SHA256())
    pin_hash.update(pin.encode())
    pin_aes_key = pin_hash.finalize()

    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_private_key_pem = padder.update(private_key_pem) + padder.finalize()

    cipher = Cipher(algorithms.AES(pin_aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(padded_private_key_pem) + encryptor.finalize()
    return iv + encrypted_private_key


##
# @brief Saves the encrypted private key and the public key to disk.
#
# @param encrypted_private_key The encrypted private key with IV as bytes.
# @param public_key_pem The public key in PEM format.
# @param name The base filename (without extension) to save the key files.
# @return True if keys were successfully saved, False otherwise.
#
def save_keys(encrypted_private_key, public_key_pem, name) -> bool:
    try:
        with open(f"{name}_private.bin", "wb") as f:
            f.write(encrypted_private_key)

        with open(f"{name}_public.pem", "wb") as f:
            f.write(public_key_pem)
        return True
    except Exception as e:
        messagebox.showerror("Error saving keys", f"There has been an error while saving the keys: {str(e)}")
        return False


##
# @brief Handles the logic when the "Generate RSA Keys" button is clicked.
#
# Validates the user input and initiates the key generation and saving process.
#
# @param pin The 6-digit PIN entered by the user.
# @param name The base filename provided by the user.
#
def on_generate_button_click(pin: str, name: str):
    if not pin or not name:
        messagebox.showerror("Missing Entry Error", "PIN or file name can not be empty")
        return
    if not pin.isdigit():
        messagebox.showerror("PIN Digits Error", "PIN must not contain anything other than digits")
        return
    if len(pin) != 6:
        messagebox.showerror("PIN Length Error", "PIN must be 6 digits long")
        return

    private_key_pem, public_key_pem = generate_keys()
    encrypted_private_key = encrypt_private_key(private_key_pem, pin)
    is_saved = save_keys(encrypted_private_key, public_key_pem, name)

    if is_saved:
        messagebox.showinfo("Success", f"Keys {name}_private.bin and {name}_public.pem have been generated and saved correctly")


##
# @brief Sets up the main application window.
#
# Initializes the Tkinter GUI window and binds Escape key to close the app.
#
# @return The initialized Tkinter window instance.
#
def app_window_setup():
    app_window = tk.Tk()
    app_window.title("RSA Keys Generator")
    app_window.minsize(width=400, height=300)

    app_window.bind('<Escape>', lambda e: app_window.destroy())

    return app_window


##
# @brief Main function that launches the application.
#
# Builds the GUI layout and starts the Tkinter event loop.
#
def main():
    app_window = app_window_setup()

    tk.Label(app_window, text="Enter a 6 digit PIN:", font=app_font).pack(pady=(30, 5))
    pin_input = tk.Entry(app_window, show="*")
    pin_input.pack()

    tk.Label(app_window, text="Enter file name:", font=app_font).pack(pady=(50,5))
    name_input = tk.Entry(app_window)
    name_input.pack(pady=(0, 20))

    generate_button = tk.Button(
        app_window,
        text="Generate RSA Keys",
        command=lambda: on_generate_button_click(pin_input.get(), name_input.get())
    )
    generate_button.pack()

    app_window.mainloop()


##
# @brief Entry point for the script.
#
if __name__ == "__main__":
    main()
