##
# @file PAdES-app.py
#
# @brief Application for signing and verifying PDF files using RSA and AES.
# Includes GUI for selecting files and handling cryptographic operations.
#

import os
import tkinter as tk
from tkinter import messagebox, filedialog, StringVar
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

app_font = ("Arial", 12)
pdf_path: StringVar
private_key_path: StringVar
public_key_path: StringVar
pin: StringVar


##
# @brief Reads and returns the encrypted private key from the file.
#
# @return The content of the private key file as bytes, or None on failure.
#
def get_encrypted_private_key():
    try:
        with open(private_key_path.get(), "rb") as f:
            encrypted_private_key_with_iv: bytes = f.read()
    except Exception as e:
        messagebox.showerror("Private key not found", "There is no private key at the specified location")
        return None
    return encrypted_private_key_with_iv


##
# @brief Initializes the main application window and variables.
#
# @return The Tkinter window object.
#
def app_window_setup():
    app_window = tk.Tk()
    app_window.title("RSA Keys Generator")
    app_window.minsize(width=400, height=300)
    app_window.bind('<Escape>', lambda e: app_window.destroy())

    global pdf_path, private_key_path, pin, public_key_path
    pdf_path = tk.StringVar()
    private_key_path = tk.StringVar()
    pin = tk.StringVar()
    public_key_path = tk.StringVar()

    return app_window


##
# @brief Opens a file dialog for selecting a PDF file and saves the path.
#
def browse_pdf():
    global pdf_path
    path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if path:
        pdf_path.set(path)
    else:
        messagebox.showerror("No chosen file", "No file has been chosen")


##
# @brief Opens a file dialog for selecting the private key file (.bin) and saves the path.
#
def browse_private_key():
    global private_key_path
    path = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
    if path:
        private_key_path.set(path)
    else:
        messagebox.showerror("No chosen file", "No file has been chosen")


##
# @brief Loads and saves path to the private key from a predefined USB pendrive location.
#
def load_private_key_from_pendrive():
    global private_key_path
    pendrive_name = 'NO NAME'
    pendrive_private_key_name = 'key_private.bin'
    pendrive_path = f'/Volumes/{pendrive_name}'
    pendrive_private_key_path = pendrive_path + '/' + pendrive_private_key_name

    if os.path.exists(pendrive_path):
        if os.path.exists(pendrive_private_key_path):
            private_key_path.set(pendrive_private_key_path)
            messagebox.showinfo("Success", f"Loaded private key from: {pendrive_private_key_path}")
            return
        else:
            messagebox.showinfo("File on pendrive not found",
                                f"There is no file on the '{pendrive_name}' pendrive named '{pendrive_private_key_name}'")
            return
    else:
        messagebox.showerror("Pendrive not found", f"There is no pendrive named '{pendrive_name}'")
        return


##
# @brief Opens a file dialog for selecting the public key file (.pem) and saves the path.
#
def browse_public_key():
    global public_key_path
    path = filedialog.askopenfilename(filetypes=[("PEN files", "*.pem")])
    if path:
        public_key_path.set(path)
    else:
        messagebox.showerror("No chosen file", "No file has been chosen")


##
# @brief Decrypts the encrypted private key using the provided PIN.
#
# @return Decrypted private key in PEM format, or None on failure.
#
def decrypt_private_key():
    global private_key_path, pin
    pin_str: str = pin.get()
    encrypted_private_key_with_iv: bytes = get_encrypted_private_key()
    if encrypted_private_key_with_iv is None:
        return None

    iv = encrypted_private_key_with_iv[:16]
    encrypted_private_key = encrypted_private_key_with_iv[16:]

    pin_hash = hashes.Hash(hashes.SHA256())
    pin_hash.update(pin_str.encode())
    pin_aes_key = pin_hash.finalize()

    cipher = Cipher(algorithms.AES(pin_aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_private_key) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    private_key_pem = unpadder.update(decrypted_data) + unpadder.finalize()

    return private_key_pem


##
# @brief Signs the PDF file using the provided private RSA key.
#
# @param private_key A deserialized RSA private key object.
#
def sign_pdf(private_key):
    global pdf_path
    with open(pdf_path.get(), "rb") as f:
        content = f.read()

        pdf_hash = hashes.Hash(hashes.SHA256())
        pdf_hash.update(content)
        pdf_hash = pdf_hash.finalize()

        signature = private_key.sign(
            pdf_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.MGF1.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        output_path = pdf_path.get().replace(".pdf", "_signed.pdf")
        with open(output_path, "wb") as new_f:
            new_f.write(content)
            new_f.write(b"\n%%PAdES_SIGNATURE%%\n")
            new_f.write(signature)


##
# @brief Handles the Sign PDF button logic.
#
# Verifies input, decrypts the private key, and signs the PDF.
#
def sign_pdf_button():
    try:
        if not all([pdf_path.get(), private_key_path.get(), pin.get()]):
            messagebox.showerror("Error", "One or more fields empty")
            return
        
        for path in [pdf_path.get(), private_key_path.get(), pin.get()]:
            if not os.path.exists(path):
                messagebox.showerror("Error", "One or more fields refer to a path that no longer exists")
                return

        private_key_pem = decrypt_private_key()
        if private_key_pem is None:
            messagebox.showerror("Failure", "Couldn't sign the pdf")
            return
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        sign_pdf(private_key)
    except Exception as e:
        messagebox.showerror("PIN error", "Pin is incorrect")
        return
    messagebox.showinfo("Success", "Signed PDF successfully")


##
# @brief Extracts the original content and signature from a signed PDF.
#
# @return A tuple (content, signature) where both are in bytes.
#
def extract_content_and_signature():
    with open(pdf_path.get(), "rb") as f:
        pdf_data = f.read()

    marker = b"\n%%PAdES_SIGNATURE%%\n"
    if marker not in pdf_data:
        messagebox.showerror("PDF not signed", "The PDF you have chosen is not a signed PDF")

    parts = pdf_data.split(marker)
    content = parts[0]
    signature = parts[1]
    return content, signature


##
# @brief Verifies the PDF signature against the provided public key.
#
# @param content The original PDF content (without signature).
# @param signature The digital signature extracted from the PDF.
# @return True if verification succeeds, False otherwise.
#
def verify_pdf(content: bytes, signature: bytes) -> bool:
    global pdf_path, public_key_path
    try:
        if not all([pdf_path.get(), public_key_path.get()]):
            messagebox.showerror("Missing fields", "You did not select public key or pdf to verify")
            return False

        for path in [pdf_path.get(), public_key_path.get()]:
            if not os.path.exists(path):
                messagebox.showerror("Error", "One or more fields refer to a path that no longer exists")
                return False

        with open(public_key_path.get(), "rb") as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        pdf_hash = hashes.Hash(hashes.SHA256())
        pdf_hash.update(content)
        pdf_hash = pdf_hash.finalize()

        try:
            public_key.verify(
                signature,
                pdf_hash,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.MGF1.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            messagebox.showinfo("Verification success", "Signature has been verified with success")
            return True
        except Exception as e:
            messagebox.showinfo("Verification failure", f"The PDF signature does not match the public key ({str(e)})")
            return False

    except Exception as e:
        messagebox.showerror("Unknown error", f"Error while verifying: {str(e)}")
        return False


##
# @brief Handles the Verify PDF button logic.
#
# Extracts the content and verifies the signature.
#
def verify_pdf_button():
    global pdf_path
    content, signature = extract_content_and_signature()
    result = verify_pdf(content, signature)


##
# @brief Main function. Sets up the GUI and starts the Tkinter event loop.
#
def main():
    global pdf_path, private_key_path, pin, public_key_path
    app_window = app_window_setup()

    tk.Label(app_window, text="Choose pdf file:", font=app_font).grid(row=0, column=0, sticky="w", pady=5, padx=(5, 0))
    tk.Entry(app_window, textvariable=pdf_path, width=50, state="readonly").grid(row=0, column=1, padx=5)
    tk.Button(app_window, text="Browse", command=browse_pdf).grid(row=0, column=2)

    tk.Label(app_window, text="Choose private key (.bin):", font=app_font).grid(row=1, column=0, sticky="w", pady=5,
                                                                                padx=(5, 0))
    tk.Entry(app_window, textvariable=private_key_path, width=50, state="readonly").grid(row=1, column=1, padx=5)
    tk.Button(app_window, text="Browse", command=browse_private_key).grid(row=1, column=2)
    tk.Button(app_window, text="Load from pendrive", command=load_private_key_from_pendrive).grid(row=1, column=3)

    tk.Label(app_window, text="Choose public key (.pem):", font=app_font).grid(row=2, column=0, sticky="w", pady=5,
                                                                               padx=(5, 0))
    tk.Entry(app_window, textvariable=public_key_path, width=50, state="readonly").grid(row=2, column=1, padx=5)
    tk.Button(app_window, text="Browse", command=browse_public_key).grid(row=2, column=2)

    tk.Label(app_window, text="Enter a 6 digit PIN:", font=app_font).grid(row=3, column=0, sticky="w", pady=(5, 0),
                                                                          padx=(5, 0))
    tk.Entry(app_window, textvariable=pin, show="*").grid(row=4, column=0, sticky="w", pady=(0, 5), padx=(5, 0))

    tk.Button(app_window, text="Sign PDF", command=sign_pdf_button).grid(row=4, column=1, padx=(10, 0), pady=20)
    tk.Button(app_window, text="Verify PDF", command=verify_pdf_button).grid(row=4, column=2, padx=(0, 10), pady=20)

    app_window.mainloop()


##
# @brief Entry point for the script.
#
if __name__ == "__main__":
    main()
