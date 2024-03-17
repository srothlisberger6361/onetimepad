import tkinter as tk
from tkinter import filedialog, simpledialog
from stegano import lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def derive_aes_key(passphrase, key_length=32):
    """Derive an AES key from the passphrase."""
    return hashlib.sha256(passphrase.encode()).digest()[:key_length]

def aes_decrypt(data, key):
    """Decrypt data using AES encryption."""
    iv = data[:16]  # Extract the IV (first 16 bytes)
    ct = data[16:]  # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def extract_data_from_image(image_path):
    """Extract hex string data from an image and convert it to bytes."""
    data_hex_str = lsb.reveal(image_path)
    return bytes.fromhex(data_hex_str)

def one_time_pad_decrypt(encrypted_message, key):
    """Decrypt message using a one-time pad (XOR)."""
    return bytes([m ^ k for m, k in zip(encrypted_message, key)])

def gather_inputs_and_decrypt():
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    passphrase = simpledialog.askstring("Input", "Enter secret passphrase:", parent=root)
    if not passphrase:
        return  # Exit if no passphrase provided

    key_image_path = filedialog.askopenfilename(title="Select image 1", filetypes=(("PNG files", "*.png"), ("All files", "*.*")))
    if not key_image_path:
        return  # Exit if no file selected

    message_image_path = filedialog.askopenfilename(title="Select image 2", filetypes=(("PNG files", "*.png"), ("All files", "*.*")))
    if not message_image_path:
        return  # Exit if no file selected

    try:
        aes_key = derive_aes_key(passphrase)

        aes_encrypted_otp_key = extract_data_from_image(key_image_path)
        otp_key = aes_decrypt(aes_encrypted_otp_key, aes_key)

        encrypted_message = extract_data_from_image(message_image_path)
        decrypted_message = one_time_pad_decrypt(encrypted_message, otp_key)

        tk.messagebox.showinfo("Decrypted Message", f"Decrypted message: {decrypted_message.decode()}")
    except Exception as e:
        tk.messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    gather_inputs_and_decrypt()
