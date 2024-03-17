import argparse
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from PIL import Image
import os
from stegano import lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox

def derive_aes_key(passphrase, key_length=32):
    """Derive an AES key from the passphrase."""
    return hashlib.sha256(passphrase.encode()).digest()[:key_length]

def aes_encrypt(data, key):
    """Encrypt data using AES encryption."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # IV is prepended to ciphertext

def one_time_pad_encrypt(message, key):
    """Encrypt message using a one-time pad (XOR)."""
    assert len(message) <= len(key), "Key must be at least as long as the message"
    return bytes([m ^ k for m, k in zip(message, key)])

def embed_data_into_image(data, image_path, output_image_path):
    """Embed data (hex string) into an image."""
    data_hex_str = data.hex()  # Convert binary data to hex string for embedding
    secret_image = lsb.hide(image_path, data_hex_str)
    secret_image.save(output_image_path)
    print(f"Data embedded into {output_image_path}.")

def send_email(subject, body, sender_email, receiver_email, password, attachment_filenames):
    """Send an email with attachments."""
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    for filename in attachment_filenames:
        with open(filename, 'rb') as attachment:
            part = MIMEApplication(attachment.read(), Name=os.path.basename(filename))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(filename)}"'
        msg.attach(part)

    with smtplib.SMTP('smtp-mail.outlook.com', 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, password)
        smtp.send_message(msg)
    print("Email sent with attachments.")

def gather_inputs_and_send():
    root = tk.Tk()
    root.withdraw()  # we don't want a full GUI, so keep the root window from appearing

    # Ask user for inputs
    sender_email = simpledialog.askstring("Input", "Enter your email to send from:", parent=root)
    password = simpledialog.askstring("Input", "Enter your email password to send from:", parent=root, show='*')
    receiver_email = simpledialog.askstring("Input", "Enter the recipients email:", parent=root)
    message = simpledialog.askstring("Input", "Enter your message:", parent=root)
    passphrase = simpledialog.askstring("Input", "Enter secret passphrase (make sure the reciever gets it):", parent=root)

    # File dialog for images
    key_image = filedialog.askopenfilename(title="Select key image", filetypes=(("png files", "*.png"), ("all files", "*.*")))
    message_image = filedialog.askopenfilename(title="Select message image", filetypes=(("png files", "*.png"), ("all files", "*.*")))

    # Ensure all fields are filled
    if not all([sender_email, password, receiver_email, message, passphrase, key_image, message_image]):
        messagebox.showerror("Error", "All fields must be filled!")
        return

    try:
        # Derive AES key from passphrase
        aes_key = derive_aes_key(passphrase)

        # Generate OTP key (same length as message) and encrypt message with OTP
        otp_key = os.urandom(len(message))
        encrypted_message = one_time_pad_encrypt(message.encode(), otp_key)

        # Encrypt OTP key with AES
        aes_encrypted_otp_key = aes_encrypt(otp_key, aes_key)

        # Embed AES-encrypted OTP key in pic1.png and OTP-encrypted message in pic2.png
        embed_data_into_image(aes_encrypted_otp_key, key_image, "pic1.png")
        embed_data_into_image(encrypted_message, message_image, "pic2.png")
        # Send email with embedded images
        email_subject = "Vacation Pics!"
        email_body = ""
        send_email(email_subject, email_body, sender_email, receiver_email, password, ["pic1.png", "pic2.png"])

        messagebox.showinfo("Success", "Message sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e)) 
   
if __name__ == "__main__":
    gather_inputs_and_send()
