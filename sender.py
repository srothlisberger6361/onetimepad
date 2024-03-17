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

def main():
    parser = argparse.ArgumentParser(description="Encrypt data, embed it in images, and send via email")
    parser.add_argument("-es", "--sender_email", required=True)
    parser.add_argument("-ps", "--sender_password", required=True)
    parser.add_argument("-er", "--receiver_email", required=True)
    parser.add_argument("-m", "--message", required=True)
    parser.add_argument("-p", "--passphrase", required=True, help="Passphrase for AES key derivation")
    parser.add_argument("-ki", "--key_image", required=True, help="Image for embedding the AES-encrypted OTP key")
    parser.add_argument("-mi", "--message_image", required=True, help="Image for embedding the OTP encrypted message")
    args = parser.parse_args()

    # Derive AES key from passphrase
    aes_key = derive_aes_key(args.passphrase)

    # Generate OTP key (same length as message) and encrypt message with OTP
    otp_key = os.urandom(len(args.message))
    encrypted_message = one_time_pad_encrypt(args.message.encode(), otp_key)

    # Encrypt OTP key with AES
    aes_encrypted_otp_key = aes_encrypt(otp_key, aes_key)

    # Embed AES-encrypted OTP key in pic1.png and OTP-encrypted message in pic2.png
    embed_data_into_image(aes_encrypted_otp_key, args.key_image, "pic1.png")
    embed_data_into_image(encrypted_message, args.message_image, "pic2.png")
    
    # Send email with embedded images
    email_subject = "Vacation Pics!"
    email_body = ""
    send_email(email_subject, email_body, args.sender_email, args.receiver_email, args.sender_password, ["pic1.png", "pic2.png"])

if __name__ == "__main__":
    main()
