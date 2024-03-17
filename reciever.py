import argparse
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

def main():
    parser = argparse.ArgumentParser(description="Decrypt and extract message from images")
    parser.add_argument("-p", "--passphrase", required=True, help="Passphrase for AES key derivation")
    parser.add_argument("-ki", "--key_image", default="pic1.png", help="Image with the AES-encrypted OTP key")
    parser.add_argument("-mi", "--message_image", default="pic2.png", help="Image with the OTP encrypted message")
    args = parser.parse_args()

    # Derive AES key from the passphrase
    aes_key = derive_aes_key(args.passphrase)

    # Extract and decrypt the OTP key from the image
    aes_encrypted_otp_key = extract_data_from_image(args.key_image)
    otp_key = aes_decrypt(aes_encrypted_otp_key, aes_key)

    # Extract the encrypted message and decrypt it using the OTP key
    encrypted_message = extract_data_from_image(args.message_image)
    decrypted_message = one_time_pad_decrypt(encrypted_message, otp_key)

    print(f"Decrypted message: {decrypted_message.decode()}")

if __name__ == "__main__":
    main()


