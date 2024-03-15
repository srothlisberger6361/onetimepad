import argparse
import requests
from stegano import lsb

def download_image_from_facebook(access_token, post_id, image_name):
    graph = facebook.GraphAPI(access_token)
    post = graph.get_object(post_id, fields='full_picture')
    image_url = post['full_picture']

    response = requests.get(image_url)
    with open(image_name, 'wb') as image_file:
        image_file.write(response.content)

    print("Image downloaded successfully.")

def extract_file_from_image(image_with_embedded_file, output_filename):
    # Hardcoded region coordinates
    region = (100, 100, 200, 200)  # (x, y, width, height)

    # Extract file from image using LSB steganography
    extracted_file = lsb.reveal(image_with_embedded_file, region=region)
    with open(output_filename, 'wb') as file:
        file.write(extracted_file)

    print("File extracted successfully from the image.")

def decrypt_message(encrypted_filename, key_filename, output_filename):
    with open(encrypted_filename, 'rb') as encrypted_file, \
         open(key_filename, 'rb') as key_file, \
         open(output_filename, 'wb') as decrypted_file:
        
        encrypted_data = encrypted_file.read()
        key = key_file.read()

        decrypted_message = bytearray()
        for m, k in zip(encrypted_data, key):
            decrypted_message.append(m ^ k)  # XOR operation
        
        decrypted_file.write(decrypted_message)

    print("Message decrypted successfully.")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Download image from Facebook, extract file, and decrypt message")
    parser.add_argument("-p", "--post_id", help="Post ID on Facebook", required=True)
    parser.add_argument("-i", "--image_name", help="Image name (with extension)", required=True)
    args = parser.parse_args()

    access_token = "your_facebook_access_token"
    post_id = args.post_id
    image_name = args.image_name
    output_filename = "extracted_file.bin"
    encrypted_filename = "encrypted_message.bin"
    key_filename = "one_time_pad_key.bin"
    decrypted_output_filename = "decrypted_message.txt"

    download_image_from_facebook(access_token, post_id, image_name)
    extract_file_from_image(image_name, output_filename)
    decrypt_message(encrypted_filename, key_filename, decrypted_output_filename)

    print("Extraction and decryption complete.")

if __name__ == "__main__":
    main()
