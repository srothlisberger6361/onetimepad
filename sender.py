import argparse
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import random
from PIL import Image
import facebook

def post_to_facebook_page(access_token, page_id, message, image_path):
    graph = facebook.GraphAPI(access_token)
    with open(image_path, 'rb') as image_file:
        response = graph.put_photo(image=image_file, message=message)
    return response['post_id']

def generate_key(message_length):
    """Generate a one-time pad key."""
    key = [random.randint(0, 255) for _ in range(message_length)]
    return bytes(key)

def encrypt(message, key):
    """Encrypt the message using the one-time pad technique."""
    encrypted_message = bytearray()
    for m, k in zip(message, key):
        encrypted_message.append(m ^ k)  # XOR operation
    return encrypted_message

def save_to_file(data, filename):
    """Save data to a file."""
    with open(filename, 'wb') as file:
        file.write(data)

def embed_key_into_image(image_path, key_filename, output_image_path, region):
    # Open the image
    image = Image.open(image_path)

    # Open the key file and read its content
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()

    # Convert the key to bytes
    key_bytes = bytearray(key)

    # Embed the key into the specified region of the image
    for i, byte in enumerate(key_bytes):
        # Get the pixel value at the current position
        pixel = image.getpixel((region[0] + i % (region[2] - region[0]), region[1] + i // (region[2] - region[0])))

        # Modify the least significant bit of the pixel value to embed the key byte
        modified_pixel = tuple(pixel[:-1] + ((pixel[-1] & 0xFE) | (byte >> 7),))

        # Update the pixel value in the image
        image.putpixel((region[0] + i % (region[2] - region[0]), region[1] + i // (region[2] - region[0])), modified_pixel)

    # Save the modified image
    image.save(output_image_path)

    print("One-Time Pad Key embedded into the image.")

def send_email(subject, body, sender_email, receiver_email, password, attachment_filename):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    # Add attachment
    with open(attachment_filename, 'rb') as attachment:
        part = MIMEApplication(attachment.read(), Name=attachment_filename)
    part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
    msg.attach(part)

    with smtplib.SMTP('smtp-mail.outlook.com', 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, password)
        smtp.send_message(msg)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Encrypt a message, embed it in an image, post to Facebook, and send via email")
    parser.add_argument("-es", "--sender_email", help="Sender email address", required=True)
    parser.add_argument("-ps", "--sender_password", help="Sender email password", required=True)
    parser.add_argument("-er", "--receiver_email", help="Receiver email address", required=True)
    parser.add_argument("-m", "--message", help="Message to encrypt", required=True)
    parser.add_argument("-s", "--image", help="Image name to embed the one-time-pad in (in the current directory)", required=True)
    args = parser.parse_args()

    # Prompt the user to enter the message
    message = args.message.encode()
    
    # Generate one-time pad key and encrypt the message
    key = generate_key(len(message))
    encrypted_message = encrypt(message, key)
    
    # Save the key and encrypted message to files
    key_filename = "one_time_pad_key.bin"
    encrypted_filename = "encrypted_message.bin"
    save_to_file(key, key_filename)
    save_to_file(encrypted_message, encrypted_filename)
    print("\nGenerated One-Time Pad Key saved to:", key_filename)
    print("Encrypted Message saved to:", encrypted_filename)
    
    # Embed the one-time pad key into the image
    image_path = args.image
    output_image_path = "image_with_embedded_key.png"  # New image with embedded key
    region = (50, 50, 150, 150)  # Specify the region to embed the key
    embed_key_into_image(image_path, key_filename, output_image_path, region)
    print("One-Time Pad Key embedded into the image.")

    # Post to Facebook Page
    access_token = "your_facebook_access_token"
    page_id = "your_facebook_page_id"
    facebook_message = "Here is the one-time pad for encryption: [attach one-time-pad file or provide instructions]"
    
    # Post to Facebook and get the post ID
    post_id = post_to_facebook_page(access_token, page_id, facebook_message, output_image_path)
    
    # Send email with the encrypted message as attachment and post ID in the body
    email_subject = "Encrypted Message"
    email_body = f"Please find the encrypted message attached. Post ID: {post_id}"
    sender_email = args.sender_email
    receiver_email = args.receiver_email
    password = args.sender_password
    attachment_filename = encrypted_filename
    send_email(email_subject, email_body, sender_email, receiver_email, password, attachment_filename)
    print("Embedded picture posted to Facebook page.")

if __name__ == "__main__":
    main()
