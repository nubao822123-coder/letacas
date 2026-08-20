import os
from cryptography.fernet import Fernet

def generate_and_save_key(filename="secret.key"):
    """Generates a secure key and saves it to a file."""
    key = Fernet.generate_key()

    if os.path.exists(filename):
        print(f"Key file {filename} already exists. not chenerating key")
    else:
        with open(filename, "wb") as key_file:
            key_file.write(key)
            print(f"Key successfully saved to {filename}")
   
def load_key(filename="secret.key"):
    return open(filename, "rb").read()
    
def encrypt_message(message) -> bytes:
    """Encrypts a plain text string or bytes."""
    key = load_key()
    f = Fernet(key)
    # Convert string to bytes before encryption if necessary
    if isinstance(message, str):
        encoded_message = message.encode()
    else:
        encoded_message = message
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message
def decrypt_message(encrypted_message: bytes) -> str:
    """Decrypts a ciphered byte string back to plain text."""
    key = load_key()
    f = Fernet(key)
    decrypted_bytes = f.decrypt(encrypted_message)
    # Convert bytes back to string
    return decrypted_bytes.decode()

