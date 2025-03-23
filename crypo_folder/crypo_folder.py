import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Function to derive a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(file_path: str, key: bytes):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Pad plaintext to be AES block size compatible
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Store encrypted file
    with open(file_path + ".enc", "wb") as f:
        f.write(iv + ciphertext)  # Prepend IV for decryption
    
    os.remove(file_path)  # Delete original file

# Function to decrypt a file
def decrypt_file(file_path: str, key: bytes):
    with open(file_path, "rb") as f:
        data = f.read()
    
    iv, ciphertext = data[:16], data[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    # Restore original file
    original_file_path = file_path[:-4]  # Remove ".enc"
    with open(original_file_path, "wb") as f:
        f.write(plaintext)
    
    os.remove(file_path)  # Delete encrypted file

# Function to encrypt all files in a folder
def encrypt_folder(folder_path: str, password: str):
    salt = os.urandom(16)  # Generate random salt
    key = derive_key(password, salt)

    with open(os.path.join(folder_path, "encryption_key.json"), "w") as f:
        f.write(json.dumps({"salt": base64.b64encode(salt).decode()}))

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and filename != "encryption_key.json":
            encrypt_file(file_path, key)
    
    print("Encryption complete!")

# Function to decrypt all files in a folder
def decrypt_folder(folder_path: str, password: str):
    key_file = os.path.join(folder_path, "encryption_key.json")
    
    if not os.path.exists(key_file):
        print("Error: Encryption key file missing!")
        return
    
    with open(key_file, "r") as f:
        data = json.load(f)
        salt = base64.b64decode(data["salt"])
    
    key = derive_key(password, salt)
    
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and filename.endswith(".enc"):
            decrypt_file(file_path, key)
    
    os.remove(key_file)  # Remove key file after decryption
    print("Decryption complete!")
    
# Example usage:
# encrypt_folder("your_folder_path", "your_password")
# decrypt_folder("your_folder_path", "your_password")
