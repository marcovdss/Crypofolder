import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Function to derive a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=200000,  # Increased iterations for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data using AES-GCM
def encrypt_data(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(12)  # AES-GCM recommended IV size is 12 bytes
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # Store IV and tag for authentication

# Function to decrypt data using AES-GCM
def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to encrypt a file
def encrypt_file(file_path: str, key: bytes):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    encrypted_data = encrypt_data(plaintext, key)

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    
    os.remove(file_path)  # Remove original file **after successful encryption**

# Function to decrypt a file
def decrypt_file(file_path: str, key: bytes):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        plaintext = decrypt_data(encrypted_data, key)
    except Exception:
        print(f"Error: Decryption failed for {file_path}. Possible tampering detected.")
        return
    
    original_file_path = file_path[:-4]  # Remove ".enc"
    with open(original_file_path, "wb") as f:
        f.write(plaintext)
    
    os.remove(file_path)  # Remove encrypted file **after successful decryption**

# Function to encrypt all files in a folder
def encrypt_folder(folder_path: str, password: str):
    salt = os.urandom(32)  # Increased salt size to 32 bytes
    key = derive_key(password, salt)

    key_file = os.path.join(folder_path, "encryption_key.json")

    with open(key_file, "w") as f:
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
