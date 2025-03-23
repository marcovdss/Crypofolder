# 🔒 Crypofolder - Folder Encryption System

## Overview
This project provides a **secure AES-256 encryption system** to protect all files inside a folder. It encrypts and decrypts files using a password, ensuring privacy and security.

## Features
✅ AES-256 encryption (CBC mode) for strong security  
✅ Automatically generates a **random IV** for each file  
✅ Uses **PBKDF2 key derivation** with a salt for enhanced protection  
✅ Deletes the original files after encryption  
✅ Stores encryption metadata securely in `encryption_key.json`  
✅ Decrypts files back to their original state  

## Installation
### 1. Install Dependencies
Make sure you have Python installed, then install the required library:
```bash
pip install cryptography
```

### 2. Clone This Repository
```bash
git clone https://github.com/marcovdss/crypofolder.git
cd crypofolder
```

## Usage
### Encrypt a Folder
Run the following command to encrypt all files in a folder:
```python
from crypofolder import encrypt_folder
encrypt_folder("/path/to/folder", "YourStrongPassword")
```
This will:
- Encrypt all files in the specified folder
- Remove the original files
- Save encryption metadata in `encryption_key.json`

### Decrypt a Folder
To restore the original files, run:
```python
from crypofolder import decrypt_folder
decrypt_folder("/path/to/folder", "YourStrongPassword")
```
This will:
- Decrypt all `.enc` files
- Restore the original files
- Delete `encryption_key.json` after decryption

## How It Works
1. A **random salt** is generated for key derivation (PBKDF2 with SHA-256)
2. A **32-byte AES key** is derived from the password
3. Each file is encrypted using **AES-256 in CBC mode** with a **random IV**
4. The encrypted file is stored with an `.enc` extension
5. Original files are **deleted** for security

## Security Considerations
- **Do not lose your password!** The files **cannot** be decrypted without it.
- The encryption key is derived using **PBKDF2** for extra protection.
- The `encryption_key.json` stores only the salt (not the password or key), making brute-force attacks difficult.
- Consider storing encrypted backups in a safe location.

## License
This project is licensed under the **MIT License**.

## Author
👤 **Your Name**  
🔗 [Your GitHub](https://github.com/yourusername)  
📧 YourEmail@example.com

