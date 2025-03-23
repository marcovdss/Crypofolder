How It Works:

Each file is encrypted with AES-256 in CBC mode.

A random IV (Initialization Vector) ensures unique encryption even if the same file is encrypted twice.

A random salt is used to derive the key from the password using PBKDF2.

The salt is stored in encryption_key.json inside the folder.

Encrypted files have the .enc extension.

Original files are deleted after encryption.

This is a basic implementation. If you're handling sensitive data, consider adding error handling, secure key storage, and metadata protection.