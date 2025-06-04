from cryptography.fernet import Fernet
import os

# You may want to store the key securely (e.g., in a .env file or key vault)
# For simplicity, hardcoded here (NOT RECOMMENDED for production)
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    encrypted = cipher.encrypt(data)
    with open(path, 'wb') as f:
        f.write(encrypted)
    return path  # Same path and name

def decrypt_file(path):
    with open(path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    temp_path = path + '.dec'
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    return temp_path
