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
    
    encrypted_path = path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)

    os.remove(path)  # remove original plaintext file
    return encrypted_path

def decrypt_file(encrypted_path):
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_path = encrypted_path.replace('.enc', '')
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_path

