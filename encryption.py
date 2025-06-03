from cryptography.fernet import Fernet
import os

key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    encrypted = cipher.encrypt(data)
    encrypted_path = path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)
    return encrypted_path

def decrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    decrypted = cipher.decrypt(data)
    decrypted_path = path.replace('.enc', '')
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)
    return decrypted_path
