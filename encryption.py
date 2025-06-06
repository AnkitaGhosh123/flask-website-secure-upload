from cryptography.fernet import Fernet
import os

KEY_FILE = 'secret.key'

# Ensure key exists and load it
def load_encryption_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

key = load_encryption_key()
cipher = Fernet(key)

def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    encrypted = cipher.encrypt(data)

    # Ensure 'encrypted/' folder exists
    encrypted_folder = 'encrypted'
    os.makedirs(encrypted_folder, exist_ok=True)

    encrypted_filename = os.path.basename(path) + '.enc'
    encrypted_path = os.path.join(encrypted_folder, encrypted_filename)

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)

    os.remove(path)  # remove the original file
    return encrypted_path

def decrypt_file(encrypted_path):
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_filename = os.path.basename(encrypted_path).replace('.enc', '')
    decrypted_path = os.path.join('decrypted_temp', decrypted_filename)

    os.makedirs('decrypted_temp', exist_ok=True)
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_path
