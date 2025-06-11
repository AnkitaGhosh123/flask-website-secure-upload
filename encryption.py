from cryptography.fernet import Fernet
import os

KEY_FILE = 'secret.key'

# Ensure encryption key exists or create one
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
    # Read the original file
    with open(path, 'rb') as f:
        data = f.read()
    
    # Encrypt data
    encrypted = cipher.encrypt(data)

    # Ensure the 'encrypted/' folder exists
    encrypted_folder = 'encrypted'
    os.makedirs(encrypted_folder, exist_ok=True)

    # Generate encrypted filename
    encrypted_filename = os.path.basename(path) + '.enc'
    encrypted_path = os.path.join(encrypted_folder, encrypted_filename)

    # Save the encrypted file
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)

    # Remove the original file to keep data secure
    os.remove(path)
    
    return encrypted_path

def decrypt_file(encrypted_path):
    # Read the encrypted file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Define decrypted file path
    decrypted_filename = os.path.basename(encrypted_path).replace('.enc', '')
    decrypted_folder = 'decrypted_temp'
    os.makedirs(decrypted_folder, exist_ok=True)
    decrypted_path = os.path.join(decrypted_folder, decrypted_filename)

    # Save the decrypted file
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_path
