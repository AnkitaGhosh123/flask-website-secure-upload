from flask import Flask, render_template, request, redirect, flash, session, send_file
import os, random
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = 'your-secret-key'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Encryption key setup
key_file = 'encryption.key'
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
else:
    with open(key_file, 'rb') as f:
        key = f.read()
fernet = Fernet(key)

# Dummy allowed devices
ALLOWED_DEVICES = ['device1', 'device2', 'device3']

# Simulated current device
def get_current_device():
    return 'device1'  # Simulated. In real app, use device fingerprint or IP

def device_check():
    return get_current_device() in ALLOWED_DEVICES

# Simulate the 2FA logic with expiration
def is_2fa_expired():
    # Check if the 2FA code has expired (more than 2 minutes old)
    timestamp_str = session.get('2fa_timestamp')
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str)
        expiration_time = timestamp + timedelta(minutes=1)
        return datetime.now() > expiration_time
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        session['2fa_code'] = str(random.randint(100000, 999999))
        session['2fa_timestamp'] = datetime.now().isoformat()  # Store as ISO string
        print(f"Your 2FA code is: {session['2fa_code']}")
        return redirect('/verify')
    return render_template('2fa_start.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form.get('code')
        if code == session.get('2fa_code') and device_check():
            session['authenticated'] = True
            return redirect('/upload')
        else:
            flash('2FA failed or device not recognized.')
            return redirect('/')
    return render_template('2fa_verify.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('authenticated'):
        flash('Please complete 2FA first.')
        return redirect('/')

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file and uploaded_file.filename.endswith('.xlsx'):
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            encrypted_path = os.path.join(UPLOAD_FOLDER, "encrypted_" + filename)

            uploaded_file.save(filepath)
            with open(filepath, 'rb') as f:
                encrypted_data = fernet.encrypt(f.read())
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            os.remove(filepath)
            flash('Excel file uploaded and encrypted successfully!')
            return redirect('/upload')
        else:
            flash('Upload a valid .xlsx file.')
            return redirect('/upload')

    # Fetch the list of encrypted files for download
    files = [f.replace("encrypted_", "") for f in os.listdir(UPLOAD_FOLDER) if f.startswith("encrypted_")]
    return render_template('upload.html', files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if not session.get('authenticated'):
        flash('Please complete 2FA first.')
        return redirect('/')

    encrypted_path = os.path.join(UPLOAD_FOLDER, "encrypted_" + filename)
    decrypted_path = os.path.join(UPLOAD_FOLDER, "decrypted_" + filename)

    try:
        with open(encrypted_path, 'rb') as f:
            decrypted_data = fernet.decrypt(f.read())
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        return send_file(decrypted_path, as_attachment=True)
    except Exception as e:
        flash(f"Error decrypting file: {str(e)}")
        return redirect('/upload')

# ✅ REQUIRED: Add this to run the server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
