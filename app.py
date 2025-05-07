import os
import random
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, flash, session, send_file
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Use environment variable in production

# Configure upload folder
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

# Allowed devices
ALLOWED_DEVICES = ['device1', 'device2', 'device3']

def get_current_device():
    return 'device1'  # Replace with real device check

def device_check():
    return get_current_device() in ALLOWED_DEVICES

def is_2fa_expired():
    timestamp_str = session.get('2fa_timestamp')
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str)
        expiration_time = timestamp + timedelta(minutes=1)
        return datetime.now() > expiration_time
    return True

# Initialize user database
DB_FILE = 'users.db'
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
init_db()

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')  # Set in render.yaml
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')  # Set in render.yaml

mail = Mail(app)
print("Flask-Mail configured. Ready to send emails.")

# Function to send 2FA email
def send_2fa_email(to_email, code):
    sender_email = app.config.get('MAIL_USERNAME')
    if not sender_email:
        print("MAIL_USERNAME not set! Cannot send 2FA email.")
        flash("Internal error: Email not configured.")
        return

    msg = Message(
        subject="Your 2FA Code",
        sender=sender_email,
        recipients=[to_email]
    )
    msg.body = f"Your 2FA code is: {code}"

    try:
        mail.send(msg)
        print(f"2FA code sent to {to_email}. Code: {code}")  # Remove in production
    except Exception as e:
        print(f"Error sending email: {e}")
        flash("Failed to send 2FA code. Please try again.")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            flash("Account created. Please log in.")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Email already exists.")
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.execute("SELECT id, password FROM users WHERE email=?", (email,))
            row = cur.fetchone()
            if row and check_password_hash(row[1], password):
                session['user_id'] = row[0]
                flash("Logged in successfully.")
                return redirect('/')
            else:
                flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect('/login')

@app.route('/', methods=['GET', 'POST'])
def index():
    if not session.get('user_id'):
        if request.method == 'GET':
            flash('Login required for 2FA.')
        return redirect('/login')

    if request.method == 'POST':
        session['2fa_code'] = str(random.randint(100000, 999999))
        session['2fa_timestamp'] = datetime.now().isoformat()

        user_id = session['user_id']
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.execute("SELECT email FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
            if row:
                send_2fa_email(row[0], session['2fa_code'])

        return redirect('/verify')

    return render_template('2fa_start.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form.get('code')
        if code == session.get('2fa_code') and device_check() and not is_2fa_expired():
            session['authenticated'] = True
            flash("2FA verification successful.")
            return redirect('/upload')
        else:
            flash('2FA failed, expired, or device not recognized.')
            return redirect('/')
    return render_template('2fa_verify.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('user_id'):
        flash('Please log in to upload files.')
        return redirect('/login')
    if not session.get('authenticated'):
        flash('2FA verification required.')
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

    files = [f.replace("encrypted_", "") for f in os.listdir(UPLOAD_FOLDER) if f.startswith("encrypted_")]
    return render_template('upload.html', files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if not session.get('user_id'):
        flash('Please log in to download files.')
        return redirect('/login')
    if not session.get('authenticated'):
        flash('Please complete 2FA to access this file.')
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
