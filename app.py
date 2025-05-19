import os
import random
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, flash, session, send_file
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# ===== Blockchain Implementation =====
class Blockchain:
    def __init__(self):
        self.chain = []
        # Create genesis block
        self.create_block(data="Genesis Block", previous_hash="0")

    def create_block(self, data, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'previous_hash': previous_hash,
        }
        block['hash'] = self.hash_block(block)
        self.chain.append(block)
        return block

    def hash_block(self, block):
        block_string = f"{block['index']}{block['timestamp']}{block['data']}{block['previous_hash']}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def last_block(self):
        return self.chain[-1]

# New blockchain validation function
def is_chain_valid(blockchain):
    chain = blockchain.chain
    for i in range(1, len(chain)):
        current = chain[i]
        previous = chain[i - 1]

        # Recompute the hash of the current block
        recalculated_hash = blockchain.hash_block({
            'index': current['index'],
            'timestamp': current['timestamp'],
            'data': current['data'],
            'previous_hash': current['previous_hash']
        })

        # Check if stored hash is valid
        if current['hash'] != recalculated_hash:
            return False, f"Block {current['index']} hash is invalid."

        # Check if previous_hash matches hash of previous block
        if current['previous_hash'] != previous['hash']:
            return False, f"Block {current['index']} previous_hash does not match hash of previous block."

    return True, "Blockchain is valid."

# ====================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Encryption key
key_file = 'encryption.key'
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
else:
    with open(key_file, 'rb') as f:
        key = f.read()
fernet = Fernet(key)

# DB setup
DB_FILE = 'users.db'

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        # Users table
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        # Uploads log table
        conn.execute('''CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
init_db()

# Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
mail = Mail(app)

def send_2fa_email(to_email, code):
    msg = Message("Your 2FA Code", sender=app.config['MAIL_USERNAME'], recipients=[to_email])
    msg.body = f"Your 2FA code is: {code}"
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Mail send error: {e}")

# Device check based on User-Agent header
def get_current_device():
    user_agent = request.headers.get('User-Agent', '')
    if 'Chrome' in user_agent:
        return 'chrome'
    elif 'Firefox' in user_agent:
        return 'firefox'
    elif 'PostmanRuntime' in user_agent:
        return 'postman'
    else:
        return 'unknown'

ALLOWED_DEVICES = ['chrome', 'firefox']

def device_check():
    current_device = get_current_device()
    return current_device in ALLOWED_DEVICES

def is_2fa_expired():
    timestamp_str = session.get('2fa_timestamp')
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str)
        return datetime.now() > (timestamp + timedelta(minutes=1))
    return True

# Initialize blockchain
blockchain = Blockchain()

@app.route('/')
def index():
    return redirect('/login')

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
                session['user_email'] = email
                code = str(random.randint(100000, 999999))
                session['2fa_code'] = code
                session['2fa_timestamp'] = datetime.now().isoformat()
                send_2fa_email(email, code)
                flash("2FA code sent to your email.")
                return redirect('/verify')
            else:
                flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect('/login')

@app.route('/verify', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form.get('code')
        if (code == session.get('2fa_code')
            and device_check()
            and not is_2fa_expired()):
            session['authenticated'] = True
            flash("2FA successful.")
            return redirect('/upload')
        flash("2FA failed or expired.")
        return redirect('/verify')
    return render_template('2fa_verify.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('user_id'):
        return redirect('/login')
    if not session.get('authenticated'):
        return redirect('/verify')

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

            # Log upload in DB
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO uploads (user_id, filename, timestamp) VALUES (?, ?, ?)",
                    (session['user_id'], filename, datetime.now().isoformat())
                )

            # Blockchain record
            file_hash = hashlib.sha256(encrypted_data).hexdigest()
            data = {
                'user': session['user_email'],
                'filename': filename,
                'timestamp': datetime.now().isoformat(),
                'file_hash': file_hash
            }
            blockchain.create_block(data=data, previous_hash=blockchain.last_block()['hash'])

            flash("File encrypted, saved, and logged on blockchain.")
            return redirect('/upload')
        flash("Invalid file format.")
    files = [f.replace("encrypted_", "") for f in os.listdir(UPLOAD_FOLDER) if f.startswith("encrypted_")]
    return render_template('upload.html', files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if not session.get('user_id'):
        return redirect('/login')
    if not session.get('authenticated') or is_2fa_expired():
        code = str(random.randint(100000, 999999))
        session['2fa_code'] = code
        session['2fa_timestamp'] = datetime.now().isoformat()

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.execute("SELECT email FROM users WHERE id=?", (session['user_id'],))
            row = cur.fetchone()
            if row:
                send_2fa_email(row[0], code)
        flash("2FA code sent again. Please verify.")
        return redirect('/verify')

    encrypted_path = os.path.join(UPLOAD_FOLDER, "encrypted_" + filename)
    decrypted_path = os.path.join(UPLOAD_FOLDER, "decrypted_" + filename)
    try:
        with open(encrypted_path, 'rb') as f:
            decrypted_data = fernet.decrypt(f.read())
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        return send_file(decrypted_path, as_attachment=True)
    except Exception as e:
        flash(f"Download error: {str(e)}")
        return redirect('/upload')

@app.route('/uploads_log')
def uploads_log():
    if not session.get('user_id'):
        return redirect('/login')
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute('''
            SELECT users.email, uploads.filename, uploads.timestamp
            FROM uploads
            JOIN users ON uploads.user_id = users.id
            ORDER BY uploads.timestamp DESC
        ''')
        logs = cur.fetchall()

    return render_template('uploads_log.html', logs=logs)

@app.route('/blockchain')
def show_blockchain():
    if not session.get('user_id'):
        return redirect('/login')
    # Just display the blockchain for demonstration
    return render_template('blockchain.html', chain=blockchain.chain)

# New route to validate blockchain integrity
@app.route('/validate_chain')
def validate_chain():
    if not session.get('user_id'):
        return redirect('/login')
    valid, message = is_chain_valid(blockchain)
    if valid:
        flash("✅ Blockchain is valid and untampered.")
    else:
        flash(f"❌ Blockchain tampering detected! {message}")
    return redirect('/blockchain')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
