import os
import hashlib
import sqlite3
import random
import re
from flask import Flask, request, render_template, redirect, url_for, session, send_file, flash
from werkzeug.utils import secure_filename
from encryption import encrypt_file, decrypt_file
from blockchain import Blockchain, Block
from database import init_db, get_user, add_user, log_upload, save_file_access, get_accessible_files, get_file_owner, delete_file_record
from flask_mail import Mail, Message
from flask import after_this_request
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, 'encrypted')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail = Mail(app)

blockchain = Blockchain()
init_db()

def check_password_strength(password):
    if len(password) < 8:
        return "weak"
    if re.search(r"\d", password) and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[^\w\s]", password):
        return "strong"
    elif re.search(r"\d", password) and re.search(r"[A-Za-z]", password):
        return "moderate"
    return "weak"

@app.route('/')
def index():
    if session.get('verified'):
        return redirect(url_for('upload'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password_raw = request.form['password']
        strength = check_password_strength(password_raw)
        if strength == "weak":
            flash("Password is too weak. Use at least 8 characters with uppercase, lowercase, numbers, and symbols.")
            return redirect(url_for('signup'))

        password = hashlib.sha256(password_raw.encode()).hexdigest()
        if get_user(email):
            flash('User already exists.')
            return redirect(url_for('signup'))
        add_user(email, password)
        flash('User registered successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        session.clear()
        return render_template('login.html')

    email = request.form['email'].strip().lower()
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()
    user = get_user(email)
    if user and user[2] == password:
        session['temp_email'] = email
        session['resend_count'] = 0
        code = str(random.randint(100000, 999999))
        session['2fa_code'] = code
        session['2fa_time'] = datetime.utcnow().isoformat()
        msg = Message('Your 2FA Code', sender='youremail@gmail.com', recipients=[email])
        msg.body = f'Your 2FA code is: {code}'
        mail.send(msg)
        return render_template('2fa_verify.html')
    flash('Invalid credentials')
    return render_template('login.html')

@app.route('/2fa', methods=['POST'])
def verify_2fa():
    entered = request.form['token']
    code_time = session.get('2fa_time')
    if not code_time:
        flash("2FA session expired. Please login again.")
        return redirect(url_for('login'))

    elapsed = datetime.utcnow() - datetime.fromisoformat(code_time)
    if elapsed > timedelta(minutes=2):
        flash("2FA code expired. Please login again.")
        return redirect(url_for('login'))

    if entered == session.get('2fa_code'):
        session['email'] = session.pop('temp_email')
        session['verified'] = True
        flash('Logged in successfully.')
        return redirect(url_for('upload'))
    flash('Invalid 2FA code')
    return render_template('2fa_verify.html')

@app.route('/resend_2fa', methods=['POST'])
def resend_2fa():
    if 'temp_email' not in session:
        flash("Session expired. Login again.")
        return redirect(url_for('login'))

    if session.get('resend_count', 0) >= 5:
        flash("2FA resend limit reached.")
        return redirect(url_for('login'))

    last_sent_time = session.get('2fa_time')
    if last_sent_time:
        elapsed = datetime.utcnow() - datetime.fromisoformat(last_sent_time)
        if elapsed < timedelta(minutes=2):
            flash(f"Please wait {120 - int(elapsed.total_seconds())} seconds before resending.")
            return render_template('2fa_verify.html')

    session['resend_count'] += 1
    new_code = str(random.randint(100000, 999999))
    session['2fa_code'] = new_code
    session['2fa_time'] = datetime.utcnow().isoformat()

    msg = Message('Your new 2FA Code', sender='youremail@gmail.com', recipients=[session['temp_email']])
    msg.body = f'Your new 2FA code is: {new_code}'
    mail.send(msg)
    flash("A new 2FA code has been sent to your email.")
    return render_template('2fa_verify.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('verified'):
        flash('Please login to access this page.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash("No file selected.")
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
        if not filename:
            flash("Invalid file selected.")
            return redirect(url_for('upload'))

        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        encrypted_path = encrypt_file(path)
        encrypted_filename = os.path.basename(encrypted_path)

        final_encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
        os.rename(encrypted_path, final_encrypted_path)

        email = session['email']
        file_id = log_upload(email, filename)

        shared_with = request.form.get('shared_with', '')
        shared_list = [e.strip().lower() for e in shared_with.split(',') if e.strip()]
        if email not in shared_list:
            shared_list.append(email)
        save_file_access(file_id, shared_list)

        block_data = f"{email} uploaded {encrypted_filename}"
        prev_hash = blockchain.chain[-1].hash if blockchain.chain else "0"
        new_block = Block(len(blockchain.chain), datetime.utcnow().isoformat(), block_data, prev_hash)
        blockchain.add_block(new_block)

        flash('Upload successful.')
        return redirect(url_for('upload'))

    return render_template('upload.html')

@app.route('/tamper/<filename>')
def tamper_file(filename):
    path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename + '.enc')
    try:
        with open(path, 'rb+') as f:
            data = bytearray(f.read())
            data[10] ^= 0xFF  # Flip one byte to simulate tampering
            f.seek(0)
            f.write(data)
        flash(f'{filename} has been tampered.')
    except Exception as e:
        flash(f'Error tampering file: {e}')
    return redirect(url_for('view_blockchain'))

@app.route('/blockchain')
def view_blockchain():
    if not session.get('verified'):
        flash('Please login to access this page.')
        return redirect(url_for('login'))

    email = session['email']
    with sqlite3.connect('site.db') as conn:
        uploader_emails = conn.execute("SELECT DISTINCT uploader_email FROM uploads").fetchall()
        uploader_emails = [u[0] for u in uploader_emails]

    if email not in uploader_emails:
        flash('Access denied. Only uploaders can view the blockchain.')
        return redirect(url_for('upload'))

    for block in blockchain.chain:
        block.tampered = blockchain.is_block_tampered(block)

    return render_template('blockchain.html', chain=blockchain.chain)

@app.route('/files')
def view_accessible_files():
    email = session.get('email')
    if not email:
        flash("Please login to access this page.")
        return redirect(url_for('login'))

    files = get_accessible_files(email)
    return render_template('accessible_files.html', files=files)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
