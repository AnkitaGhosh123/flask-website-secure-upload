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
            flash("Password is too weak.")
            return redirect(url_for('signup'))

        password = hashlib.sha256(password_raw.encode()).hexdigest()
        if get_user(email):
            flash('User already exists.')
            return redirect(url_for('signup'))
        add_user(email, password)
        flash('User registered successfully.')
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
        flash("2FA session expired.")
        return redirect(url_for('login'))

    elapsed = datetime.utcnow() - datetime.fromisoformat(code_time)
    if elapsed > timedelta(minutes=2):
        flash("2FA code expired.")
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
        flash("Session expired.")
        return redirect(url_for('login'))

    if session.get('resend_count', 0) >= 5:
        flash("2FA resend limit reached.")
        return redirect(url_for('login'))

    last_sent_time = session.get('2fa_time')
    if last_sent_time:
        elapsed = datetime.utcnow() - datetime.fromisoformat(last_sent_time)
        if elapsed < timedelta(minutes=2):
            flash(f"Please wait {120 - int(elapsed.total_seconds())} seconds.")
            return render_template('2fa_verify.html')

    session['resend_count'] += 1
    new_code = str(random.randint(100000, 999999))
    session['2fa_code'] = new_code
    session['2fa_time'] = datetime.utcnow().isoformat()

    msg = Message('New 2FA Code', sender='youremail@gmail.com', recipients=[session['temp_email']])
    msg.body = f'Your new 2FA code is: {new_code}'
    mail.send(msg)
    flash("New 2FA code sent.")
    return render_template('2fa_verify.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('verified'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash("No file selected.")
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
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

        flash('File uploaded and encrypted.')
        return redirect(url_for('upload'))

    return render_template('upload.html')

@app.route('/files')
def view_accessible_files():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    files = []
    with sqlite3.connect('site.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT u.filename, u.uploader_email, u.filename || '.enc', u.id
        FROM uploads u
        JOIN file_access f ON u.id = f.file_id
        WHERE f.user_email = ?
        """, (email,))
        results = cursor.fetchall()
        for filename, uploader_email, stored_filename, _ in results:
            files.append((filename, stored_filename, uploader_email))
    return render_template('accessible_files.html', files=files, user=email)

@app.route('/download/<filename>')
def download(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    user = session['email']
    accessible_files = get_accessible_files(user)
    allowed_filenames = [f[1].replace('.enc', '') for f in accessible_files]

    if filename not in allowed_filenames:
        flash("Access denied.")
        return redirect(url_for('view_accessible_files'))

    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename + '.enc')
    if not os.path.exists(encrypted_path):
        flash("File not found.")
        return redirect(url_for('view_accessible_files'))

    decrypted_path = decrypt_file(encrypted_path)

    if not os.path.exists(decrypted_path):
        flash("Decryption failed.")
        return redirect(url_for('view_accessible_files'))

    return send_file(decrypted_path, as_attachment=True)

@app.route('/delete/<filename>')
def delete(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    email = session['email']
    original_filename = filename.replace('.enc', '')
    owner = get_file_owner(original_filename)  # Fix here

    if email != owner:
        flash("You don't have permission to delete this file.")
        return redirect(url_for('view_accessible_files'))

    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
        delete_file_record(original_filename)  # Fix here
        flash('File deleted successfully.')
    else:
        flash('File not found.')

    return redirect(url_for('view_accessible_files'))

@app.route('/upload_log')
def upload_log():
    if not session.get('verified'):
        return redirect(url_for('login'))

    email = session['email']
    with sqlite3.connect('site.db') as conn:
        uploads = conn.execute("""
            SELECT id, filename, uploader_email, timestamp
            FROM uploads
            WHERE uploader_email = ?
            ORDER BY timestamp DESC
        """, (email,)).fetchall()

    return render_template('uploads_log.html', uploads=uploads)

@app.route('/blockchain')
def view_blockchain():
    if not session.get('verified'):
        return redirect(url_for('login'))

    email = session['email']
    with sqlite3.connect('site.db') as conn:
        uploader_emails = conn.execute("SELECT DISTINCT uploader_email FROM uploads").fetchall()
        uploader_emails = [u[0] for u in uploader_emails]

    if email not in uploader_emails:
        flash('Access denied.')
        return redirect(url_for('upload'))

    return render_template('blockchain.html', chain=blockchain.chain)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
