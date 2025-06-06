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
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password_raw = request.form['password']
        strength = check_password_strength(password_raw)
        if strength == "weak":
            flash("Password is too weak. Use at least 8 characters with uppercase, lowercase, numbers, and symbols.")
            return redirect(url_for('signup'))

        password = hashlib.sha256(password_raw.encode()).hexdigest()
        if get_user(email):
            flash('User already exists')
            return redirect(url_for('signup'))
        add_user(email, password)
        flash('User registered.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
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
        return redirect(url_for('upload'))
    flash('Invalid 2FA code')
    return render_template('2fa_verify.html')

@app.route('/resend_2fa', methods=['POST'])
def resend_2fa():
    if 'temp_email' not in session or session.get('resend_count', 0) >= 5:
        flash("You can't resend the 2FA code anymore.")
        return redirect(url_for('login'))

    session['resend_count'] += 1
    code = str(random.randint(100000, 999999))
    session['2fa_code'] = code
    session['2fa_time'] = datetime.utcnow().isoformat()

    msg = Message('Your new 2FA Code', sender='youremail@gmail.com', recipients=[session['temp_email']])
    msg.body = f'Your new 2FA code is: {code}'
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
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)

        if not filename:
            flash("Invalid file selected.")
            return redirect(url_for('upload'))

        # Save file using absolute path from config
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        encrypted_path = encrypt_file(path)
        encrypted_filename = os.path.basename(encrypted_path)

        email = session['email']
        file_id = log_upload(email, filename)

        shared_with = request.form.get('shared_with', '')
        shared_list = [e.strip() for e in shared_with.split(',') if e.strip()]
        if email not in shared_list:
            shared_list.append(email)
        save_file_access(file_id, shared_list)

        block_data = f"{email} uploaded {encrypted_filename}"
        prev_hash = blockchain.chain[-1].hash if blockchain.chain else "0"
        new_block = Block(len(blockchain.chain), datetime.utcnow().isoformat(), block_data, prev_hash)
        blockchain.add_block(new_block)

        flash('Upload successful.')

    return render_template('upload.html')

@app.route('/files')
def view_accessible_files():
    if not session.get('verified'):
        return redirect(url_for('login'))

    email = session['email']
    files_raw = get_accessible_files(email)
    files = [(f[0].replace('.enc', ''), f[0], f[1]) for f in files_raw]
        return render_template(
        'accessible_files.html',
        files=files,
        user=email
    )

@app.route('/blockchain')
def view_blockchain():
    chain = blockchain.chain
  # returns list of Block objects or dicts with prev_hash
    return render_template('blockchain.html', chain=chain)

@app.route('/download/<filename>')
def download(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    files = get_accessible_files(session['email'])
    accessible_filenames = [f[0].replace('.enc', '') for f in files]
    if filename not in accessible_filenames:
        flash('Access denied.')
        return redirect(url_for('view_accessible_files'))

    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if not os.path.exists(encrypted_path):
        flash('Encrypted file not found.')
        return redirect(url_for('view_accessible_files'))

    decrypted_path = decrypt_file(encrypted_path)

    @after_this_request
    def cleanup(response):
        try:
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
        except Exception as e:
            print(f"Cleanup error: {e}")
        return response

    return send_file(decrypted_path, as_attachment=True)

@app.route('/delete/<filename>')
def delete(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    owner = get_file_owner(filename)
    if owner != session['email']:
        flash('Unauthorized to delete this file.')
        return redirect(url_for('view_accessible_files'))

    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if os.path.exists(encrypted_path):
        try:
            os.remove(encrypted_path)
        except Exception as e:
            flash(f"Failed to delete file: {e}")
            return redirect(url_for('view_accessible_files'))
    else:
        flash("File not found on server.")

    delete_file_record(filename)
    flash('File successfully deleted.')
    return redirect(url_for('view_accessible_files'))

@app.route('/uploads')
def uploads():
    if not session.get('verified'):
        return redirect(url_for('login'))
    with sqlite3.connect('site.db') as conn:
        logs = conn.execute("SELECT * FROM uploads").fetchall()
    return render_template('uploads_log.html', logs=logs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
