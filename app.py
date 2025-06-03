import os
import hashlib
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, send_file, flash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from encryption import encrypt_file, decrypt_file
from blockchain import Blockchain, Block
from database import init_db, get_user, add_user, log_upload

from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Email config (configure with real credentials in production)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

blockchain = Blockchain()
init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        if get_user(email):
            flash('User already exists')
            return redirect(url_for('signup'))
        add_user(email, password)
        flash('User registered. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        user = get_user(email)
        if user and user[2] == password:
            session['email'] = email
            token = s.dumps(email, salt='2fa-salt')
            msg = Message('Your 2FA Code', sender='youremail@gmail.com', recipients=[email])
            msg.body = f'Your 2FA code is: {token}'
            mail.send(msg)
            return render_template('2fa_verify.html', token=token)
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/2fa', methods=['POST'])
def verify_2fa():
    entered_token = request.form['token']
    try:
        email = s.loads(entered_token, salt='2fa-salt', max_age=300)
        session['verified'] = True
        return redirect(url_for('upload'))
    except:
        flash('2FA verification failed.')
        return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('verified'):
        flash('Login required for file upload.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        f = request.files['file']
        filename = secure_filename(f.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(filepath)
        encrypted_path = encrypt_file(filepath)
        os.remove(filepath)
        block_data = f"{session['email']} uploaded {filename}"
        new_block = Block(len(blockchain.chain), block_data, blockchain.chain[-1].hash)
        blockchain.add_block(new_block)
        log_upload(session['email'], filename)
        flash('File uploaded and encrypted successfully.')
    return render_template('upload.html')

@app.route('/download/<filename>')
def download(filename):
    if not session.get('verified'):
        flash('Login required to download files.')
        return redirect(url_for('login'))
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    decrypted_path = decrypt_file(encrypted_path)
    return send_file(decrypted_path, as_attachment=True)

@app.route('/blockchain')
def view_blockchain():
    return render_template('blockchain.html', chain=blockchain.chain)

@app.route('/uploads')
def uploads():
    if not session.get('verified'):
        flash('Login required.')
        return redirect(url_for('login'))
    conn = sqlite3.connect('site.db')
    logs = conn.execute("SELECT * FROM uploads").fetchall()
    conn.close()
    return render_template('uploads.html', logs=logs)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's PORT or fallback to 5000
    app.run(host="0.0.0.0", port=port, debug=True)
