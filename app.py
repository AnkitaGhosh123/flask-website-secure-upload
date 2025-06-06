import os
import hashlib
import sqlite3
import random
from flask import Flask, request, render_template, redirect, url_for, session, send_file, flash
from werkzeug.utils import secure_filename
from encryption import encrypt_file, decrypt_file
from blockchain import Blockchain, Block
from database import init_db, get_user, add_user, log_upload, save_file_access, get_accessible_files, get_file_owner, delete_file_record
from flask_mail import Mail, Message
from flask import after_this_request

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Mail config
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
            code = str(random.randint(100000, 999999))
            session['2fa_code'] = code
            msg = Message('Your 2FA Code', sender='youremail@gmail.com', recipients=[email])
            msg.body = f'Your 2FA code is: {code}'
            mail.send(msg)
            return render_template('2fa_verify.html')
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/2fa', methods=['POST'])
def verify_2fa():
    entered = request.form['token']
    if entered == session.get('2fa_code'):
        session['email'] = session.pop('temp_email')
        session['verified'] = True
        return redirect(url_for('upload'))
    flash('Invalid 2FA code')
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

        # Save original file temporarily
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        # Encrypt the file and remove original
        encrypted_path = encrypt_file(path)  # This returns path + '.enc'
        encrypted_filename = os.path.basename(encrypted_path)  # example: "myfile.pdf.enc"

        email = session['email']

        # Log original filename (not encrypted one)
        file_id = log_upload(email, filename)

        # Handle shared access
        shared_with = request.form.get('shared_with', '')
        shared_list = [e.strip() for e in shared_with.split(',') if e.strip()]
        save_file_access(file_id, shared_list)

        # Blockchain logging
        block_data = f"{email} uploaded {filename}"
        new_block = Block(len(blockchain.chain), block_data, blockchain.chain[-1].hash)
        blockchain.add_block(new_block)

        flash('Upload successful.')

    return render_template('upload.html')


@app.route('/files')
def view_accessible_files():
    if not session.get('verified'):
        return redirect(url_for('login'))
    files_raw = get_accessible_files(session['email'])  # [(filename, uploader_email)]
# Strip .enc from filenames for UI, but keep .enc for links
    files = [(f[0].replace('.enc', ''), f[0], f[1]) for f in files_raw]  # (display_name, actual_filename, uploader)
    return render_template('accessible_files.html', files=files, user=session['email'])

@app.route('/download/<filename>')
def download(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    # Step 1: Validate access
    files = get_accessible_files(session['email'])  # List of (filename, uploader)
    accessible_filenames = [f[0] for f in files]
    if filename not in accessible_filenames:
        flash('Access denied.')
        return redirect(url_for('view_accessible_files'))

    # Step 2: Locate encrypted file
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if not os.path.exists(encrypted_path):
        flash('Encrypted file not found.')
        return redirect(url_for('view_accessible_files'))

    # Step 3: Decrypt it temporarily
    decrypted_path = decrypt_file(encrypted_path)

    # Step 4: Register cleanup after sending file
    @after_this_request
    def cleanup(response):
        try:
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
        except Exception as e:
            print(f"Cleanup error: {e}")
        return response

    # Step 5: Send file to user
    return send_file(decrypted_path, as_attachment=True)

@app.route('/delete/<filename>')
def delete(filename):
    if not session.get('verified'):
        return redirect(url_for('login'))

    # Step 1: Confirm if current user is the owner
    owner = get_file_owner(filename)
    if owner != session['email']:
        flash('Unauthorized to delete this file.')
        return redirect(url_for('view_accessible_files'))

    # Step 2: Locate encrypted file and delete it
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if os.path.exists(encrypted_path):
        try:
            os.remove(encrypted_path)
        except Exception as e:
            flash(f"Failed to delete file: {e}")
            return redirect(url_for('view_accessible_files'))
    else:
        flash("File not found on server.")

    # Step 3: Delete from database (uploads + file_access)
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

@app.route('/blockchain')
def view_blockchain():
    return render_template('blockchain.html', chain=blockchain.chain)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
