import sqlite3

def init_db():
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Uploads table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uploader_email TEXT NOT NULL,
            filename TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # File access table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            user_email TEXT,
            FOREIGN KEY(file_id) REFERENCES uploads(id)
        )
    ''')

    conn.commit()
    conn.close()

def get_user(email):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(email, password):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    conn.commit()
    conn.close()

def log_upload(email, filename):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO uploads (uploader_email, filename) VALUES (?, ?)", (email, filename))
    file_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return file_id

def save_file_access(file_id, user_emails):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    for email in user_emails:
        cursor.execute("INSERT INTO file_access (file_id, user_email) VALUES (?, ?)", (file_id, email))
    conn.commit()
    conn.close()

def get_accessible_files(user_email):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT uploads.filename, uploads.uploader_email
        FROM uploads
        JOIN file_access ON uploads.id = file_access.file_id
        WHERE file_access.user_email = ?
    ''', (user_email,))
    files = cursor.fetchall()
    conn.close()
    return files  # List of (filename, uploader_email)

def get_file_owner(filename):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("SELECT uploader_email FROM uploads WHERE filename = ?", (filename,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def delete_file_record(filename):
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM uploads WHERE filename = ?", (filename,))
    result = cursor.fetchone()
    if result:
        file_id = result[0]
        cursor.execute("DELETE FROM file_access WHERE file_id = ?", (file_id,))
        cursor.execute("DELETE FROM uploads WHERE id = ?", (file_id,))
        conn.commit()
    conn.close()
