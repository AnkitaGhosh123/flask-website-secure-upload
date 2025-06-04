import sqlite3

def init_db():
    with sqlite3.connect('site.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, filename TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS file_access (file_id INTEGER, email TEXT, FOREIGN KEY(file_id) REFERENCES uploads(id))''')
        conn.commit()

def get_user(email):
    with sqlite3.connect('site.db') as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

def add_user(email, password):
    with sqlite3.connect('site.db') as conn:
        conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()

def log_upload(email, filename):
    with sqlite3.connect('site.db') as conn:
        conn.execute("INSERT INTO uploads (email, filename) VALUES (?, ?)", (email, filename))
        conn.commit()

def get_file_id(email, filename):
    with sqlite3.connect('site.db') as conn:
        cur = conn.execute("SELECT id FROM uploads WHERE email=? AND filename=? ORDER BY id DESC LIMIT 1", (email, filename))
        row = cur.fetchone()
        return row[0] if row else None

def add_file_access(file_id, allowed_emails):
    with sqlite3.connect('site.db') as conn:
        for email in allowed_emails:
            conn.execute("INSERT INTO file_access (file_id, email) VALUES (?, ?)", (file_id, email.strip()))
        conn.commit()

def get_accessible_files(user_email):
    with sqlite3.connect('site.db') as conn:
        return conn.execute('''SELECT uploads.id, uploads.email, uploads.filename, uploads.timestamp FROM uploads
                            LEFT JOIN file_access ON uploads.id = file_access.file_id
                            WHERE uploads.email = ? OR file_access.email = ?
                            GROUP BY uploads.id ORDER BY uploads.timestamp DESC''', (user_email, user_email)).fetchall()

def is_owner(user_email, file_id):
    with sqlite3.connect('site.db') as conn:
        result = conn.execute("SELECT 1 FROM uploads WHERE id=? AND email=?", (file_id, user_email)).fetchone()
        return bool(result)

def delete_file_record(file_id):
    with sqlite3.connect('site.db') as conn:
        conn.execute("DELETE FROM uploads WHERE id=?", (file_id,))
        conn.execute("DELETE FROM file_access WHERE file_id=?", (file_id,))
        conn.commit()
