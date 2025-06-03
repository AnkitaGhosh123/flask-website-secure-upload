import sqlite3

def init_db():
    conn = sqlite3.connect('site.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY, email TEXT, filename TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def get_user(email):
    conn = sqlite3.connect('site.db')
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return user

def add_user(email, password):
    conn = sqlite3.connect('site.db')
    conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    conn.commit()
    conn.close()

def log_upload(email, filename):
    conn = sqlite3.connect('site.db')
    conn.execute("INSERT INTO uploads (email, filename) VALUES (?, ?)", (email, filename))
    conn.commit()
    conn.close()
