# Multi Factor Authentification Application
# - Users can register or log into accounts
# - Passwords are hashed and treated with bcrypt
# - Users are saved in a sqlite3 Database
# - Uses Google Authenticator in order to provide the multifactor 
import sqlite3
import bcrypt
import qrcode
import pyotp
import os
import tkinter as tk
from io import BytesIO
from PIL import ImageTk, Image

#Constants
USERS_DB = 'users.db'

#SQLite Database
def init_db():
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    #Table for users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        secret_key TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
        
init_db()

# Registering users
def reg_user(username, password):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    # Hash password using bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # TOTP Secret Key
    secret_key = pyotp.random_base32()
    
    try:
        # Insert user into the database
        cursor.execute('INSERT INTO users (username, password_hash, secret_key) VALUES (?, ?, ?)', (username, password_hash, secret_key))
        conn.commit()

        # Generate QR Code for Google Authenticator
        totp = pyotp.TOTP(secret_key)
        uri = totp.provisioning_uri(name=username, issuer_name="MFA App")
        
        # Save the QR Code image to a file
        qr = qrcode.make(uri)
        qr_path = "qr_code.png"  # Save QR code as a PNG image
        qr.save(qr_path)

        conn.close()
        return True, f"User {username} registered successfully! Please scan the QR Code for Google Authenticator", secret_key, qr_path

    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already taken!", None, None

#Login Function
def login(username, password, otp):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    #Get hashed password for username
    cursor.execute('SELECT password_hash, secret_key FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user is None:
        conn.close()
        return False, "Username not found!"
    
    stored_password_hash, secret_key = user
    
    #Verify Password
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
       totp = pyotp.TOTP(secret_key)
       
       if totp.verify(otp):
            conn.close()
            return True, f"Login successful for {username}!"
       else:
            conn.close() 
            return False, "Incorrect one time password!"
    else:
        conn.close()
        return False, "Incorrect password!"
    
