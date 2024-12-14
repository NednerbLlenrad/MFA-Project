# Multi Factor Authentification Application
# - Users can register or log into accounts
# - Passwords are hashed and treated with bcrypt
# - Users are saved in a sqlite3 Database
# - Uses Google Authenticator in order to provide the multifactor 
import sqlite3
import bcrypt
import qrcode
import pyotp

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

#Registering users
def reg_user(username, password):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    #Hash password using bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    #TOTP Secret Key
    secret_key = pyotp.random_base32()
    
    try:
        #Insert user
        cursor.execute('INSERT INTO users (username, password_hash, secret_key) VALUES (?, ?, ?)', (username, password_hash, secret_key))
        conn.commit()
        
        #Show QR Code for Google Authenticator
        totp = pyotp.TOTP(secret_key)
        uri = totp.provisioning_uri(name=username, issuer_name="MFA App")
        qr = qrcode.make(uri)
        qr.show()
        
        print(f"User {username} registered successfully!")
        print(f"For verification, scan this QR code with Google Authenticator or use this key: {secret_key}")
    except sqlite3.IntegrityError:
        print("Username already taken!")
        
    conn.close()
    
#Login Function
def login(username, password):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    #Get hashed password for username
    cursor.execute('SELECT password_hash, secret_key FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user is None:
        print("Username not found!")
        return False
    
    stored_password_hash, secret_key = user
    
    #Verify Password
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
       totp = pyotp.TOTP(secret_key)
       otp = input("Enter the code from Google Authenticator: ")
       
       if totp.verify(otp):
            print(f"Login successful for {username}!")
            return True
       else: 
            print("Incorrect one time password!")
            return False
    else:
        print("Incorrect password!")
        return False
    
def main():
    while True:
        print("1: Register New User")
        print("2: Login")
        print("3: Exit")
        choice = input("Select an Option:")
        
        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            check_password = input("Re-enter Password: ")
            if password == check_password: 
                reg_user(username, password)
            else:
                print("Passwords do not match!")
        elif choice == '2':
            username = input("Username: ")
            password = input("Password: ")
            login(username, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid option! Please try again!")
    
if __name__ == "__main__":
    main()