**Multi-Factor Authentication (MFA) Application**
---------------------------------------------------------
Overview
------------------------------
Brenden's MFA Application is a Python-based project designed to enhance account security by implementing multi-factor authentication (MFA). The app combines traditional password-based login with time-based one-time passwords (TOTP), offering an additional layer of protection for user accounts.

Features

- User Registration: Create accounts with username, password, and TOTP-based authentication.

- Time-Based OTP (TOTP): Generate dynamic OTPs using a secret key and integrate with popular authenticator apps like Google Authenticator.

- QR Code Display: Generate QR codes for easy setup of TOTP in an authenticator app.

Installation
----------------------------------------------
**Prerequisites**
 - Python 3.12 or later.

**Required Python libraries:**

 - tkinter (pre-installed with Python)

 - Pillow

 - qrcode

 - pyotp

 - sqlite3 (pre-installed with Python)

Setup
--------------------------------------------------------
1. Clone the repository or download the source code.

2. Navigate to the project directory.

3. Install dependencies:

```pip install Pillow qrcode pyotp```

4. Ensure the following project structure:
```
MFA Project/
|-- MFA_Gui.py
|-- mfa_app.py
|-- Assets/
    |-- Dance.gif
```
Usage
----------------------------------------------
**Run the application:**

```python MFA_Gui.py```

**Use the graphical interface to:
**
 - Register: Enter a username, password, and confirm the password. A QR code will be generated for scanning with an authenticator app.

 - Login: Enter the username, password, and OTP from the authenticator app. Successful login displays a celebratory GIF.

 - Use the "Return to Main Menu" button to navigate back to the main screen.

Project Structure
---------------------------------------
MFA_Gui.py: Contains the main graphical interface logic.

mfa_app.py: Handles backend functionality such as user registration, login verification, and database management.

Assets/: Contains assets like the GIF animation displayed post-login.

How It Works
----------------------------------
**Registration:**

 - Users input their username and password.

 - The app generates a secret key for the user and creates a QR code containing the TOTP provisioning URI.

 - Users scan the QR code with an authenticator app to link their account.

**Login:**

 - Users input their credentials and OTP from the authenticator app.

 - The app verifies the hashed password and validates the TOTP.

**Post-Login:**

 - Upon successful login, a celebratory image is displayed in the app window.

License
-------------------------
This project is licensed under the MIT License. See LICENSE for details.

Acknowledgments
------------------------
Python documentation for tkinter and sqlite3.

Libraries such as Pillow, qrcode, and pyotp for simplifying development.
