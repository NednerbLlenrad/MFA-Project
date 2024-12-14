import tkinter as tk
from tkinter import simpledialog, messagebox
from PIL import ImageTk, Image
import os
import qrcode
import pyotp
from mfa_app import reg_user, login, init_db

# GUI Main Application
class MFAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MFA Application")  # Set the window title
        self.geometry("1200x800")  # Set window size to 1200x800
        self.current_screen = None
        self.qr_image_label = None  # To hold the QR code image label
        init_db()  # Initialize the database
        self.show_main_menu()
    
    #Show main Menu screen
    def show_main_menu(self):
        if self.current_screen:
            self.current_screen.destroy()

        self.current_screen = tk.Frame(self)
        self.current_screen.pack(fill="both", expand=True)


        title_label = tk.Label(self.current_screen, text="Brenden's MFA Application!", font=("Arial", 24))
        title_label.pack(pady=20)

        register_button = tk.Button(self.current_screen, text="Register", command=self.show_register_screen, font=("Arial", 16))
        login_button = tk.Button(self.current_screen, text="Login", command=self.show_login_screen, font=("Arial", 16))
        exit_button = tk.Button(self.current_screen, text="Exit", command=self.quit, font=("Arial", 16))

        register_button.pack(pady=20)
        login_button.pack(pady=20)
        exit_button.pack(pady=20)

    #Register User screen
    def show_register_screen(self):
        if self.current_screen:
            self.current_screen.destroy()

        self.current_screen = tk.Frame(self)
        self.current_screen.pack(fill="both", expand=True)

        #Entry and labels for username, password, and password confirmation
        username_label = tk.Label(self.current_screen, text="Username", font=("Arial", 16))
        password_label = tk.Label(self.current_screen, text="Password", font=("Arial", 16))
        confirm_password_label = tk.Label(self.current_screen, text="Confirm Password", font=("Arial", 16))

        self.username_entry = tk.Entry(self.current_screen, font=("Arial", 16))
        self.password_entry = tk.Entry(self.current_screen, show="*", font=("Arial", 16))
        self.confirm_password_entry = tk.Entry(self.current_screen, show="*", font=("Arial", 16))

        submit_button = tk.Button(self.current_screen, text="Submit", command=self.register_user, font=("Arial", 16))

        username_label.pack(pady=10)
        self.username_entry.pack(pady=10)
        password_label.pack(pady=10)
        self.password_entry.pack(pady=10)
        confirm_password_label.pack(pady=10)
        self.confirm_password_entry.pack(pady=10)
        submit_button.pack(pady=20)

    #Register User 
    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        #Check for password matching
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        success, message, secret_key, qr_path = reg_user(username, password)

        if success:
            messagebox.showinfo("Registration Successful", message)

            # Generate and display QR code in the same window
            self.show_qr_code(username, secret_key)
        else:
            messagebox.showerror("Error", message)

    #Shows the QR code on screen
    def show_qr_code(self, username, secret_key):
        if self.current_screen:
            self.current_screen.destroy()

        self.current_screen = tk.Frame(self)
        self.current_screen.pack(fill="both", expand=True)

        totp = pyotp.TOTP(secret_key)
        uri = totp.provisioning_uri(name=username, issuer_name="MFA App")
        
        # Create and display QR code
        qr = qrcode.make(uri)
        qr_image = ImageTk.PhotoImage(qr)

        if self.qr_image_label:
            self.qr_image_label.destroy()  # Remove the previous QR code image

        self.qr_image_label = tk.Label(self.current_screen, image=qr_image)
        self.qr_image_label.image = qr_image  
        self.qr_image_label.pack(pady=20)

        # Return to main menu
        scan_button = tk.Button(self.current_screen, text="Scan and Return to Main Menu", command=self.show_main_menu, font=("Arial", 16))
        scan_button.pack(pady=20)

    #Login Screen
    def show_login_screen(self):
        if self.current_screen:
            self.current_screen.destroy()

        self.current_screen = tk.Frame(self)
        self.current_screen.pack(fill="both", expand=True)

        #Username and Password Entries
        username_label = tk.Label(self.current_screen, text="Username", font=("Arial", 16))
        password_label = tk.Label(self.current_screen, text="Password", font=("Arial", 16))

        self.username_entry = tk.Entry(self.current_screen, font=("Arial", 16))
        self.password_entry = tk.Entry(self.current_screen, show="*", font=("Arial", 16))

        #Verify button to prompt OTP verification
        verify_button = tk.Button(self.current_screen, text="Verify", command=self.verify_login, font=("Arial", 16))

        username_label.pack(pady=10)
        self.username_entry.pack(pady=10)
        password_label.pack(pady=10)
        self.password_entry.pack(pady=10)
        verify_button.pack(pady=20)

    #Login with OTP Verification
    def verify_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        otp = simpledialog.askstring("Enter OTP", "Please enter your OTP from Google Authenticator:")

        success, message = login(username, password, otp)

        if success:
            messagebox.showinfo("Login Successful", message)
            self.show_gif_screen()
        else:
            messagebox.showerror("Login Failed", message)

    #Shows Gif Image upon successful login
    def show_gif_screen(self):
        if self.current_screen:
            self.current_screen.destroy()

        self.current_screen = tk.Frame(self)
        self.current_screen.pack(fill="both", expand=True)

        # Load and display animated GIF
        gif_path = r"Assets\Dance.gif"  
        gif_image = ImageTk.PhotoImage(Image.open(gif_path))
        
        gif_label = tk.Label(self.current_screen, image=gif_image)
        gif_label.image = gif_image  
        gif_label.pack(pady=20)

        # Button to return to the main menu
        return_button = tk.Button(self.current_screen, text="Return to Main Menu", command=self.show_main_menu, font=("Arial", 16))
        return_button.pack(pady=20)

# Run Application
if __name__ == "__main__":
    app = MFAApp()
    app.mainloop()
