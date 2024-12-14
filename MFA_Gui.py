import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import mfa_app

import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import mfa_app  # Importing your MFA logic

# GUI Application Class
class MFAAppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MFA Application")
        self.root.geometry("400x300")
        
        # Main Menu Frame
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)
        
        tk.Label(self.main_frame, text="Welcome to MFA App", font=("Arial", 16)).pack(pady=10)
        
        tk.Button(self.main_frame, text="Register", width=20, command=self.show_register).pack(pady=5)
        tk.Button(self.main_frame, text="Login", width=20, command=self.show_login).pack(pady=5)
        tk.Button(self.main_frame, text="Exit", width=20, command=root.quit).pack(pady=5)
        
        # Login and Registration Frames
        self.register_frame = self.create_register_frame()
        self.login_frame = self.create_login_frame()

    def create_register_frame(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Register", font=("Arial", 14)).pack(pady=10)
        tk.Label(frame, text="Username").pack()
        self.reg_username = tk.Entry(frame)
        self.reg_username.pack()
        tk.Label(frame, text="Password").pack()
        self.reg_password = tk.Entry(frame, show="*")
        self.reg_password.pack()
        tk.Label(frame, text="Confirm Password").pack()
        self.reg_confirm_password = tk.Entry(frame, show="*")
        self.reg_confirm_password.pack()
        tk.Button(frame, text="Submit", command=self.register_user).pack(pady=10)
        tk.Button(frame, text="Back", command=lambda: self.switch_frame(self.register_frame, self.main_frame)).pack()
        return frame

    def create_login_frame(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Login", font=("Arial", 14)).pack(pady=10)
        tk.Label(frame, text="Username").pack()
        self.login_username = tk.Entry(frame)
        self.login_username.pack()
        tk.Label(frame, text="Password").pack()
        self.login_password = tk.Entry(frame, show="*")
        self.login_password.pack()
        tk.Button(frame, text="Submit", command=self.login_user).pack(pady=10)
        tk.Button(frame, text="Back", command=lambda: self.switch_frame(self.login_frame, self.main_frame)).pack()
        return frame

    def show_register(self):
        self.switch_frame(self.main_frame, self.register_frame)

    def show_login(self):
        self.switch_frame(self.main_frame, self.login_frame)

    def switch_frame(self, current_frame, next_frame):
        current_frame.pack_forget()
        next_frame.pack(fill="both", expand=True)

    def register_user(self):
        username = self.reg_username.get()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        message = mfa_app.reg_user(username, password)
        messagebox.showinfo("Info", message)

    def login_user(self):
        username = self.login_username.get()
        password = self.login_password.get()
        success, message = mfa_app.login(username, password)
        
        if success:
            self.show_success_animation()
        else:
            messagebox.showerror("Error", message)

    def show_success_animation(self):
        self.login_frame.pack_forget()
        animation_frame = tk.Frame(self.root)
        animation_frame.pack(fill="both", expand=True)
        
        tk.Label(animation_frame, text="Login Successful!", font=("Arial", 16)).pack(pady=10)
        
        # Display GIF
        gif_path = "assets/success.gif"
        gif = Image.open(gif_path)
        gif_frames = [ImageTk.PhotoImage(gif.seek(i)) for i in range(gif.n_frames)]
        gif_label = tk.Label(animation_frame)
        gif_label.pack()

        def update_gif(index):
            gif_label.config(image=gif_frames[index])
            self.root.after(100, update_gif, (index + 1) % len(gif_frames))

        update_gif(0)
        
        tk.Button(animation_frame, text="Back to Menu", command=lambda: self.switch_frame(animation_frame, self.main_frame)).pack(pady=10)

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = MFAAppGUI(root)
    root.mainloop()
